use super::javascript;
use super::{
    Confidence, ConnectionRateLimiter, DetectedFileType, EndpointScan, ExposureFinding,
    ExposureScanRequest, JavaScriptVersionStatus, TechnologyComponent, TechnologyComponentKind,
    TechnologyEcosystem, TechnologyFileType, TechnologySupportStatus, TechnologyVersionStatus,
};
use futures_util::stream::{FuturesUnordered, StreamExt};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use quick_xml::{Reader, events::Event};
use regex::Regex;
use semver::Version;
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use tokio_util::sync::CancellationToken;
use url::Url;

const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONCURRENT_VERSION_FETCHES: usize = 8;

pub(super) struct CapturedTechnologyResource {
    pub ip: IpAddr,
    pub port: u16,
    pub url: String,
    pub fetch_url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub truncated: bool,
    pub detected_file_types: Vec<DetectedFileType>,
}

pub(super) struct AnalysisReport {
    pub warnings: Vec<String>,
    pub findings: Vec<ExposureFinding>,
}

#[derive(Clone)]
struct LatestResult {
    latest: Option<String>,
    error: Option<String>,
    support_status: Option<TechnologySupportStatus>,
}

#[derive(Clone)]
struct LookupJob {
    ecosystem: TechnologyEcosystem,
    identifier: String,
    priority: (u8, u8, String),
}

pub(super) fn classify_resource(
    url: &Url,
    content_type: Option<&str>,
    body: &[u8],
) -> Vec<DetectedFileType> {
    let extension = extension_file_type(url.path());
    let mime = content_type.and_then(mime_file_type);
    let signatures = signature_file_types(body);
    let mut evidence = BTreeMap::<TechnologyFileType, (u8, Vec<String>)>::new();
    if let Some(file_type) = extension {
        let item = evidence.entry(file_type).or_default();
        item.0 |= 1;
        item.1.push(format!("URL extension for {file_type}"));
    }
    if let Some(file_type) = mime {
        let item = evidence.entry(file_type).or_default();
        item.0 |= 2;
        item.1.push(format!("Content-Type indicates {file_type}"));
    }
    for file_type in signatures {
        let item = evidence.entry(file_type).or_default();
        item.0 |= 4;
        item.1
            .push(format!("Validated {file_type} content signature"));
    }
    if url.path().to_ascii_lowercase().ends_with(".map")
        && let Ok(map) = serde_json::from_slice::<Value>(body)
        && map.get("version").and_then(Value::as_u64).is_some()
        && let Some(sources) = map.get("sources").and_then(Value::as_array)
    {
        for source in sources.iter().filter_map(Value::as_str).take(2048) {
            if let Some(file_type) = extension_file_type(source) {
                let item = evidence.entry(file_type).or_default();
                item.0 |= 4;
                item.1
                    .push(format!("Validated source-map entry for {file_type}"));
            }
        }
        if let Some(contents) = map.get("sourcesContent").and_then(Value::as_array) {
            for content in contents.iter().filter_map(Value::as_str).take(256) {
                for file_type in signature_file_types(content.as_bytes()) {
                    let item = evidence.entry(file_type).or_default();
                    item.0 |= 4;
                    item.1
                        .push(format!("Validated source-map content for {file_type}"));
                }
            }
        }
    }
    let conflicting = extension.is_some() && mime.is_some() && extension != mime;
    evidence
        .into_iter()
        .map(|(file_type, (sources, mut evidence))| {
            evidence.sort();
            evidence.dedup();
            let confidence = if sources & 4 != 0 || sources.count_ones() >= 2 {
                Confidence::High
            } else if conflicting {
                Confidence::Low
            } else {
                Confidence::Medium
            };
            DetectedFileType {
                file_type,
                confidence,
                evidence,
            }
        })
        .collect()
}

pub(super) fn should_capture(
    url: &Url,
    content_type: Option<&str>,
    body: &[u8],
    detected: &[DetectedFileType],
) -> bool {
    let path = url.path().to_ascii_lowercase();
    let start = String::from_utf8_lossy(&body[..body.len().min(256)]).to_ascii_lowercase();
    detected.iter().any(|item| {
        !matches!(
            item.file_type,
            TechnologyFileType::Jar | TechnologyFileType::DotNetAssembly
        )
    }) || is_manifest_path(&path)
        || path.ends_with(".map")
        || start.trim_start().starts_with("<!doctype html")
        || start.trim_start().starts_with("<html")
        || content_type.is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("html") || value.contains("json") || value.contains("xml")
        })
}

fn extension_file_type(path: &str) -> Option<TechnologyFileType> {
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    let extension = path.rsplit_once('.').map(|(_, value)| value)?;
    Some(match extension {
        "js" | "mjs" | "cjs" => TechnologyFileType::JavaScript,
        "jsx" => TechnologyFileType::Jsx,
        "ts" => TechnologyFileType::TypeScript,
        "tsx" => TechnologyFileType::Tsx,
        "php" | "phtml" | "phar" => TechnologyFileType::Php,
        "py" | "pyw" => TechnologyFileType::Python,
        "rb" => TechnologyFileType::Ruby,
        "erb" => TechnologyFileType::Erb,
        "java" => TechnologyFileType::Java,
        "jsp" | "jspx" => TechnologyFileType::Jsp,
        "kt" | "kts" => TechnologyFileType::Kotlin,
        "jar" => TechnologyFileType::Jar,
        "cs" => TechnologyFileType::CSharp,
        "cshtml" | "razor" => TechnologyFileType::Razor,
        "aspx" | "ashx" | "asmx" => TechnologyFileType::AspNet,
        "dll" => TechnologyFileType::DotNetAssembly,
        "go" => TechnologyFileType::Go,
        "rs" => TechnologyFileType::Rust,
        _ => return None,
    })
}

fn mime_file_type(content_type: &str) -> Option<TechnologyFileType> {
    let value = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    Some(match value.as_str() {
        "application/javascript"
        | "text/javascript"
        | "application/ecmascript"
        | "text/ecmascript" => TechnologyFileType::JavaScript,
        "application/typescript" | "text/typescript" => TechnologyFileType::TypeScript,
        "application/x-httpd-php" | "text/x-php" => TechnologyFileType::Php,
        "text/x-python" | "application/x-python-code" => TechnologyFileType::Python,
        "text/x-ruby" | "application/x-ruby" => TechnologyFileType::Ruby,
        "text/x-java-source" => TechnologyFileType::Java,
        "application/java-archive" | "application/java-vm" => TechnologyFileType::Jar,
        "text/x-kotlin" => TechnologyFileType::Kotlin,
        "text/x-csharp" => TechnologyFileType::CSharp,
        "text/x-go" => TechnologyFileType::Go,
        "text/x-rust" => TechnologyFileType::Rust,
        _ => return None,
    })
}

fn signature_file_types(body: &[u8]) -> Vec<TechnologyFileType> {
    let bytes = &body[..body.len().min(64 * 1024)];
    if bytes.starts_with(b"PK\x03\x04") {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim_start();
    if trimmed.to_ascii_lowercase().starts_with("<!doctype html")
        || trimmed.to_ascii_lowercase().starts_with("<html")
    {
        return Vec::new();
    }
    let mut types = Vec::new();
    if trimmed.starts_with("<?php") {
        types.push(TechnologyFileType::Php);
    }
    if trimmed.starts_with("<%@") && trimmed.contains("Page") {
        types.push(TechnologyFileType::AspNet);
    }
    if (trimmed.starts_with("@page") || trimmed.starts_with("@model"))
        && (text.contains("@code") || text.contains("@functions"))
    {
        types.push(TechnologyFileType::Razor);
    }
    if text.starts_with("#!")
        && text
            .lines()
            .next()
            .is_some_and(|line| line.contains("python"))
        || (text.contains("def ") && text.contains("import ") && text.contains(':'))
    {
        types.push(TechnologyFileType::Python);
    }
    if text.starts_with("#!")
        && text
            .lines()
            .next()
            .is_some_and(|line| line.contains("ruby"))
        || (text.contains("require '") && text.contains("def ") && text.contains("\nend"))
    {
        types.push(TechnologyFileType::Ruby);
    }
    if (text.contains("package ") && text.contains("public class "))
        || (text.contains("import java.") && text.contains("class "))
    {
        types.push(TechnologyFileType::Java);
    }
    if text.contains("fun main(") && (text.contains("val ") || text.contains("import kotlin.")) {
        types.push(TechnologyFileType::Kotlin);
    }
    if (text.contains("using System;") || text.contains("namespace System"))
        && (text.contains(" class ") || text.contains("record "))
    {
        types.push(TechnologyFileType::CSharp);
    }
    if text.contains("package main") && text.contains("func main(") {
        types.push(TechnologyFileType::Go);
    }
    if text.contains("fn main(") && (text.contains("use std::") || text.contains("extern crate ")) {
        types.push(TechnologyFileType::Rust);
    }
    if (text.contains("\"use strict\"") || text.contains("'use strict'"))
        && (text.contains("function ") || text.contains("=>"))
    {
        types.push(TechnologyFileType::JavaScript);
    }
    if (text.contains("interface ") || text.contains("type "))
        && (text.contains(": string") || text.contains(": number"))
    {
        types.push(TechnologyFileType::TypeScript);
    }
    types.sort();
    types.dedup();
    types
}

fn is_manifest_path(path: &str) -> bool {
    matches!(
        path.rsplit('/').next().unwrap_or(path),
        "package.json"
            | "package-lock.json"
            | "npm-shrinkwrap.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "composer.json"
            | "composer.lock"
            | "requirements.txt"
            | "pipfile"
            | "pipfile.lock"
            | "poetry.lock"
            | "uv.lock"
            | "pyproject.toml"
            | "gemfile"
            | "gemfile.lock"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "gradle.lockfile"
            | "packages.config"
            | "packages.lock.json"
            | "directory.packages.props"
            | "go.mod"
            | "go.sum"
            | "cargo.toml"
            | "cargo.lock"
    )
}

pub(super) async fn analyze(
    endpoints: &mut [EndpointScan],
    resources: &[CapturedTechnologyResource],
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
    enrichment: &mut javascript::EnrichmentState,
) -> AnalysisReport {
    for endpoint in endpoints.iter_mut() {
        endpoint.technology_components.clear();
        import_javascript_components(endpoint);
    }
    for resource in resources {
        let Some(endpoint) = endpoints
            .iter_mut()
            .find(|endpoint| endpoint.ip == resource.ip && endpoint.port == resource.port)
        else {
            continue;
        };
        for component in parse_resource(resource) {
            merge_component(&mut endpoint.technology_components, component);
        }
        detect_url_components(endpoint, &resource.url);
        detect_content_components(endpoint, resource);
    }
    for endpoint in endpoints.iter_mut() {
        let urls = endpoint
            .javascript_sources
            .iter()
            .flat_map(|source| {
                std::iter::once(source.source_url.as_str()).chain(source.final_url.as_deref())
            })
            .map(str::to_owned)
            .collect::<Vec<_>>();
        for url in urls {
            detect_url_components(endpoint, &url);
        }
        import_product_components(endpoint);
    }

    let mut cache = HashMap::<(TechnologyEcosystem, String), LatestResult>::new();
    seed_javascript_cache(endpoints, &mut cache);
    let mut jobs = HashMap::<(TechnologyEcosystem, String), LookupJob>::new();
    for endpoint in endpoints.iter_mut() {
        for component in &mut endpoint.technology_components {
            if component.status != TechnologyVersionStatus::Unknown {
                continue;
            }
            let Some(installed) = component.installed_version.clone() else {
                component.status = TechnologyVersionStatus::InventoryOnly;
                continue;
            };
            let Some(identifier) = component.package_identifier.clone() else {
                component.status = TechnologyVersionStatus::NotChecked;
                if component.ecosystem == TechnologyEcosystem::WebServer {
                    component.support_status = TechnologySupportStatus::NotChecked;
                }
                component.check_error = Some("No high-confidence registry mapping".to_owned());
                continue;
            };
            let lookup_identifier = if component.ecosystem == TechnologyEcosystem::WebServer {
                web_server_cache_identifier(&identifier, &installed)
            } else {
                registry_cache_identifier(component.ecosystem, &identifier)
            };
            let key = (component.ecosystem, lookup_identifier.clone());
            if !cache.contains_key(&key) {
                let priority = lookup_priority(component, &lookup_identifier);
                jobs.entry(key)
                    .and_modify(|job| job.priority = job.priority.clone().min(priority.clone()))
                    .or_insert(LookupJob {
                        ecosystem: component.ecosystem,
                        identifier: lookup_identifier,
                        priority,
                    });
            }
        }
    }

    fetch_lookup_jobs(jobs, &mut cache, request, cancel, limiter, enrichment).await;

    let mut warning_groups = BTreeMap::<(TechnologyEcosystem, String), HashSet<String>>::new();
    for endpoint in endpoints.iter_mut() {
        for component in &mut endpoint.technology_components {
            if component.status == TechnologyVersionStatus::Unknown {
                let installed = component.installed_version.clone().unwrap_or_default();
                let identifier = component.package_identifier.clone().unwrap_or_default();
                let lookup_identifier = if component.ecosystem == TechnologyEcosystem::WebServer {
                    web_server_cache_identifier(&identifier, &installed)
                } else {
                    registry_cache_identifier(component.ecosystem, &identifier)
                };
                let result = cache
                    .get(&(component.ecosystem, lookup_identifier))
                    .cloned()
                    .unwrap_or_else(|| LatestResult {
                        latest: None,
                        error: Some(
                            enrichment
                                .stop_error(cancel)
                                .unwrap_or(javascript::METADATA_LIMIT_ERROR)
                                .to_owned(),
                        ),
                        support_status: None,
                    });
                apply_latest_result(component, &installed, result);
            }
            if component.status == TechnologyVersionStatus::NotChecked
                && component.installed_version.is_some()
                && let Some(identifier) = component.package_identifier.as_deref()
                && let Some(error) = component.check_error.as_deref()
            {
                warning_groups
                    .entry((component.ecosystem, error.to_owned()))
                    .or_default()
                    .insert(identifier.to_owned());
            }
        }
        endpoint.technology_components.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then(left.name.cmp(&right.name))
                .then(left.installed_version.cmp(&right.installed_version))
        });
    }
    let warnings = warning_groups
        .into_iter()
        .map(|((ecosystem, error), identifiers)| {
            format!(
                "{ecosystem} metadata unavailable for {} unique component(s): {error}",
                identifiers.len()
            )
        })
        .collect();
    AnalysisReport {
        findings: outdated_findings(endpoints),
        warnings,
    }
}

fn lookup_priority(component: &TechnologyComponent, identifier: &str) -> (u8, u8, String) {
    let preferred = matches!(
        component.kind,
        TechnologyComponentKind::Server
            | TechnologyComponentKind::Runtime
            | TechnologyComponentKind::Framework
    );
    let high = component.confidence == Confidence::High;
    let group = match (high, preferred) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    };
    let kind = match component.kind {
        TechnologyComponentKind::Server => 0,
        TechnologyComponentKind::Runtime => 1,
        TechnologyComponentKind::Framework => 2,
        TechnologyComponentKind::Plugin => 3,
        TechnologyComponentKind::Package => 4,
    };
    (group, kind, identifier.to_owned())
}

async fn fetch_lookup_jobs(
    jobs: HashMap<(TechnologyEcosystem, String), LookupJob>,
    cache: &mut HashMap<(TechnologyEcosystem, String), LatestResult>,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
    enrichment: &mut javascript::EnrichmentState,
) {
    enrichment.start();
    let mut jobs = jobs.into_iter().collect::<Vec<_>>();
    jobs.sort_by(|left, right| {
        left.1
            .priority
            .cmp(&right.1.priority)
            .then(left.0.cmp(&right.0))
    });
    let mut fetched = HashMap::new();
    let mut requests = HashMap::<String, ((u8, u8, String), String)>::new();
    for (_, job) in &jobs {
        let Some(url) = registry_url(job.ecosystem, &job.identifier) else {
            continue;
        };
        if let Some(result) = enrichment.cached(&url) {
            fetched.insert(url, result);
            continue;
        }
        let accept = registry_accept(job.ecosystem, &job.identifier).to_owned();
        requests
            .entry(url)
            .and_modify(|existing| {
                if job.priority < existing.0 {
                    *existing = (job.priority.clone(), accept.clone());
                }
            })
            .or_insert_with(|| (job.priority.clone(), accept));
    }
    let mut requests = requests.into_iter().collect::<Vec<_>>();
    requests.sort_by(|left, right| left.1.0.cmp(&right.1.0).then(left.0.cmp(&right.0)));

    let context = enrichment.fetch_context();
    let mut pending = FuturesUnordered::new();
    let mut next = 0usize;
    let mut reserved = 0usize;
    while next < requests.len() || !pending.is_empty() {
        while pending.len() < MAX_CONCURRENT_VERSION_FETCHES && next < requests.len() {
            if enrichment.stop_error(cancel).is_some() {
                break;
            }
            let available = enrichment.remaining_bytes().saturating_sub(reserved);
            if available == 0 {
                break;
            }
            let body_limit = MAX_METADATA_BYTES.min(available);
            let (url, (_, accept)) = requests[next].clone();
            next += 1;
            reserved += body_limit;
            let context = context.clone();
            pending.push(async move {
                let headers = [("Accept", accept.as_str())];
                let result = javascript::fetch_metadata_url(
                    &url, body_limit, &headers, request, cancel, limiter, context,
                )
                .await;
                (url, body_limit, result)
            });
        }
        let Some((url, body_limit, result)) = pending.next().await else {
            break;
        };
        reserved = reserved.saturating_sub(body_limit);
        enrichment.store(url.clone(), result.clone());
        fetched.insert(url, result);
    }
    if next < requests.len() {
        let error = enrichment
            .stop_error(cancel)
            .unwrap_or(javascript::METADATA_LIMIT_ERROR)
            .to_owned();
        for (url, _) in &requests[next..] {
            fetched.insert(url.clone(), metadata_error(url, &error));
        }
    }

    for (key, job) in jobs {
        let result = match registry_url(job.ecosystem, &job.identifier) {
            Some(url) => fetched
                .get(&url)
                .cloned()
                .map(|fetched| latest_result(job.ecosystem, &job.identifier, fetched))
                .unwrap_or_else(|| LatestResult {
                    latest: None,
                    error: Some(javascript::METADATA_LIMIT_ERROR.to_owned()),
                    support_status: None,
                }),
            None => LatestResult {
                latest: None,
                error: Some("No release source is configured for this component".to_owned()),
                support_status: None,
            },
        };
        cache.insert(key, result);
    }
}

fn metadata_error(url: &str, error: &str) -> javascript::Fetched {
    javascript::Fetched {
        final_url: Url::parse(url).ok(),
        response: None,
        error: Some(error.to_owned()),
        captured_bytes: 0,
    }
}

fn apply_latest_result(component: &mut TechnologyComponent, installed: &str, result: LatestResult) {
    component.latest_version = result.latest;
    if component.ecosystem == TechnologyEcosystem::WebServer {
        component.support_status = result
            .support_status
            .unwrap_or(TechnologySupportStatus::NotChecked);
    }
    if let Some(error) = result.error {
        component.status = TechnologyVersionStatus::NotChecked;
        component.check_error = Some(error);
    } else if let Some(latest) = component.latest_version.as_deref() {
        component.status = compare_versions(component.ecosystem, installed, latest);
        if component.status == TechnologyVersionStatus::Unverifiable {
            component.check_error =
                Some("Installed or latest version is not an exact comparable version".to_owned());
        }
    } else {
        component.status = TechnologyVersionStatus::NotChecked;
        component.check_error = Some("Registry returned no stable release".to_owned());
    }
}

fn import_javascript_components(endpoint: &mut EndpointScan) {
    let mut components = Vec::new();
    for source in &endpoint.javascript_sources {
        for library in &source.libraries {
            let ecosystem = if library.npm_package.is_some() {
                TechnologyEcosystem::Npm
            } else {
                TechnologyEcosystem::JavaScript
            };
            components.push(TechnologyComponent {
                name: library.name.clone(),
                ecosystem,
                kind: known_kind(
                    ecosystem,
                    library.npm_package.as_deref().unwrap_or(&library.name),
                ),
                package_identifier: library.npm_package.clone(),
                installed_version: library.installed_version.clone(),
                latest_version: library.latest_version.clone(),
                status: if library.installed_version.is_some() {
                    javascript_status(library.status)
                } else {
                    TechnologyVersionStatus::InventoryOnly
                },
                support_status: TechnologySupportStatus::NotApplicable,
                confidence: if library.installed_version.is_some() {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                release_source_url: None,
                evidence_urls: vec![source.source_url.clone()],
                evidence: library.evidence.clone(),
                check_error: library
                    .installed_version
                    .is_some()
                    .then(|| library.check_error.clone())
                    .flatten(),
            });
        }
    }
    for component in components {
        merge_component(&mut endpoint.technology_components, component);
    }
}

fn javascript_status(status: JavaScriptVersionStatus) -> TechnologyVersionStatus {
    match status {
        JavaScriptVersionStatus::Unknown => TechnologyVersionStatus::Unknown,
        JavaScriptVersionStatus::NotChecked => TechnologyVersionStatus::NotChecked,
        JavaScriptVersionStatus::Current => TechnologyVersionStatus::Current,
        JavaScriptVersionStatus::OutdatedPatch => TechnologyVersionStatus::OutdatedPatch,
        JavaScriptVersionStatus::OutdatedMinor => TechnologyVersionStatus::OutdatedMinor,
        JavaScriptVersionStatus::OutdatedMajor => TechnologyVersionStatus::OutdatedMajor,
        JavaScriptVersionStatus::NewerThanLatest => TechnologyVersionStatus::NewerThanLatest,
        JavaScriptVersionStatus::Prerelease => TechnologyVersionStatus::Prerelease,
        JavaScriptVersionStatus::Unverifiable => TechnologyVersionStatus::Unverifiable,
    }
}

fn seed_javascript_cache(
    endpoints: &[EndpointScan],
    cache: &mut HashMap<(TechnologyEcosystem, String), LatestResult>,
) {
    for component in endpoints
        .iter()
        .flat_map(|endpoint| &endpoint.technology_components)
    {
        if component.ecosystem != TechnologyEcosystem::Npm {
            continue;
        }
        let Some(identifier) = component.package_identifier.clone() else {
            continue;
        };
        if component.latest_version.is_some() || component.check_error.is_some() {
            cache
                .entry((
                    component.ecosystem,
                    registry_cache_identifier(component.ecosystem, &identifier),
                ))
                .or_insert_with(|| LatestResult {
                    latest: component.latest_version.clone(),
                    error: component.check_error.clone(),
                    support_status: None,
                });
        }
    }
}

fn registry_cache_identifier(ecosystem: TechnologyEcosystem, identifier: &str) -> String {
    if matches!(
        ecosystem,
        TechnologyEcosystem::MavenCentral | TechnologyEcosystem::GoModules
    ) {
        identifier.to_owned()
    } else {
        identifier.to_ascii_lowercase()
    }
}

fn merge_component(components: &mut Vec<TechnologyComponent>, mut incoming: TechnologyComponent) {
    let identity = |component: &TechnologyComponent| {
        component
            .package_identifier
            .as_deref()
            .unwrap_or(&component.name)
            .to_ascii_lowercase()
    };
    let incoming_identity = identity(&incoming);
    let matching = components.iter_mut().find(|existing| {
        existing.ecosystem == incoming.ecosystem
            && identity(existing) == incoming_identity
            && (existing.installed_version == incoming.installed_version
                || existing.installed_version.is_none()
                || incoming.installed_version.is_none())
    });
    if let Some(existing) = matching {
        if existing.installed_version.is_none() && incoming.installed_version.is_some() {
            existing.installed_version = incoming.installed_version.take();
            existing.status = incoming.status;
        }
        if existing.latest_version.is_none() {
            existing.latest_version = incoming.latest_version;
        }
        if existing.package_identifier.is_none() {
            existing.package_identifier = incoming.package_identifier;
        }
        if existing.support_status == TechnologySupportStatus::NotApplicable
            || existing.support_status == TechnologySupportStatus::Unknown
        {
            existing.support_status = incoming.support_status;
        }
        if existing.release_source_url.is_none() {
            existing.release_source_url = incoming.release_source_url;
        }
        existing.confidence = existing.confidence.max(incoming.confidence);
        existing.evidence_urls.extend(incoming.evidence_urls);
        existing.evidence.extend(incoming.evidence);
        existing.evidence_urls.sort();
        existing.evidence_urls.dedup();
        existing.evidence.sort();
        existing.evidence.dedup();
    } else {
        incoming.evidence_urls.sort();
        incoming.evidence_urls.dedup();
        incoming.evidence.sort();
        incoming.evidence.dedup();
        components.push(incoming);
    }
}

fn component(
    name: &str,
    ecosystem: TechnologyEcosystem,
    identifier: Option<&str>,
    version: Option<&str>,
    exact: bool,
    url: &str,
    evidence: String,
) -> TechnologyComponent {
    TechnologyComponent {
        name: name.to_owned(),
        ecosystem,
        kind: known_kind(ecosystem, identifier.unwrap_or(name)),
        package_identifier: identifier.map(str::to_owned),
        installed_version: exact.then(|| version.map(normalize_version)).flatten(),
        latest_version: None,
        status: if exact && version.is_some() {
            TechnologyVersionStatus::Unknown
        } else {
            TechnologyVersionStatus::InventoryOnly
        },
        support_status: if ecosystem == TechnologyEcosystem::WebServer {
            if exact && version.is_some() {
                TechnologySupportStatus::NotChecked
            } else {
                TechnologySupportStatus::Unknown
            }
        } else {
            TechnologySupportStatus::NotApplicable
        },
        confidence: if exact {
            Confidence::High
        } else {
            Confidence::Medium
        },
        release_source_url: identifier
            .filter(|_| ecosystem == TechnologyEcosystem::WebServer)
            .and_then(web_server_release_source)
            .map(str::to_owned),
        evidence_urls: vec![url.to_owned()],
        evidence: vec![evidence],
        check_error: None,
    }
}

fn known_kind(ecosystem: TechnologyEcosystem, identifier: &str) -> TechnologyComponentKind {
    let id = identifier.to_ascii_lowercase();
    let framework = match ecosystem {
        TechnologyEcosystem::Npm => matches!(
            id.as_str(),
            "react" | "vue" | "@angular/core" | "next" | "nuxt" | "express" | "svelte"
        ),
        TechnologyEcosystem::Composer => {
            matches!(
                id.as_str(),
                "laravel/framework"
                    | "symfony/framework-bundle"
                    | "sulu/sulu"
                    | "silverstripe/cms"
                    | "magento/product-community-edition"
            )
        }
        TechnologyEcosystem::PyPi => {
            matches!(id.as_str(), "django" | "flask" | "fastapi")
        }
        TechnologyEcosystem::RubyGems => matches!(id.as_str(), "rails" | "sinatra"),
        TechnologyEcosystem::MavenCentral => id.starts_with("org.springframework:"),
        TechnologyEcosystem::NuGet => id.starts_with("microsoft.aspnetcore"),
        TechnologyEcosystem::GoModules => {
            id == "github.com/gin-gonic/gin" || id == "github.com/labstack/echo/v4"
        }
        TechnologyEcosystem::CratesIo => matches!(id.as_str(), "actix-web" | "rocket" | "axum"),
        TechnologyEcosystem::WordPress => return TechnologyComponentKind::Plugin,
        TechnologyEcosystem::Runtime => return TechnologyComponentKind::Runtime,
        TechnologyEcosystem::WebServer => return TechnologyComponentKind::Server,
        TechnologyEcosystem::JavaScript => false,
    };
    if framework {
        TechnologyComponentKind::Framework
    } else {
        TechnologyComponentKind::Package
    }
}

fn parse_resource(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    if resource.truncated {
        return Vec::new();
    }
    let path = Url::parse(&resource.fetch_url)
        .ok()
        .map(|url| url.path().to_ascii_lowercase())
        .unwrap_or_else(|| resource.fetch_url.to_ascii_lowercase());
    let name = path.rsplit('/').next().unwrap_or(&path);
    match name {
        "package.json" => parse_package_json(resource),
        "package-lock.json" | "npm-shrinkwrap.json" => parse_package_lock(resource),
        "yarn.lock" => parse_yarn_lock(resource),
        "pnpm-lock.yaml" => parse_pnpm_lock(resource),
        "composer.json" => parse_composer_json(resource),
        "composer.lock" => parse_composer_lock(resource),
        "requirements.txt" | "pipfile" => parse_python_inventory(resource),
        "pyproject.toml" => parse_pyproject(resource),
        "pipfile.lock" => parse_pipfile_lock(resource),
        "poetry.lock" | "uv.lock" => parse_toml_package_lock(resource, TechnologyEcosystem::PyPi),
        "gemfile" => parse_gemfile(resource),
        "gemfile.lock" => parse_gemfile_lock(resource),
        "pom.xml" => parse_pom(resource),
        "build.gradle" | "build.gradle.kts" => parse_gradle_inventory(resource),
        "gradle.lockfile" => parse_gradle_lock(resource),
        "packages.config" => parse_nuget_xml(resource, true),
        "directory.packages.props" => parse_nuget_xml(resource, false),
        "packages.lock.json" => parse_nuget_lock(resource),
        "go.mod" => parse_go_mod(resource),
        "go.sum" => parse_go_sum(resource),
        "cargo.toml" => parse_cargo_manifest(resource),
        "cargo.lock" => parse_toml_package_lock(resource, TechnologyEcosystem::CratesIo),
        _ => Vec::new(),
    }
}

fn parse_package_json(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let Ok(value) = serde_json::from_slice::<Value>(&resource.body) else {
        return Vec::new();
    };
    let Some(root) = value.as_object() else {
        return Vec::new();
    };
    ["dependencies", "devDependencies", "peerDependencies"]
        .into_iter()
        .filter_map(|key| {
            root.get(key)
                .and_then(Value::as_object)
                .map(|map| (key, map))
        })
        .flat_map(|(key, dependencies)| {
            dependencies.iter().filter_map(move |(name, value)| {
                let requested = value.as_str()?;
                Some(component(
                    name,
                    TechnologyEcosystem::Npm,
                    Some(name),
                    Some(requested),
                    false,
                    &resource.url,
                    format!("package.json {key} requests {requested}"),
                ))
            })
        })
        .collect()
}

fn parse_package_lock(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let Ok(value) = serde_json::from_slice::<Value>(&resource.body) else {
        return Vec::new();
    };
    let Some(root) = value.as_object() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if let Some(packages) = root.get("packages").and_then(Value::as_object) {
        for (path, item) in packages {
            let Some(name) = path
                .rsplit("node_modules/")
                .next()
                .filter(|name| !name.is_empty())
            else {
                continue;
            };
            let Some(version) = item.get("version").and_then(Value::as_str) else {
                continue;
            };
            found.push(component(
                name,
                TechnologyEcosystem::Npm,
                Some(name),
                Some(version),
                exact_version(version),
                &resource.url,
                format!("npm lockfile pins {version}"),
            ));
        }
    } else if let Some(dependencies) = root.get("dependencies").and_then(Value::as_object) {
        collect_npm_lock_dependencies(dependencies, resource, &mut found);
    }
    found
}

fn collect_npm_lock_dependencies(
    dependencies: &serde_json::Map<String, Value>,
    resource: &CapturedTechnologyResource,
    found: &mut Vec<TechnologyComponent>,
) {
    for (name, item) in dependencies {
        if let Some(version) = item.get("version").and_then(Value::as_str) {
            found.push(component(
                name,
                TechnologyEcosystem::Npm,
                Some(name),
                Some(version),
                exact_version(version),
                &resource.url,
                format!("npm lockfile pins {version}"),
            ));
        }
        if let Some(children) = item.get("dependencies").and_then(Value::as_object) {
            collect_npm_lock_dependencies(children, resource, found);
        }
    }
}

fn parse_yarn_lock(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let text = String::from_utf8_lossy(&resource.body);
    let version = Regex::new(r#"^\s*version\s+\"([^\"]+)\""#).expect("valid regex");
    let mut names = Vec::<String>::new();
    let mut found = Vec::new();
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) && line.ends_with(':') {
            names = line
                .trim_end_matches(':')
                .split(',')
                .filter_map(|item| yarn_name(item.trim().trim_matches(['\'', '"'])))
                .collect();
        } else if let Some(version) = version
            .captures(line)
            .and_then(|captures| captures.get(1))
            .map(|value| value.as_str())
        {
            for name in names.drain(..) {
                found.push(component(
                    &name,
                    TechnologyEcosystem::Npm,
                    Some(&name),
                    Some(version),
                    exact_version(version),
                    &resource.url,
                    format!("yarn.lock pins {version}"),
                ));
            }
        }
    }
    found
}

fn yarn_name(spec: &str) -> Option<String> {
    if spec.starts_with('@') {
        let slash = spec.find('/')?;
        let after = &spec[slash + 1..];
        let end = after
            .find('@')
            .map_or(spec.len(), |index| slash + 1 + index);
        return Some(spec[..end].to_owned());
    }
    Some(spec.split('@').next()?.to_owned()).filter(|name| !name.is_empty())
}

fn parse_pnpm_lock(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let text = String::from_utf8_lossy(&resource.body);
    let pattern =
        Regex::new(r#"(?m)^\s{0,4}['\"]?/?((?:@[^/@\s]+/)?[^@:\s'\"]+)@([0-9][^:\s'\"]*)['\"]?:"#)
            .expect("valid regex");
    pattern
        .captures_iter(&text)
        .filter_map(|captures| {
            let name = captures.get(1)?.as_str();
            let version = captures.get(2)?.as_str();
            Some(component(
                name,
                TechnologyEcosystem::Npm,
                Some(name),
                Some(version),
                exact_version(version),
                &resource.url,
                format!("pnpm lockfile pins {version}"),
            ))
        })
        .collect()
}

fn parse_composer_json(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let Ok(value) = serde_json::from_slice::<Value>(&resource.body) else {
        return Vec::new();
    };
    let Some(root) = value.as_object() else {
        return Vec::new();
    };
    ["require", "require-dev"]
        .into_iter()
        .filter_map(|key| {
            root.get(key)
                .and_then(Value::as_object)
                .map(|map| (key, map))
        })
        .flat_map(|(key, dependencies)| {
            dependencies.iter().filter_map(move |(name, value)| {
                if name == "php" || name.starts_with("ext-") {
                    return None;
                }
                let requested = value.as_str()?;
                Some(component(
                    name,
                    TechnologyEcosystem::Composer,
                    Some(name),
                    Some(requested),
                    false,
                    &resource.url,
                    format!("composer.json {key} requests {requested}"),
                ))
            })
        })
        .collect()
}

fn parse_composer_lock(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let Ok(value) = serde_json::from_slice::<Value>(&resource.body) else {
        return Vec::new();
    };
    ["packages", "packages-dev"]
        .into_iter()
        .filter_map(|key| value.get(key).and_then(Value::as_array))
        .flatten()
        .filter_map(|item| {
            let name = item.get("name")?.as_str()?;
            let version = item.get("version")?.as_str()?;
            Some(component(
                name,
                TechnologyEcosystem::Composer,
                Some(name),
                Some(version),
                exact_version(version),
                &resource.url,
                format!("composer.lock pins {version}"),
            ))
        })
        .collect()
}

fn parse_python_inventory(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let text = String::from_utf8_lossy(&resource.body);
    let requirement = Regex::new(r#"(?im)^[\s\"']*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]+\])?\s*(==|~=|>=|<=|!=|>|<|\^|=)?\s*([^\s,;\"']*)"#)
        .expect("valid regex");
    requirement
        .captures_iter(&text)
        .filter_map(|captures| {
            let name = captures.get(1)?.as_str();
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "python" | "source" | "requires-python"
            ) {
                return None;
            }
            let spec = captures.get(3).map_or("", |value| value.as_str());
            Some(component(
                name,
                TechnologyEcosystem::PyPi,
                Some(name),
                (!spec.is_empty()).then_some(spec),
                false,
                &resource.url,
                if spec.is_empty() {
                    "Python dependency manifest entry".to_owned()
                } else {
                    format!("Python dependency manifest requests {spec}")
                },
            ))
        })
        .take(4096)
        .collect()
}

fn parse_pyproject(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let text = String::from_utf8_lossy(&resource.body);
    let requirement = Regex::new(
        r#"[\"']([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(==|~=|>=|<=|!=|>|<|\^|~)?\s*([^\s,;\"']*)[\"']"#,
    )
    .expect("valid regex");
    let assignment = Regex::new(r#"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*[\"']([^\"']+)[\"']"#)
        .expect("valid regex");
    let mut dependency_section = false;
    let mut dependency_array = false;
    let mut found = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            let section = trimmed.trim_matches(['[', ']']).to_ascii_lowercase();
            dependency_section = section.contains("dependenc");
            dependency_array = false;
            continue;
        }
        if trimmed.starts_with("dependencies") && trimmed.contains('[') {
            dependency_array = true;
            continue;
        }
        if dependency_array && trimmed == "]" {
            dependency_array = false;
            continue;
        }
        if !dependency_section && !dependency_array {
            continue;
        }
        if let Some(captures) = requirement.captures(line) {
            let Some(name) = captures.get(1).map(|value| value.as_str()) else {
                continue;
            };
            if name.eq_ignore_ascii_case("python") {
                continue;
            }
            let requested = captures
                .get(3)
                .map(|value| value.as_str())
                .filter(|value| !value.is_empty());
            found.push(component(
                name,
                TechnologyEcosystem::PyPi,
                Some(name),
                requested,
                false,
                &resource.url,
                requested.map_or_else(
                    || "pyproject.toml dependency".to_owned(),
                    |value| format!("pyproject.toml requests {value}"),
                ),
            ));
        } else if let Some(captures) = assignment.captures(line) {
            let Some(name) = captures.get(1).map(|value| value.as_str()) else {
                continue;
            };
            if name.eq_ignore_ascii_case("python") {
                continue;
            }
            let requested = captures.get(2).map(|value| value.as_str());
            found.push(component(
                name,
                TechnologyEcosystem::PyPi,
                Some(name),
                requested,
                false,
                &resource.url,
                requested.map_or_else(
                    || "pyproject.toml dependency".to_owned(),
                    |value| format!("pyproject.toml requests {value}"),
                ),
            ));
        }
    }
    found
}

fn parse_pipfile_lock(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let Ok(value) = serde_json::from_slice::<Value>(&resource.body) else {
        return Vec::new();
    };
    ["default", "develop"]
        .into_iter()
        .filter_map(|key| value.get(key).and_then(Value::as_object))
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(|(name, item)| {
            let version = item.get("version").and_then(Value::as_str)?;
            Some(component(
                name,
                TechnologyEcosystem::PyPi,
                Some(name),
                Some(version),
                exact_version(version),
                &resource.url,
                format!("Pipfile.lock pins {version}"),
            ))
        })
        .collect()
}

fn parse_toml_package_lock(
    resource: &CapturedTechnologyResource,
    ecosystem: TechnologyEcosystem,
) -> Vec<TechnologyComponent> {
    let text = String::from_utf8_lossy(&resource.body);
    let assignment =
        Regex::new(r#"^\s*(name|version)\s*=\s*[\"']([^\"']+)[\"']"#).expect("valid regex");
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut found = Vec::new();
    for line in text.lines().chain(std::iter::once("[[package]]")) {
        if line.trim() == "[[package]]" {
            if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                found.push(component(
                    &name,
                    ecosystem,
                    Some(&name),
                    Some(&version),
                    exact_version(&version),
                    &resource.url,
                    format!("lockfile pins {version}"),
                ));
            }
            continue;
        }
        if let Some(captures) = assignment.captures(line) {
            match captures.get(1).map(|value| value.as_str()) {
                Some("name") => {
                    current_name = captures.get(2).map(|value| value.as_str().to_owned())
                }
                Some("version") => {
                    current_version = captures.get(2).map(|value| value.as_str().to_owned())
                }
                _ => {}
            }
        }
    }
    found
}

fn parse_gemfile(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let text = String::from_utf8_lossy(&resource.body);
    let pattern = Regex::new(r#"(?m)^\s*gem\s+[\"']([^\"']+)[\"'](?:\s*,\s*[\"']([^\"']+)[\"'])?"#)
        .expect("valid regex");
    pattern
        .captures_iter(&text)
        .filter_map(|captures| {
            let name = captures.get(1)?.as_str();
            let requested = captures.get(2).map(|value| value.as_str());
            Some(component(
                name,
                TechnologyEcosystem::RubyGems,
                Some(name),
                requested,
                false,
                &resource.url,
                requested.map_or_else(
                    || "Gemfile dependency".to_owned(),
                    |value| format!("Gemfile requests {value}"),
                ),
            ))
        })
        .collect()
}

fn parse_gemfile_lock(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let text = String::from_utf8_lossy(&resource.body);
    let pattern = Regex::new(r"(?m)^ {4}([A-Za-z0-9_.-]+) \(([^ )]+)\)").expect("valid regex");
    pattern
        .captures_iter(&text)
        .filter_map(|captures| {
            let name = captures.get(1)?.as_str();
            let version = captures.get(2)?.as_str();
            Some(component(
                name,
                TechnologyEcosystem::RubyGems,
                Some(name),
                Some(version),
                exact_version(version),
                &resource.url,
                format!("Gemfile.lock pins {version}"),
            ))
        })
        .collect()
}

fn parse_pom(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    if !valid_xml(&resource.body) {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&resource.body);
    let dependency = Regex::new(r"(?s)<dependency\b[^>]*>(.*?)</dependency>").expect("valid regex");
    dependency
        .captures_iter(&text)
        .filter_map(|captures| {
            let block = captures.get(1)?.as_str();
            let group = xml_value(block, "groupId")?;
            let artifact = xml_value(block, "artifactId")?;
            let identifier = format!("{group}:{artifact}");
            let version = xml_value(block, "version");
            let evidence = version.as_ref().map_or_else(
                || "Maven dependency manifest entry".to_owned(),
                |value| format!("pom.xml requests {value}"),
            );
            Some(component(
                &artifact,
                TechnologyEcosystem::MavenCentral,
                Some(&identifier),
                version.as_deref(),
                false,
                &resource.url,
                evidence,
            ))
        })
        .collect()
}

fn parse_gradle_inventory(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let text = String::from_utf8_lossy(&resource.body);
    let pattern = Regex::new(r#"[\"']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^\"']+)[\"']"#)
        .expect("valid regex");
    pattern
        .captures_iter(&text)
        .filter_map(|captures| {
            let group = captures.get(1)?.as_str();
            let artifact = captures.get(2)?.as_str();
            let requested = captures.get(3)?.as_str();
            let identifier = format!("{group}:{artifact}");
            Some(component(
                artifact,
                TechnologyEcosystem::MavenCentral,
                Some(&identifier),
                Some(requested),
                false,
                &resource.url,
                format!("Gradle dependency requests {requested}"),
            ))
        })
        .collect()
}

fn parse_gradle_lock(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let text = String::from_utf8_lossy(&resource.body);
    let pattern =
        Regex::new(r"(?m)^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^=\s]+)=").expect("valid regex");
    pattern
        .captures_iter(&text)
        .filter_map(|captures| {
            let group = captures.get(1)?.as_str();
            let artifact = captures.get(2)?.as_str();
            let version = captures.get(3)?.as_str();
            let identifier = format!("{group}:{artifact}");
            Some(component(
                artifact,
                TechnologyEcosystem::MavenCentral,
                Some(&identifier),
                Some(version),
                exact_version(version),
                &resource.url,
                format!("Gradle lockfile pins {version}"),
            ))
        })
        .collect()
}

fn parse_nuget_xml(
    resource: &CapturedTechnologyResource,
    installed_manifest: bool,
) -> Vec<TechnologyComponent> {
    if !valid_xml(&resource.body) {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&resource.body);
    let package = Regex::new(
        r#"(?i)<package\b[^>]*\bid=[\"']([^\"']+)[\"'][^>]*\bversion=[\"']([^\"']+)[\"'][^>]*/?>"#,
    )
    .expect("valid regex");
    let version_first = Regex::new(
        r#"(?i)<package\b[^>]*\bversion=[\"']([^\"']+)[\"'][^>]*\bid=[\"']([^\"']+)[\"'][^>]*/?>"#,
    )
    .expect("valid regex");
    let package_version = Regex::new(r#"(?i)<PackageVersion\b[^>]*\bInclude=[\"']([^\"']+)[\"'][^>]*\bVersion=[\"']([^\"']+)[\"'][^>]*/?>"#)
        .expect("valid regex");
    package
        .captures_iter(&text)
        .filter_map(|captures| {
            nuget_xml_component(
                resource,
                captures.get(1)?.as_str(),
                captures.get(2)?.as_str(),
                installed_manifest,
            )
        })
        .chain(version_first.captures_iter(&text).filter_map(|captures| {
            nuget_xml_component(
                resource,
                captures.get(2)?.as_str(),
                captures.get(1)?.as_str(),
                installed_manifest,
            )
        }))
        .chain(package_version.captures_iter(&text).filter_map(|captures| {
            nuget_xml_component(
                resource,
                captures.get(1)?.as_str(),
                captures.get(2)?.as_str(),
                installed_manifest,
            )
        }))
        .collect()
}

fn nuget_xml_component(
    resource: &CapturedTechnologyResource,
    name: &str,
    version: &str,
    installed_manifest: bool,
) -> Option<TechnologyComponent> {
    Some(component(
        name,
        TechnologyEcosystem::NuGet,
        Some(name),
        Some(version),
        installed_manifest && exact_version(version),
        &resource.url,
        format!("NuGet package manifest records {version}"),
    ))
}

fn parse_nuget_lock(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let Ok(value) = serde_json::from_slice::<Value>(&resource.body) else {
        return Vec::new();
    };
    let Some(dependencies) = value.get("dependencies").and_then(Value::as_object) else {
        return Vec::new();
    };
    dependencies
        .values()
        .filter_map(Value::as_object)
        .flat_map(|framework| framework.iter())
        .filter_map(|(name, item)| {
            let version = item.get("resolved").and_then(Value::as_str)?;
            Some(component(
                name,
                TechnologyEcosystem::NuGet,
                Some(name),
                Some(version),
                exact_version(version),
                &resource.url,
                format!("packages.lock.json pins {version}"),
            ))
        })
        .collect()
}

fn parse_go_mod(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let text = String::from_utf8_lossy(&resource.body);
    let pattern = Regex::new(r"(?m)^\s*([A-Za-z0-9._~/-]+)\s+(v[0-9][^\s]*)").expect("valid regex");
    pattern
        .captures_iter(&text)
        .filter_map(|captures| {
            let name = captures.get(1)?.as_str();
            let requested = captures.get(2)?.as_str();
            Some(component(
                name,
                TechnologyEcosystem::GoModules,
                Some(name),
                Some(requested),
                false,
                &resource.url,
                format!("go.mod requires {requested}"),
            ))
        })
        .collect()
}

fn parse_go_sum(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let text = String::from_utf8_lossy(&resource.body);
    let mut seen = HashSet::new();
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let name = fields.next()?;
            let version = fields.next()?.trim_end_matches("/go.mod");
            if !seen.insert((name.to_owned(), version.to_owned())) {
                return None;
            }
            Some(component(
                name,
                TechnologyEcosystem::GoModules,
                Some(name),
                Some(version),
                exact_version(version),
                &resource.url,
                format!("go.sum records {version}"),
            ))
        })
        .take(4096)
        .collect()
}

fn parse_cargo_manifest(resource: &CapturedTechnologyResource) -> Vec<TechnologyComponent> {
    let text = String::from_utf8_lossy(&resource.body);
    let mut in_dependencies = false;
    let simple =
        Regex::new(r#"^\s*([A-Za-z0-9_-]+)\s*=\s*[\"']([^\"']+)[\"']"#).expect("valid regex");
    let table =
        Regex::new(r#"^\s*([A-Za-z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*[\"']([^\"']+)[\"']"#)
            .expect("valid regex");
    let mut found = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with('[') {
            let section = line.trim().trim_matches(['[', ']']).to_ascii_lowercase();
            in_dependencies = section.ends_with("dependencies");
            continue;
        }
        if !in_dependencies {
            continue;
        }
        let captures = table.captures(line).or_else(|| simple.captures(line));
        let Some(captures) = captures else {
            continue;
        };
        let Some(name) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        let Some(requested) = captures.get(2).map(|value| value.as_str()) else {
            continue;
        };
        found.push(component(
            name,
            TechnologyEcosystem::CratesIo,
            Some(name),
            Some(requested),
            false,
            &resource.url,
            format!("Cargo.toml requests {requested}"),
        ));
    }
    found
}

fn valid_xml(bytes: &[u8]) -> bool {
    let mut reader = Reader::from_reader(bytes);
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => return true,
            Err(_) => return false,
            _ => {}
        }
    }
}

fn xml_value(block: &str, tag: &str) -> Option<String> {
    Regex::new(&format!(r"(?s)<{tag}\b[^>]*>\s*([^<]+?)\s*</{tag}>"))
        .ok()?
        .captures(block)?
        .get(1)
        .map(|value| value.as_str().to_owned())
}

fn exact_version(value: &str) -> bool {
    let value = normalize_version(value);
    !value.is_empty()
        && value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit())
        && !value.contains(|character: char| {
            matches!(
                character,
                '*' | '^' | '~' | '<' | '>' | ' ' | ',' | '$' | '{'
            )
        })
        && version_numbers(&value).is_some()
}

fn normalize_version(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('=')
        .trim_start()
        .trim_start_matches(['v', 'V'])
        .trim_end_matches("+incompatible")
        .to_owned()
}

fn detect_url_components(endpoint: &mut EndpointScan, url: &str) {
    let Ok(parsed) = Url::parse(url) else {
        return;
    };
    let path = parsed.path().to_ascii_lowercase();
    if let Some(captures) = Regex::new(r"/wp-content/plugins/([a-z0-9_-]+)(?:/|$)")
        .expect("valid regex")
        .captures(&path)
        && let Some(slug) = captures.get(1).map(|value| value.as_str())
    {
        let version = parsed
            .query_pairs()
            .find(|(name, _)| name.eq_ignore_ascii_case("ver"))
            .map(|(_, value)| value.into_owned())
            .filter(|value| exact_version(value));
        merge_component(
            &mut endpoint.technology_components,
            component(
                slug,
                TechnologyEcosystem::WordPress,
                Some(slug),
                version.as_deref(),
                version.is_some(),
                url,
                if let Some(version) = &version {
                    format!("WordPress plugin asset path exposes version {version}")
                } else {
                    "WordPress plugin asset path".to_owned()
                },
            ),
        );
    }
    for (marker, name, package) in [
        ("/_next/", "Next.js", "next"),
        ("/_nuxt/", "Nuxt", "nuxt"),
        ("/react", "React", "react"),
        ("/vue.", "Vue", "vue"),
    ] {
        if path.contains(marker) {
            merge_component(
                &mut endpoint.technology_components,
                component(
                    name,
                    TechnologyEcosystem::Npm,
                    Some(package),
                    None,
                    false,
                    url,
                    format!("Curated framework asset marker {marker}"),
                ),
            );
        }
    }
}

fn detect_content_components(endpoint: &mut EndpointScan, resource: &CapturedTechnologyResource) {
    let text = String::from_utf8_lossy(&resource.body);
    let lower = text.to_ascii_lowercase();
    let mut detected = Vec::new();
    if lower.contains("__react_devtools_global_hook__")
        || lower.contains("data-reactroot")
        || lower.contains("react.production.min")
    {
        detected.push(fingerprint_component(
            "React",
            TechnologyEcosystem::Npm,
            "react",
            None,
            resource,
            "Curated React content fingerprint",
        ));
    }
    if lower.contains("__vue__") || lower.contains("data-v-") || lower.contains("vue.runtime") {
        detected.push(fingerprint_component(
            "Vue",
            TechnologyEcosystem::Npm,
            "vue",
            None,
            resource,
            "Curated Vue content fingerprint",
        ));
    }
    if let Some(version) = capture(&text, r#"(?i)\bng-version=[\"']([0-9][0-9A-Za-z._-]*)"#) {
        detected.push(fingerprint_component(
            "Angular",
            TechnologyEcosystem::Npm,
            "@angular/core",
            Some(&version),
            resource,
            "Angular ng-version attribute",
        ));
    } else if lower.contains("ng-version=") || lower.contains("ng-app=") {
        detected.push(fingerprint_component(
            "Angular",
            TechnologyEcosystem::Npm,
            "@angular/core",
            None,
            resource,
            "Curated Angular content fingerprint",
        ));
    }
    if lower.contains("__next_data__") {
        detected.push(fingerprint_component(
            "Next.js",
            TechnologyEcosystem::Npm,
            "next",
            None,
            resource,
            "Next.js __NEXT_DATA__ marker",
        ));
    }
    if lower.contains("__nuxt__") {
        detected.push(fingerprint_component(
            "Nuxt",
            TechnologyEcosystem::Npm,
            "nuxt",
            None,
            resource,
            "Nuxt __NUXT__ marker",
        ));
    }
    if lower.contains("csrfmiddlewaretoken") {
        detected.push(fingerprint_component(
            "Django",
            TechnologyEcosystem::PyPi,
            "Django",
            None,
            resource,
            "Django CSRF field marker",
        ));
    }
    if lower.contains("rails-ujs") || (lower.contains("csrf-param") && lower.contains("csrf-token"))
    {
        detected.push(fingerprint_component(
            "Ruby on Rails",
            TechnologyEcosystem::RubyGems,
            "rails",
            None,
            resource,
            "Ruby on Rails content fingerprint",
        ));
    }
    if lower.contains("whitelabel error page") {
        detected.push(fingerprint_component(
            "Spring Boot",
            TechnologyEcosystem::MavenCentral,
            "org.springframework.boot:spring-boot",
            None,
            resource,
            "Spring Boot Whitelabel Error Page",
        ));
    }
    if lower.contains("__viewstate") {
        detected.push(TechnologyComponent {
            name: "ASP.NET".to_owned(),
            ecosystem: TechnologyEcosystem::Runtime,
            kind: TechnologyComponentKind::Framework,
            package_identifier: None,
            installed_version: None,
            latest_version: None,
            status: TechnologyVersionStatus::InventoryOnly,
            support_status: TechnologySupportStatus::NotApplicable,
            confidence: Confidence::High,
            release_source_url: None,
            evidence_urls: vec![resource.url.clone()],
            evidence: vec!["ASP.NET __VIEWSTATE field".to_owned()],
            check_error: None,
        });
    }
    if lower.contains("_framework/blazor") {
        detected.push(TechnologyComponent {
            name: "Blazor".to_owned(),
            ecosystem: TechnologyEcosystem::Runtime,
            kind: TechnologyComponentKind::Framework,
            package_identifier: None,
            installed_version: None,
            latest_version: None,
            status: TechnologyVersionStatus::InventoryOnly,
            support_status: TechnologySupportStatus::NotApplicable,
            confidence: Confidence::High,
            release_source_url: None,
            evidence_urls: vec![resource.url.clone()],
            evidence: vec!["Blazor framework asset marker".to_owned()],
            check_error: None,
        });
    }
    if let Some(version) = capture(
        &text,
        r#"(?i)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']wordpress\s+([0-9][0-9A-Za-z._-]*)"#,
    )
    .or_else(|| {
        capture(
            &text,
            r#"(?i)<meta[^>]+content=[\"']wordpress\s+([0-9][0-9A-Za-z._-]*)[\"'][^>]+name=[\"']generator[\"']"#,
        )
    }) {
        let mut item = component(
            "WordPress",
            TechnologyEcosystem::WordPress,
            Some("wordpress"),
            Some(&version),
            exact_version(&version),
            &resource.url,
            format!("WordPress generator exposes {version}"),
        );
        item.kind = TechnologyComponentKind::Framework;
        detected.push(item);
    }
    for component in detected {
        merge_component(&mut endpoint.technology_components, component);
    }
}

fn fingerprint_component(
    name: &str,
    ecosystem: TechnologyEcosystem,
    package: &str,
    version: Option<&str>,
    resource: &CapturedTechnologyResource,
    evidence: &str,
) -> TechnologyComponent {
    component(
        name,
        ecosystem,
        Some(package),
        version,
        version.is_some_and(exact_version),
        &resource.url,
        evidence.to_owned(),
    )
}

fn import_product_components(endpoint: &mut EndpointScan) {
    let mut detected = Vec::new();
    for product in &endpoint.products {
        let normalized = product.name.to_ascii_lowercase();
        let mapping = match normalized.as_str() {
            "nginx" => Some((
                TechnologyEcosystem::WebServer,
                "nginx",
                "nginx",
                TechnologyComponentKind::Server,
            )),
            "openresty" => Some((
                TechnologyEcosystem::WebServer,
                "OpenResty",
                "openresty",
                TechnologyComponentKind::Server,
            )),
            "apache http server" | "apache" => Some((
                TechnologyEcosystem::WebServer,
                "Apache HTTP Server",
                "apache-httpd",
                TechnologyComponentKind::Server,
            )),
            "microsoft iis" | "iis" => Some((
                TechnologyEcosystem::WebServer,
                "Microsoft IIS",
                "iis",
                TechnologyComponentKind::Server,
            )),
            "caddy" => Some((
                TechnologyEcosystem::WebServer,
                "Caddy",
                "caddy",
                TechnologyComponentKind::Server,
            )),
            "litespeed" => Some((
                TechnologyEcosystem::WebServer,
                "LiteSpeed",
                "litespeed",
                TechnologyComponentKind::Server,
            )),
            "openlitespeed" => Some((
                TechnologyEcosystem::WebServer,
                "OpenLiteSpeed",
                "openlitespeed",
                TechnologyComponentKind::Server,
            )),
            "lighttpd" => Some((
                TechnologyEcosystem::WebServer,
                "lighttpd",
                "lighttpd",
                TechnologyComponentKind::Server,
            )),
            "apache tomcat" | "tomcat" => Some((
                TechnologyEcosystem::WebServer,
                "Apache Tomcat",
                "tomcat",
                TechnologyComponentKind::Server,
            )),
            "jetty" => Some((
                TechnologyEcosystem::WebServer,
                "Jetty",
                "jetty",
                TechnologyComponentKind::Server,
            )),
            "kestrel" => Some((
                TechnologyEcosystem::WebServer,
                "Kestrel",
                "kestrel",
                TechnologyComponentKind::Server,
            )),
            "gunicorn" => Some((
                TechnologyEcosystem::WebServer,
                "gunicorn",
                "gunicorn",
                TechnologyComponentKind::Server,
            )),
            "uvicorn" => Some((
                TechnologyEcosystem::WebServer,
                "Uvicorn",
                "uvicorn",
                TechnologyComponentKind::Server,
            )),
            "puma" => Some((
                TechnologyEcosystem::WebServer,
                "Puma",
                "puma",
                TechnologyComponentKind::Server,
            )),
            "passenger" => Some((
                TechnologyEcosystem::WebServer,
                "Passenger",
                "passenger",
                TechnologyComponentKind::Server,
            )),
            "cowboy" => Some((
                TechnologyEcosystem::WebServer,
                "Cowboy",
                "cowboy",
                TechnologyComponentKind::Server,
            )),
            "werkzeug" => Some((
                TechnologyEcosystem::WebServer,
                "Werkzeug",
                "werkzeug",
                TechnologyComponentKind::Server,
            )),
            "php" => Some((
                TechnologyEcosystem::Runtime,
                "PHP",
                "php",
                TechnologyComponentKind::Runtime,
            )),
            "python" => Some((
                TechnologyEcosystem::Runtime,
                "Python",
                "python",
                TechnologyComponentKind::Runtime,
            )),
            "ruby" => Some((
                TechnologyEcosystem::Runtime,
                "Ruby",
                "ruby",
                TechnologyComponentKind::Runtime,
            )),
            "node.js" | "node" => Some((
                TechnologyEcosystem::Runtime,
                "Node.js",
                "node",
                TechnologyComponentKind::Runtime,
            )),
            "express" => Some((
                TechnologyEcosystem::Npm,
                "Express",
                "express",
                TechnologyComponentKind::Framework,
            )),
            "asp.net" => Some((
                TechnologyEcosystem::Runtime,
                "ASP.NET",
                "",
                TechnologyComponentKind::Framework,
            )),
            "django" => Some((
                TechnologyEcosystem::PyPi,
                "Django",
                "Django",
                TechnologyComponentKind::Framework,
            )),
            "ruby on rails" | "rails" => Some((
                TechnologyEcosystem::RubyGems,
                "Ruby on Rails",
                "rails",
                TechnologyComponentKind::Framework,
            )),
            "spring" => Some((
                TechnologyEcosystem::MavenCentral,
                "Spring Framework",
                "org.springframework:spring-core",
                TechnologyComponentKind::Framework,
            )),
            "spring boot" => Some((
                TechnologyEcosystem::MavenCentral,
                "Spring Boot",
                "org.springframework.boot:spring-boot",
                TechnologyComponentKind::Framework,
            )),
            "wordpress" => Some((
                TechnologyEcosystem::WordPress,
                "WordPress",
                "wordpress",
                TechnologyComponentKind::Framework,
            )),
            "woocommerce" => Some((
                TechnologyEcosystem::WordPress,
                "WooCommerce",
                "woocommerce",
                TechnologyComponentKind::Plugin,
            )),
            "magento" | "adobe commerce" => Some((
                TechnologyEcosystem::Composer,
                "Magento",
                "",
                TechnologyComponentKind::Framework,
            )),
            "sulu" => Some((
                TechnologyEcosystem::Composer,
                "Sulu",
                "sulu/sulu",
                TechnologyComponentKind::Framework,
            )),
            "silverstripe" => Some((
                TechnologyEcosystem::Composer,
                "Silverstripe",
                "silverstripe/cms",
                TechnologyComponentKind::Framework,
            )),
            "symfony" => Some((
                TechnologyEcosystem::Composer,
                "Symfony",
                "symfony/framework-bundle",
                TechnologyComponentKind::Framework,
            )),
            "java" | "openjdk" => Some((
                TechnologyEcosystem::Runtime,
                "Java",
                "java",
                TechnologyComponentKind::Runtime,
            )),
            ".net" | "dotnet" => Some((
                TechnologyEcosystem::Runtime,
                ".NET",
                "dotnet",
                TechnologyComponentKind::Runtime,
            )),
            "go" | "golang" => Some((
                TechnologyEcosystem::Runtime,
                "Go",
                "go",
                TechnologyComponentKind::Runtime,
            )),
            "rust" => Some((
                TechnologyEcosystem::Runtime,
                "Rust",
                "rust",
                TechnologyComponentKind::Runtime,
            )),
            _ => None,
        };
        let Some((ecosystem, name, identifier, kind)) = mapping else {
            continue;
        };
        let url = endpoint
            .http
            .iter()
            .find(|response| (200..400).contains(&response.status))
            .map(|response| response.url.clone())
            .unwrap_or_else(|| format!("{}:{}", endpoint.ip, endpoint.port));
        let mut item = component(
            name,
            ecosystem,
            (!identifier.is_empty()).then_some(identifier),
            product.version.as_deref(),
            product.version.as_deref().is_some_and(|version| {
                if ecosystem == TechnologyEcosystem::WebServer {
                    crate::web_server::is_exact_web_server_version(version)
                } else {
                    exact_version(version)
                }
            }),
            &url,
            format!("Product fingerprint: {}", product.evidence.join("; ")),
        );
        item.kind = kind;
        item.confidence = product.confidence;
        detected.push(item);
    }
    detect_runtime_headers(endpoint, &mut detected);
    for component in detected {
        merge_component(&mut endpoint.technology_components, component);
    }
}

fn detect_runtime_headers(endpoint: &EndpointScan, detected: &mut Vec<TechnologyComponent>) {
    let rules = [
        (
            "php",
            r"(?i)\bPHP/?([0-9]+(?:\.[0-9]+){1,3}(?:[-._A-Za-z0-9]+)?)",
            "PHP",
        ),
        (
            "python",
            r"(?i)\bPython/?([0-9]+(?:\.[0-9]+){1,3}(?:[-._A-Za-z0-9]+)?)",
            "Python",
        ),
        (
            "ruby",
            r"(?i)\bRuby/?([0-9]+(?:\.[0-9]+){1,3}(?:[-._A-Za-z0-9]+)?)",
            "Ruby",
        ),
        (
            "node",
            r"(?i)\bNode(?:\.js)?/?v?([0-9]+(?:\.[0-9]+){1,3}(?:[-._A-Za-z0-9]+)?)",
            "Node.js",
        ),
    ];
    for response in &endpoint.http {
        for (header_name, header_value) in &response.headers {
            if !matches!(
                header_name.to_ascii_lowercase().as_str(),
                "server" | "x-powered-by" | "x-runtime"
            ) {
                continue;
            }
            for (identifier, pattern, name) in rules {
                let Some(version) = capture(header_value, pattern) else {
                    continue;
                };
                let mut item = component(
                    name,
                    TechnologyEcosystem::Runtime,
                    Some(identifier),
                    Some(&version),
                    exact_version(&version),
                    &response.url,
                    format!("{header_name} header exposes {name} {version}"),
                );
                item.kind = TechnologyComponentKind::Runtime;
                detected.push(item);
            }
        }
    }
}

fn capture(text: &str, pattern: &str) -> Option<String> {
    Regex::new(pattern)
        .ok()?
        .captures(text)?
        .get(1)
        .map(|value| value.as_str().to_owned())
}

fn registry_accept(ecosystem: TechnologyEcosystem, identifier: &str) -> &'static str {
    let base_identifier = identifier
        .split_once('@')
        .map(|(identifier, _)| identifier)
        .unwrap_or(identifier);
    if ecosystem == TechnologyEcosystem::Npm {
        "application/vnd.npm.install-v1+json"
    } else if ecosystem == TechnologyEcosystem::WebServer && base_identifier == "lighttpd" {
        "text/plain"
    } else if ecosystem == TechnologyEcosystem::WebServer
        && matches!(
            base_identifier,
            "nginx"
                | "apache-httpd"
                | "iis"
                | "openresty"
                | "litespeed"
                | "openlitespeed"
                | "tomcat"
                | "jetty"
        )
    {
        "text/html"
    } else if matches!(
        ecosystem,
        TechnologyEcosystem::GoModules | TechnologyEcosystem::Runtime
    ) && matches!(identifier, "ruby" | "rust")
    {
        "text/plain"
    } else {
        "application/json"
    }
}

fn latest_result(
    ecosystem: TechnologyEcosystem,
    identifier: &str,
    fetched: javascript::Fetched,
) -> LatestResult {
    let Some(response) = fetched.response else {
        return LatestResult {
            latest: None,
            error: fetched
                .error
                .or_else(|| Some("Registry returned no response".to_owned())),
            support_status: None,
        };
    };
    if let Some(error) = fetched.error {
        return LatestResult {
            latest: None,
            error: Some(error),
            support_status: None,
        };
    }
    if !(200..300).contains(&response.status) {
        return LatestResult {
            latest: None,
            error: Some(format!("Registry returned HTTP {}", response.status)),
            support_status: None,
        };
    }
    if response.body_truncated {
        return LatestResult {
            latest: None,
            error: Some("Registry metadata exceeded the remaining byte limit".to_owned()),
            support_status: None,
        };
    }
    if ecosystem == TechnologyEcosystem::WebServer {
        return match parse_web_server_latest(identifier, &response.body) {
            Ok(release) => LatestResult {
                latest: release.latest,
                error: None,
                support_status: Some(release.support_status),
            },
            Err(error) => LatestResult {
                latest: None,
                error: Some(error),
                support_status: None,
            },
        };
    }
    match parse_latest(ecosystem, identifier, &response.body) {
        Ok(latest) => LatestResult {
            latest,
            error: None,
            support_status: None,
        },
        Err(error) => LatestResult {
            latest: None,
            error: Some(error),
            support_status: None,
        },
    }
}

fn registry_url(ecosystem: TechnologyEcosystem, identifier: &str) -> Option<String> {
    let identifier = identifier
        .split_once('@')
        .map(|(identifier, _)| identifier)
        .unwrap_or(identifier);
    let encoded = utf8_percent_encode(identifier, NON_ALPHANUMERIC).to_string();
    Some(match ecosystem {
        TechnologyEcosystem::JavaScript => return None,
        TechnologyEcosystem::Npm => format!("https://registry.npmjs.org/{encoded}"),
        TechnologyEcosystem::Composer => format!(
            "https://repo.packagist.org/p2/{}.json",
            encode_path(identifier)
        ),
        TechnologyEcosystem::WordPress if identifier == "wordpress" => {
            "https://api.wordpress.org/core/version-check/1.7/".to_owned()
        }
        TechnologyEcosystem::WordPress => format!(
            "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D={encoded}"
        ),
        TechnologyEcosystem::PyPi => format!("https://pypi.org/pypi/{encoded}/json"),
        TechnologyEcosystem::RubyGems => {
            format!("https://rubygems.org/api/v1/versions/{encoded}.json")
        }
        TechnologyEcosystem::MavenCentral => {
            let (group, artifact) = identifier.split_once(':')?;
            let query_text = format!("g:\"{group}\" AND a:\"{artifact}\"");
            let query = utf8_percent_encode(&query_text, NON_ALPHANUMERIC);
            format!(
                "https://search.maven.org/solrsearch/select?q={query}&core=gav&rows=200&wt=json"
            )
        }
        TechnologyEcosystem::NuGet => format!(
            "https://api-v2v3search-0.nuget.org/query?q=packageid%3A{encoded}&prerelease=false&semVerLevel=2.0.0&take=20"
        ),
        TechnologyEcosystem::GoModules => {
            format!(
                "https://proxy.golang.org/{}/@v/list",
                go_module_escape(identifier)
            )
        }
        TechnologyEcosystem::CratesIo => {
            format!("https://crates.io/api/v1/crates/{encoded}")
        }
        TechnologyEcosystem::Runtime => match identifier {
            "php" => "https://www.php.net/releases/index.php?json&max=100".to_owned(),
            "python" => {
                "https://www.python.org/api/v2/downloads/release/?is_published=true".to_owned()
            }
            "ruby" => "https://cache.ruby-lang.org/pub/ruby/index.txt".to_owned(),
            "java" => "https://api.adoptium.net/v3/info/available_releases".to_owned(),
            "dotnet" => {
                "https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json"
                    .to_owned()
            }
            "go" => "https://go.dev/dl/?mode=json&include=all".to_owned(),
            "rust" => "https://static.rust-lang.org/dist/channel-rust-stable.toml".to_owned(),
            "node" => "https://nodejs.org/dist/index.json".to_owned(),
            _ => return None,
        },
        TechnologyEcosystem::WebServer => web_server_release_source(identifier)?.to_owned(),
    })
}

fn web_server_release_source(identifier: &str) -> Option<&'static str> {
    Some(match identifier {
        "nginx" => "https://nginx.org/en/download.html",
        "apache-httpd" => "https://httpd.apache.org/download",
        "iis" => {
            "https://learn.microsoft.com/en-us/lifecycle/products/internet-information-services-iis"
        }
        "openresty" => "https://openresty.org/en/download.html",
        "litespeed" => "https://www.litespeedtech.com/products/litespeed-web-server/download",
        "openlitespeed" => "https://openlitespeed.org/downloads/",
        "lighttpd" => "https://download.lighttpd.net/lighttpd/releases-1.4.x/latest.txt",
        "caddy" => "https://api.github.com/repos/caddyserver/caddy/releases?per_page=5",
        "tomcat" => "https://tomcat.apache.org/whichversion.html",
        "jetty" => "https://jetty.org/download.html",
        "kestrel" => {
            "https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json"
        }
        "gunicorn" => "https://pypi.org/pypi/gunicorn/json",
        "uvicorn" => "https://pypi.org/pypi/uvicorn/json",
        "puma" => "https://rubygems.org/api/v1/versions/puma.json",
        "passenger" => "https://rubygems.org/api/v1/versions/passenger.json",
        "cowboy" => "https://api.github.com/repos/ninenines/cowboy/tags?per_page=100",
        "werkzeug" => "https://pypi.org/pypi/Werkzeug/json",
        _ => return None,
    })
}

fn encode_path(value: &str) -> String {
    value
        .split('/')
        .map(|segment| utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn go_module_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        if character.is_ascii_uppercase() {
            escaped.push('!');
            escaped.push(character.to_ascii_lowercase());
        } else {
            escaped.push(character);
        }
    }
    encode_path(&escaped)
}

struct WebServerRelease {
    latest: Option<String>,
    support_status: TechnologySupportStatus,
}

fn web_server_cache_identifier(identifier: &str, installed: &str) -> String {
    let line = web_server_release_line(identifier, installed).unwrap_or_else(|| "all".to_owned());
    format!("{}@{}", identifier.to_ascii_lowercase(), line)
}

fn web_server_release_line(identifier: &str, version: &str) -> Option<String> {
    let numbers = version_numbers(version)?;
    let count = match identifier {
        "caddy" => 1,
        "openresty" => 3,
        "nginx" | "apache-httpd" | "iis" | "litespeed" | "openlitespeed" | "lighttpd"
        | "tomcat" | "jetty" | "kestrel" => 2,
        _ => return None,
    };
    (numbers.len() >= count).then(|| {
        numbers
            .into_iter()
            .take(count)
            .map(|number| number.to_string())
            .collect::<Vec<_>>()
            .join(".")
    })
}

fn parse_web_server_latest(identifier: &str, bytes: &[u8]) -> Result<WebServerRelease, String> {
    let (identifier, detected_line) = identifier
        .split_once('@')
        .map(|(identifier, line)| (identifier, (line != "all").then_some(line)))
        .unwrap_or((identifier, None));
    let versions = web_server_versions(identifier, bytes)?;
    let latest_overall = max_stable(versions.iter().map(String::as_str));
    let latest_in_line = detected_line.and_then(|line| {
        max_stable(versions.iter().filter_map(|version| {
            (web_server_release_line(identifier, version).as_deref() == Some(line))
                .then_some(version.as_str())
        }))
    });
    let latest = latest_in_line.clone().or(latest_overall.clone());
    if latest.is_none() {
        return Err("Upstream metadata returned no stable release".to_owned());
    }
    let support_status = web_server_support_status(
        identifier,
        detected_line,
        latest_overall.as_deref(),
        latest_in_line.is_some(),
        bytes,
    );
    Ok(WebServerRelease {
        latest,
        support_status,
    })
}

fn web_server_versions(identifier: &str, bytes: &[u8]) -> Result<Vec<String>, String> {
    let mut versions = match identifier {
        "gunicorn" | "uvicorn" | "werkzeug" => {
            let value = json(bytes, "PyPI")?;
            value
                .get("releases")
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|releases| releases.iter())
                .filter(|(_, files)| {
                    files.as_array().is_some_and(|files| {
                        files.iter().any(|file| {
                            !file.get("yanked").and_then(Value::as_bool).unwrap_or(false)
                        })
                    })
                })
                .map(|(version, _)| version.to_owned())
                .collect()
        }
        "puma" | "passenger" => {
            let value = json(bytes, "RubyGems")?;
            value
                .as_array()
                .into_iter()
                .flatten()
                .filter(|item| {
                    !item
                        .get("prerelease")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                        && !item.get("yanked").and_then(Value::as_bool).unwrap_or(false)
                })
                .filter_map(|item| {
                    item.get("number")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .collect()
        }
        "caddy" | "cowboy" => {
            let value = json(bytes, "GitHub releases")?;
            value
                .as_array()
                .into_iter()
                .flatten()
                .filter(|release| {
                    !release
                        .get("draft")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                        && !release
                            .get("prerelease")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                })
                .filter_map(|release| {
                    release
                        .get("tag_name")
                        .or_else(|| release.get("name"))
                        .and_then(Value::as_str)
                })
                .filter_map(server_version_from_tag)
                .collect()
        }
        "kestrel" => {
            let value = json(bytes, ".NET release")?;
            value
                .get("releases-index")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|release| release.get("latest-release").and_then(Value::as_str))
                .map(str::to_owned)
                .collect()
        }
        _ => web_server_html_versions(identifier, bytes)?,
    };
    versions.retain(|version| version_numbers(version).is_some() && !is_prerelease(version));
    versions.sort_by(|left, right| compare_version_values(left, right).unwrap_or(Ordering::Equal));
    versions.dedup();
    Ok(versions)
}

fn web_server_html_versions(identifier: &str, bytes: &[u8]) -> Result<Vec<String>, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| format!("invalid upstream release page: {error}"))?;
    if identifier == "iis" {
        let regex = Regex::new(r"(?i)\bIIS\s+([0-9]+(?:\.[0-9]+)?)")
            .map_err(|error| format!("invalid release parser: {error}"))?;
        return Ok(regex
            .captures_iter(text)
            .filter_map(|captures| captures.get(1).map(|value| value.as_str()))
            .map(|version| {
                if version.contains('.') {
                    version.to_owned()
                } else {
                    format!("{version}.0")
                }
            })
            .collect());
    }
    if identifier == "litespeed" {
        return html_capture_versions(text, r"(?i)version\s+([0-9]+(?:\.[0-9]+){1,3})\s+stable", 1);
    }
    if identifier == "openlitespeed" {
        return html_capture_versions(
            text,
            r"(?is)openlitespeed\s+v\s*([0-9]+(?:\.[0-9]+){1,3}).{0,200}?\bstable\b",
            1,
        );
    }
    if identifier == "tomcat" {
        let regex =
            Regex::new(r"(?is)([0-9]{1,2}\.[0-9]+)\.x.{0,400}?([0-9]{1,2}\.[0-9]+\.[0-9]+)")
                .map_err(|error| format!("invalid release parser: {error}"))?;
        return Ok(regex
            .captures_iter(text)
            .filter_map(|captures| {
                let line = captures.get(1)?.as_str();
                let version = captures.get(2)?.as_str();
                version
                    .starts_with(&format!("{line}."))
                    .then(|| version.to_owned())
            })
            .collect());
    }
    if identifier == "jetty" {
        return html_capture_versions(
            text,
            r"(?i)>\s*([0-9]{1,2}\.[0-9]+\.[0-9]+(?:\.v[0-9]+)?)\s*(?:\(EOL\))?\s*<",
            1,
        );
    }
    let pattern = match identifier {
        "nginx" => r"(?i)nginx-([0-9]+(?:\.[0-9]+){1,3}(?:[-._](?:alpha|beta|rc)[0-9]*)?)",
        "apache-httpd" => r"(?i)httpd-([0-9]+(?:\.[0-9]+){1,3}(?:[-._](?:alpha|beta|rc)[0-9]*)?)",
        "openresty" => r"(?i)openresty-([0-9]+(?:\.[0-9]+){1,3}(?:[-._](?:alpha|beta|rc)[0-9]*)?)",
        "lighttpd" => r"(?i)lighttpd-([0-9]+(?:\.[0-9]+){1,3})",
        _ => return Ok(Vec::new()),
    };
    let regex = Regex::new(pattern).map_err(|error| format!("invalid release parser: {error}"))?;
    Ok(regex
        .captures_iter(text)
        .filter_map(|captures| captures.get(1).map(|value| value.as_str().to_owned()))
        .collect())
}

fn html_capture_versions(text: &str, pattern: &str, group: usize) -> Result<Vec<String>, String> {
    let regex = Regex::new(pattern).map_err(|error| format!("invalid release parser: {error}"))?;
    Ok(regex
        .captures_iter(text)
        .filter_map(|captures| captures.get(group).map(|value| value.as_str().to_owned()))
        .collect())
}

fn server_version_from_tag(tag: &str) -> Option<String> {
    let start = tag.find(|character: char| character.is_ascii_digit())?;
    let version = tag[start..]
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '+')
        })
        .collect::<String>();
    version_numbers(&version).is_some().then_some(version)
}

fn web_server_support_status(
    identifier: &str,
    detected_line: Option<&str>,
    latest_overall: Option<&str>,
    line_found: bool,
    bytes: &[u8],
) -> TechnologySupportStatus {
    let Some(line) = detected_line else {
        return TechnologySupportStatus::Unknown;
    };
    if let Some(supported) = explicitly_supported_line(identifier, line, bytes) {
        return if supported {
            TechnologySupportStatus::Supported
        } else {
            TechnologySupportStatus::Unsupported
        };
    }
    if line_marked_unsupported(line, bytes) {
        return TechnologySupportStatus::Unsupported;
    }
    if matches!(
        identifier,
        "gunicorn" | "uvicorn" | "puma" | "passenger" | "cowboy" | "werkzeug"
    ) {
        return TechnologySupportStatus::Unknown;
    }
    if matches!(identifier, "nginx" | "tomcat" | "jetty") {
        return if line_found {
            TechnologySupportStatus::Supported
        } else {
            TechnologySupportStatus::Unsupported
        };
    }
    let current_line =
        latest_overall.and_then(|version| web_server_release_line(identifier, version));
    if current_line.as_deref() == Some(line) {
        TechnologySupportStatus::Supported
    } else {
        TechnologySupportStatus::Unsupported
    }
}

fn explicitly_supported_line(identifier: &str, line: &str, bytes: &[u8]) -> Option<bool> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    match identifier {
        "nginx" => {
            let legacy = text.find("legacy versions")?;
            let version = format!("nginx-{line}.");
            if text[..legacy].contains(&version) {
                Some(true)
            } else if text[legacy..].contains(&version) {
                Some(false)
            } else {
                None
            }
        }
        "tomcat" => {
            let unsupported = text.find("unsupported versions")?;
            let version = format!("{line}.x");
            if text[..unsupported].contains(&version) {
                Some(true)
            } else if text[unsupported..].contains(&version) {
                Some(false)
            } else {
                None
            }
        }
        "kestrel" => {
            let value = serde_json::from_slice::<Value>(bytes).ok()?;
            let release = value
                .get("releases-index")
                .and_then(Value::as_array)?
                .iter()
                .find(|release| {
                    release
                        .get("channel-version")
                        .and_then(Value::as_str)
                        .is_some_and(|version| {
                            web_server_release_line("kestrel", version).as_deref() == Some(line)
                        })
                })?;
            release
                .get("support-phase")
                .and_then(Value::as_str)
                .map(|phase| !matches!(phase.to_ascii_lowercase().as_str(), "eol" | "end-of-life"))
        }
        _ => None,
    }
}

fn line_marked_unsupported(line: &str, bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let markers = [
        "end of life",
        "eol",
        "unsupported",
        "not supported",
        "obsolete",
        "legacy",
        "archived",
        "superseded",
        "deprecated",
    ];
    let mut offset = 0;
    while let Some(index) = text[offset..].find(line) {
        let index = offset + index;
        let row_start = text[..index]
            .rfind("<tr")
            .filter(|row| index - *row <= 2_000);
        let line_start = text[..index].rfind('\n').map(|line| line + 1);
        let start = row_start.or(line_start).unwrap_or(index);
        let row_end = text[index..]
            .find("</tr>")
            .map(|end| index + end + 5)
            .filter(|end| *end - index <= 2_000);
        let line_end = text[index..].find('\n').map(|end| index + end);
        let end = row_end
            .or(line_end)
            .unwrap_or(index + line.len())
            .min(text.len());
        if markers
            .iter()
            .any(|marker| text[start..end].contains(marker))
        {
            return true;
        }
        offset = index + line.len();
    }
    false
}

fn parse_latest(
    ecosystem: TechnologyEcosystem,
    identifier: &str,
    bytes: &[u8],
) -> Result<Option<String>, String> {
    match ecosystem {
        TechnologyEcosystem::JavaScript => Ok(None),
        TechnologyEcosystem::Npm => {
            let value = json(bytes, "npm")?;
            let latest = max_stable(
                value
                    .get("versions")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|versions| versions.keys().map(String::as_str)),
            );
            if latest.is_some() {
                Ok(latest)
            } else {
                Ok(value
                    .get("dist-tags")
                    .and_then(|tags| tags.get("latest"))
                    .and_then(Value::as_str)
                    .filter(|version| !is_prerelease(version))
                    .map(normalize_version))
            }
        }
        TechnologyEcosystem::Composer => {
            let value = json(bytes, "Packagist")?;
            Ok(max_stable(
                value
                    .get("packages")
                    .and_then(|packages| packages.get(identifier))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|item| item.get("version").and_then(Value::as_str)),
            ))
        }
        TechnologyEcosystem::WordPress if identifier == "wordpress" => {
            let value = json(bytes, "WordPress core")?;
            Ok(value
                .get("offers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|item| item.get("current").and_then(Value::as_str))
                .find(|version| !is_prerelease(version))
                .map(str::to_owned))
        }
        TechnologyEcosystem::WordPress => {
            let value = json(bytes, "WordPress Plugin API")?;
            Ok(value
                .get("version")
                .and_then(Value::as_str)
                .filter(|version| !is_prerelease(version))
                .map(str::to_owned))
        }
        TechnologyEcosystem::PyPi => {
            let value = json(bytes, "PyPI")?;
            Ok(max_stable(
                value
                    .get("releases")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|releases| releases.iter())
                    .filter(|(_, files)| {
                        files.as_array().is_some_and(|files| {
                            files.iter().any(|file| {
                                !file.get("yanked").and_then(Value::as_bool).unwrap_or(false)
                            })
                        })
                    })
                    .map(|(version, _)| version.as_str()),
            ))
        }
        TechnologyEcosystem::RubyGems => {
            let value = json(bytes, "RubyGems")?;
            Ok(max_stable(
                value
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|item| {
                        !item
                            .get("prerelease")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                            && !item.get("yanked").and_then(Value::as_bool).unwrap_or(false)
                    })
                    .filter_map(|item| item.get("number").and_then(Value::as_str)),
            ))
        }
        TechnologyEcosystem::MavenCentral => {
            let value = json(bytes, "Maven Central")?;
            Ok(max_stable(
                value
                    .get("response")
                    .and_then(|response| response.get("docs"))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|item| item.get("v").and_then(Value::as_str)),
            ))
        }
        TechnologyEcosystem::NuGet => {
            let value = json(bytes, "NuGet")?;
            Ok(value
                .get("data")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .find(|item| {
                    item.get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| id.eq_ignore_ascii_case(identifier))
                })
                .and_then(|item| item.get("version"))
                .and_then(Value::as_str)
                .filter(|version| !is_prerelease(version))
                .map(str::to_owned))
        }
        TechnologyEcosystem::GoModules => {
            let text = std::str::from_utf8(bytes)
                .map_err(|error| format!("invalid Go proxy response: {error}"))?;
            Ok(max_stable(text.lines()))
        }
        TechnologyEcosystem::CratesIo => {
            let value = json(bytes, "crates.io")?;
            Ok(max_stable(
                value
                    .get("versions")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|item| !item.get("yanked").and_then(Value::as_bool).unwrap_or(false))
                    .filter_map(|item| item.get("num").and_then(Value::as_str)),
            ))
        }
        TechnologyEcosystem::Runtime => parse_runtime_latest(identifier, bytes),
        TechnologyEcosystem::WebServer => Ok(None),
    }
}

fn json(bytes: &[u8], source: &str) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("invalid {source} metadata: {error}"))
}

fn parse_runtime_latest(identifier: &str, bytes: &[u8]) -> Result<Option<String>, String> {
    match identifier {
        "php" => {
            let value = json(bytes, "PHP release")?;
            let versions = value
                .as_object()
                .into_iter()
                .flat_map(|releases| releases.values())
                .filter_map(|release| {
                    release
                        .get("version")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .or_else(|| {
                            release
                                .get("source")
                                .and_then(Value::as_array)
                                .into_iter()
                                .flatten()
                                .filter_map(|source| source.get("name").and_then(Value::as_str))
                                .find_map(|name| {
                                    capture(name, r"(?i)\bPHP\s+([0-9]+(?:\.[0-9]+){1,3})\b")
                                })
                        })
                })
                .collect::<Vec<_>>();
            Ok(max_stable(versions.iter().map(String::as_str)))
        }
        "python" => {
            let value = json(bytes, "Python release")?;
            Ok(max_stable(
                value
                    .get("results")
                    .and_then(Value::as_array)
                    .or_else(|| value.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|item| item.get("name").and_then(Value::as_str))
                    .filter_map(|name| name.strip_prefix("Python ")),
            ))
        }
        "ruby" => {
            let text = std::str::from_utf8(bytes)
                .map_err(|error| format!("invalid Ruby release feed: {error}"))?;
            let pattern = Regex::new(r"ruby-([0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9.]+)?)")
                .expect("valid regex");
            Ok(max_stable(pattern.captures_iter(text).filter_map(
                |captures| captures.get(1).map(|value| value.as_str()),
            )))
        }
        "java" => {
            let value = json(bytes, "OpenJDK release")?;
            Ok(value
                .get("most_recent_feature_release")
                .and_then(Value::as_u64)
                .map(|version| version.to_string()))
        }
        "dotnet" => {
            let value = json(bytes, ".NET release")?;
            Ok(max_stable(
                value
                    .get("releases-index")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|item| item.get("latest-release").and_then(Value::as_str)),
            ))
        }
        "go" => {
            let value = json(bytes, "Go release")?;
            Ok(max_stable(
                value
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|item| item.get("stable").and_then(Value::as_bool).unwrap_or(false))
                    .filter_map(|item| item.get("version").and_then(Value::as_str))
                    .filter_map(|version| version.strip_prefix("go")),
            ))
        }
        "rust" => {
            let text = std::str::from_utf8(bytes)
                .map_err(|error| format!("invalid Rust release feed: {error}"))?;
            Ok(capture(
                text,
                r#"(?ms)^\[pkg\.rust\]\s+version\s*=\s*[\"']([0-9]+(?:\.[0-9]+){1,3})"#,
            )
            .filter(|version| !is_prerelease(version)))
        }
        "node" => {
            let value = json(bytes, "Node.js release")?;
            Ok(max_stable(
                value
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|item| item.get("version").and_then(Value::as_str)),
            ))
        }
        _ => Ok(None),
    }
}

fn max_stable<'a>(versions: impl Iterator<Item = &'a str>) -> Option<String> {
    versions
        .filter(|version| !is_prerelease(version) && version_numbers(version).is_some())
        .max_by(|left, right| compare_version_values(left, right).unwrap_or(Ordering::Equal))
        .map(normalize_version)
}

fn is_prerelease(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    if parse_semver_flexible(&lower).is_some_and(|version| !version.pre.is_empty()) {
        return true;
    }
    Regex::new(
        r"(?i)(?:^|[._-])(?:alpha|beta|preview|pre|rc|dev|snapshot|nightly|canary)(?:[._-]?[0-9]+|$)|[0-9](?:a|b|rc)[0-9]+",
    )
    .expect("valid prerelease regex")
    .is_match(&lower)
}

fn version_numbers(version: &str) -> Option<Vec<u64>> {
    let normalized = normalize_version(version);
    let start = normalized.find(|character: char| character.is_ascii_digit())?;
    let mut numbers = Vec::new();
    let mut current = String::new();
    for character in normalized[start..].chars() {
        if character.is_ascii_digit() {
            current.push(character);
        } else if character == '.' {
            if current.is_empty() {
                break;
            }
            numbers.push(current.parse().ok()?);
            current.clear();
        } else {
            break;
        }
    }
    if !current.is_empty() {
        numbers.push(current.parse().ok()?);
    }
    (!numbers.is_empty()).then_some(numbers)
}

fn compare_version_values(left: &str, right: &str) -> Option<Ordering> {
    let mut left = version_numbers(left)?;
    let mut right = version_numbers(right)?;
    let length = left.len().max(right.len()).max(3);
    left.resize(length, 0);
    right.resize(length, 0);
    Some(left.cmp(&right))
}

fn compare_versions(
    ecosystem: TechnologyEcosystem,
    installed: &str,
    latest: &str,
) -> TechnologyVersionStatus {
    if is_prerelease(installed) || is_prerelease(latest) {
        return TechnologyVersionStatus::Prerelease;
    }
    if matches!(
        ecosystem,
        TechnologyEcosystem::Npm
            | TechnologyEcosystem::NuGet
            | TechnologyEcosystem::GoModules
            | TechnologyEcosystem::CratesIo
    ) && let (Some(installed), Some(latest)) = (
        parse_semver_flexible(installed),
        parse_semver_flexible(latest),
    ) {
        return match installed.cmp(&latest) {
            Ordering::Equal => TechnologyVersionStatus::Current,
            Ordering::Greater => TechnologyVersionStatus::NewerThanLatest,
            Ordering::Less if installed.major != latest.major => {
                TechnologyVersionStatus::OutdatedMajor
            }
            Ordering::Less if installed.minor != latest.minor => {
                TechnologyVersionStatus::OutdatedMinor
            }
            Ordering::Less => TechnologyVersionStatus::OutdatedPatch,
        };
    }
    let Some(installed_parts) = version_numbers(installed) else {
        return TechnologyVersionStatus::Unverifiable;
    };
    let Some(latest_parts) = version_numbers(latest) else {
        return TechnologyVersionStatus::Unverifiable;
    };
    match compare_version_values(installed, latest) {
        Some(Ordering::Equal) => TechnologyVersionStatus::Current,
        Some(Ordering::Greater) => TechnologyVersionStatus::NewerThanLatest,
        Some(Ordering::Less)
            if installed_parts.first().copied().unwrap_or(0)
                != latest_parts.first().copied().unwrap_or(0) =>
        {
            TechnologyVersionStatus::OutdatedMajor
        }
        Some(Ordering::Less)
            if installed_parts.get(1).copied().unwrap_or(0)
                != latest_parts.get(1).copied().unwrap_or(0) =>
        {
            TechnologyVersionStatus::OutdatedMinor
        }
        Some(Ordering::Less) => TechnologyVersionStatus::OutdatedPatch,
        None => TechnologyVersionStatus::Unverifiable,
    }
}

fn parse_semver_flexible(version: &str) -> Option<Version> {
    let normalized = normalize_version(version);
    if let Ok(version) = Version::parse(&normalized) {
        return Some(version);
    }
    let split = normalized.find(['-', '+']).unwrap_or(normalized.len());
    let (core, suffix) = normalized.split_at(split);
    let dots = core.chars().filter(|character| *character == '.').count();
    let padded = match dots {
        0 => format!("{core}.0.0{suffix}"),
        1 => format!("{core}.0{suffix}"),
        _ => return None,
    };
    Version::parse(&padded).ok()
}

fn outdated_findings(endpoints: &[EndpointScan]) -> Vec<ExposureFinding> {
    let mut findings = BTreeMap::new();
    let mut outdated = BTreeMap::new();
    for endpoint in endpoints {
        for component in &endpoint.technology_components {
            if component.support_status == TechnologySupportStatus::Unsupported
                && let Some(installed) = component.installed_version.as_deref()
            {
                let title = format!(
                    "Unsupported technology release line: {} {installed}",
                    component.name
                );
                let mut evidence = component
                    .evidence_urls
                    .iter()
                    .map(|url| format!("Affected resource: {url}"))
                    .collect::<Vec<_>>();
                if let Some(source) = &component.release_source_url {
                    evidence.push(format!("Upstream lifecycle/release source: {source}"));
                }
                evidence.sort();
                evidence.dedup();
                findings.insert(
                    (endpoint.ip, endpoint.port, title.clone()),
                    ExposureFinding {
                        title,
                        description: format!(
                            "Upstream release metadata designates the detected {} release line as legacy, end-of-life, or outside the currently supported line",
                            component.name
                        ),
                        ip: endpoint.ip,
                        port: endpoint.port,
                        evidence,
                    },
                );
            }
            if !matches!(
                component.status,
                TechnologyVersionStatus::OutdatedPatch
                    | TechnologyVersionStatus::OutdatedMinor
                    | TechnologyVersionStatus::OutdatedMajor
            ) {
                continue;
            }
            let (Some(installed), Some(latest)) = (
                component.installed_version.as_deref(),
                component.latest_version.as_deref(),
            ) else {
                continue;
            };
            let difference = match component.status {
                TechnologyVersionStatus::OutdatedPatch => "Patch",
                TechnologyVersionStatus::OutdatedMinor => "Minor",
                TechnologyVersionStatus::OutdatedMajor => "Major",
                _ => unreachable!(),
            };
            let title = format!(
                "Outdated component: {} {installed} - {latest} ({difference} Difference)",
                component.name,
            );
            let mut evidence = component
                .evidence_urls
                .iter()
                .map(|url| format!("Affected resource: {url}"))
                .collect::<Vec<_>>();
            if let Some(source) = &component.release_source_url {
                evidence.push(format!("Upstream release source: {source}"));
            }
            evidence.sort();
            evidence.dedup();
            let candidate = ExposureFinding {
                title,
                description: format!(
                    "Installed {} {} is behind the newest stable {} release {} ({} difference)",
                    component.name,
                    installed,
                    component.ecosystem,
                    latest,
                    difference.to_ascii_lowercase()
                ),
                ip: endpoint.ip,
                port: endpoint.port,
                evidence,
            };
            let key = (
                component.name.clone(),
                installed.to_owned(),
                latest.to_owned(),
            );
            match outdated.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(candidate);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let existing = entry.get();
                    let candidate_url = candidate
                        .evidence
                        .iter()
                        .find_map(|item| item.strip_prefix("Affected resource: "))
                        .unwrap_or_default();
                    let existing_url = existing
                        .evidence
                        .iter()
                        .find_map(|item| item.strip_prefix("Affected resource: "))
                        .unwrap_or_default();
                    if (candidate.ip, candidate.port, candidate_url)
                        < (existing.ip, existing.port, existing_url)
                    {
                        entry.insert(candidate);
                    }
                }
            }
        }
    }
    let mut findings = findings
        .into_values()
        .chain(outdated.into_values())
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        left.ip
            .cmp(&right.ip)
            .then(left.port.cmp(&right.port))
            .then(left.title.cmp(&right.title))
    });
    findings
}
