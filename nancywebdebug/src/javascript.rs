use super::crawl::hostname_in_scope;
use super::fingerprints::CapturedScriptResponse;
use super::{
    ConnectionRateLimiter, EndpointScan, ExposureScanPhase, ExposureScanPhaseState,
    ExposureScanProgress, ExposureScanRequest, HttpObservation, JavaScriptLibrary,
    JavaScriptSource, ProbeContext, ScanContext, TechnologyVersionStatus, non_public_reason,
    send_phase_progress, single_http_request, url_path,
};
use crate::auth::{LoadedClientCertificate, ResolvedAuth};
use crate::diagnostics::DnsTrace;
use crate::request::resolve_host;
use futures_util::stream::{FuturesUnordered, StreamExt};
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::{
    BufferQueue, StartTag, TagToken, Token, TokenSink, TokenSinkResult, Tokenizer,
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use semver::Version;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, LazyLock, mpsc::Sender};
use std::time::Duration;
use tokio::sync::{Mutex, OnceCell};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

const CATALOG_URL: &str =
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json";
const MAX_SOURCES: usize = 256;
const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONCURRENT_FETCHES: usize = 8;
const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOTAL_METADATA_BYTES: usize = 32 * 1024 * 1024;
const ENRICHMENT_TIMEOUT: Duration = Duration::from_secs(60);
static JQUERY_CDN_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^jquery-([0-9][0-9A-Za-z._-]*?)(?:\.min)?\.js$").expect("valid regex")
});

pub(super) const METADATA_LIMIT_ERROR: &str = "Technology metadata byte limit reached";
pub(super) const ENRICHMENT_DEADLINE_ERROR: &str =
    "Technology metadata enrichment deadline reached";
pub(super) const ENRICHMENT_CANCELLED_ERROR: &str = "Technology analysis cancelled";

type Resolution = Result<Vec<IpAddr>, String>;
type ResolutionCell = Arc<OnceCell<Resolution>>;
type ResolutionCache = Arc<Mutex<HashMap<String, ResolutionCell>>>;

pub(super) struct AnalysisReport {
    pub warnings: Vec<String>,
    pub captured_responses: Vec<CapturedScriptResponse>,
}

#[derive(Clone)]
struct CatalogEntry {
    name: String,
    npm_package: Option<String>,
    uri: Vec<Regex>,
    filename: Vec<Regex>,
    content: Vec<Regex>,
    replacements: Vec<ReplacementExtractor>,
    hashes: HashMap<String, String>,
}

#[derive(Clone)]
struct ReplacementExtractor {
    regex: Regex,
    replacement: String,
}

#[derive(Clone)]
pub(super) struct Fetched {
    pub final_url: Option<Url>,
    pub response: Option<HttpObservation>,
    pub error: Option<String>,
    pub captured_bytes: usize,
}

#[derive(Clone)]
struct NpmResult {
    latest: Option<String>,
    error: Option<String>,
}

#[derive(Clone)]
pub(super) struct MetadataFetchContext {
    deadline: Instant,
    resolutions: ResolutionCache,
}

pub(super) struct EnrichmentState {
    deadline: Option<Instant>,
    pub(super) remaining_bytes: usize,
    resolutions: ResolutionCache,
    metadata: HashMap<String, Fetched>,
}

impl EnrichmentState {
    pub(super) fn new() -> Self {
        Self {
            deadline: None,
            remaining_bytes: MAX_TOTAL_METADATA_BYTES,
            resolutions: Arc::new(Mutex::new(HashMap::new())),
            metadata: HashMap::new(),
        }
    }

    pub(super) fn start(&mut self) {
        self.deadline
            .get_or_insert_with(|| Instant::now() + ENRICHMENT_TIMEOUT);
    }

    pub(super) fn fetch_context(&self) -> MetadataFetchContext {
        MetadataFetchContext {
            deadline: self
                .deadline
                .expect("metadata enrichment must be started before fetching"),
            resolutions: self.resolutions.clone(),
        }
    }

    pub(super) fn cached(&self, url: &str) -> Option<Fetched> {
        self.metadata.get(url).cloned()
    }

    pub(super) fn stop_error(&self, cancel: &CancellationToken) -> Option<&'static str> {
        if cancel.is_cancelled() {
            Some(ENRICHMENT_CANCELLED_ERROR)
        } else if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            Some(ENRICHMENT_DEADLINE_ERROR)
        } else if self.remaining_bytes == 0 {
            Some(METADATA_LIMIT_ERROR)
        } else {
            None
        }
    }
}

#[derive(Default)]
struct ScriptSink(RefCell<Vec<String>>);

impl TokenSink for ScriptSink {
    type Handle = ();

    fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
        if let TagToken(tag) = token
            && tag.kind == StartTag
            && tag.name.as_ref().eq_ignore_ascii_case("script")
            && let Some(source) = tag
                .attrs
                .iter()
                .find(|attribute| attribute.name.local.as_ref().eq_ignore_ascii_case("src"))
                .map(|attribute| attribute.value.to_string())
                .filter(|source| !source.trim().is_empty())
        {
            self.0.borrow_mut().push(source);
        }
        TokenSinkResult::Continue
    }
}

pub(super) fn discover_sources(root: &HttpObservation) -> Vec<String> {
    if !(200..300).contains(&root.status) {
        return Vec::new();
    }
    let Ok(base) = Url::parse(&root.url) else {
        return Vec::new();
    };
    let input = BufferQueue::default();
    input.push_back(StrTendril::from(
        String::from_utf8_lossy(&root.body).as_ref(),
    ));
    let tokenizer = Tokenizer::new(ScriptSink::default(), Default::default());
    let _ = tokenizer.feed(&input);
    tokenizer.end();
    let mut seen = HashSet::new();
    let mut sources = Vec::new();
    for reference in tokenizer.sink.0.into_inner() {
        if let Ok(mut url) = base.join(&reference)
            && matches!(url.scheme(), "http" | "https")
            && base
                .host_str()
                .zip(url.host_str())
                .is_some_and(|(root_hostname, hostname)| hostname_in_scope(root_hostname, hostname))
        {
            url.set_fragment(None);
            let normalized = url.to_string();
            if seen.insert(normalized.clone()) {
                sources.push(normalized);
            }
        }
    }
    sources
}

pub(super) async fn analyze(
    endpoints: &mut [EndpointScan],
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
    enrichment: &mut EnrichmentState,
    progress: &Option<Sender<ExposureScanProgress>>,
    http_auth: Option<&ResolvedAuth>,
    auth_hostname: &str,
    client_certificate: Option<&LoadedClientCertificate>,
) -> AnalysisReport {
    send_phase_progress(
        progress,
        ExposureScanPhase::JavaScriptAnalysis,
        ExposureScanPhaseState::Running,
        0.0,
        "Loading JavaScript catalog",
    );
    let catalog_result =
        ({
            let (request, cancel, limiter): (
                &ExposureScanRequest,
                &CancellationToken,
                &ConnectionRateLimiter,
            ) = (request, cancel, limiter);
            async move {
                let fetched = fetch_url(
                    CATALOG_URL,
                    MAX_METADATA_BYTES,
                    &[("Accept", "application/json")],
                    request,
                    cancel,
                    limiter,
                )
                .await;
                if let Some(error) = fetched.error {
                    return Err(error);
                }
                let response = fetched
                    .response
                    .ok_or_else(|| "catalog returned no response".to_owned())?;
                if !(200..300).contains(&response.status) {
                    return Err(format!("catalog returned HTTP {}", response.status));
                }
                if response.body_truncated {
                    return Err("catalog response exceeded 4 MiB".to_owned());
                }
                {
                    let (bytes,): (&[u8],) = (&response.body,);
                    let inlined_result: Result<Vec<CatalogEntry>, String> =
                        {
                            'inlined_parse_catalog: {
                                let value = match serde_json::from_slice::<serde_json::Value>(bytes)
                                    .map_err(|error| format!("invalid catalog JSON: {error}"))
                                {
                                    Ok(value) => value,
                                    Err(error) => {
                                        break 'inlined_parse_catalog Err(
                                            ::core::convert::From::from(error),
                                        );
                                    }
                                };
                                let root = match value
                                    .as_object()
                                    .ok_or_else(|| "catalog root is not an object".to_owned())
                                {
                                    Ok(value) => value,
                                    Err(error) => {
                                        break 'inlined_parse_catalog Err(
                                            ::core::convert::From::from(error),
                                        );
                                    }
                                };
                                let mut entries = Vec::new();
                                for (name, value) in root {
                                    let Some(object) = value.as_object() else {
                                        continue;
                                    };
                                    let npm_package = object
                                        .get("npmname")
                                        .and_then(serde_json::Value::as_str)
                                        .map(str::to_owned);
                                    let Some(extractors) = object
                                        .get("extractors")
                                        .and_then(serde_json::Value::as_object)
                                    else {
                                        continue;
                                    };
                                    let uri = {
                                        let (value,): (Option<&serde_json::Value>,) =
                                            (extractors.get("uri"),);
                                        let inlined_result: Vec<Regex> =
                                            {
                                                value
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|pattern| {
            let pattern = pattern.replace("§§version§§", "(?P<nancy_version>[0-9][0-9A-Za-z._-]*)");
            Regex::new(&pattern).ok()
        })
        .collect()
                                            };
                                        inlined_result
                                    };
                                    let filename = {
                                        let (value,): (Option<&serde_json::Value>,) =
                                            (extractors.get("filename"),);
                                        let inlined_result: Vec<Regex> =
                                            {
                                                value
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|pattern| {
            let pattern = pattern.replace("§§version§§", "(?P<nancy_version>[0-9][0-9A-Za-z._-]*)");
            Regex::new(&pattern).ok()
        })
        .collect()
                                            };
                                        inlined_result
                                    };
                                    let content = {
                                        let (value,): (Option<&serde_json::Value>,) =
                                            (extractors.get("filecontent"),);
                                        let inlined_result: Vec<Regex> =
                                            {
                                                value
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .filter_map(|pattern| {
            let pattern = pattern.replace("§§version§§", "(?P<nancy_version>[0-9][0-9A-Za-z._-]*)");
            Regex::new(&pattern).ok()
        })
        .collect()
                                            };
                                        inlined_result
                                    };
                                    let replacements = extractors
                                        .get("filecontentreplace")
                                        .and_then(serde_json::Value::as_array)
                                        .into_iter()
                                        .flatten()
                                        .filter_map(serde_json::Value::as_str)
                                        .filter_map(|value: &str| {
                                            let inner =
                                                value.strip_prefix('/')?.strip_suffix('/')?;
                                            let split = inner.rfind('/')?;
                                            let (pattern, replacement) = inner.split_at(split);
                                            let replacement = replacement.strip_prefix('/')?;
                                            Some(ReplacementExtractor {
                                                regex: Regex::new(pattern).ok()?,
                                                replacement: replacement.to_owned(),
                                            })
                                        })
                                        .collect();
                                    let hashes = extractors
                                        .get("hashes")
                                        .and_then(serde_json::Value::as_object)
                                        .into_iter()
                                        .flat_map(|hashes| hashes.iter())
                                        .filter_map(|(hash, version)| {
                                            version.as_str().map(|version| {
                                                (hash.to_ascii_lowercase(), version.to_owned())
                                            })
                                        })
                                        .collect();
                                    entries.push(CatalogEntry {
                                        name: name.clone(),
                                        npm_package,
                                        uri,
                                        filename,
                                        content,
                                        replacements,
                                        hashes,
                                    });
                                }
                                Ok(entries)
                            }
                        };
                    inlined_result
                }
            }
        })
        .await;
    let (catalog, catalog_error) = match catalog_result {
        Ok(catalog) => (catalog, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let mut warnings = catalog_error
        .as_ref()
        .map(|error| vec![format!("JavaScript catalog unavailable: {error}")])
        .unwrap_or_default();
    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::JavaScriptAnalysis,
            ExposureScanPhaseState::Running,
            0.10,
            "JavaScript catalog loaded",
        );
    }

    let mut unique = Vec::new();
    let mut seen = HashSet::new();
    let mut source_locations: Vec<(usize, String)> = Vec::new();
    for (endpoint_index, endpoint) in endpoints.iter_mut().enumerate() {
        if super::endpoint_health::stopped(endpoint.ip, endpoint.port) {
            continue;
        }
        endpoint.javascript_sources.clear();
        for source in std::mem::take(&mut endpoint.javascript_candidates) {
            source_locations.push((endpoint_index, source.clone()));
            if seen.insert(source.clone()) {
                unique.push(source);
            }
        }
    }

    let skipped = unique.len().saturating_sub(MAX_SOURCES);
    if skipped > 0 {
        warnings.push(format!(
            "JavaScript source limit reached: {skipped} unique source(s) were not fetched"
        ));
    }
    let allowed = unique.iter().take(MAX_SOURCES).cloned().collect::<Vec<_>>();
    let limited = unique
        .iter()
        .skip(MAX_SOURCES)
        .cloned()
        .collect::<HashSet<_>>();
    let mut source_cache = HashMap::new();
    let mut capture_cache = HashMap::new();
    let mut remaining = MAX_TOTAL_BYTES;
    let mut reserved = 0usize;
    let mut next_source = 0usize;
    let mut completed_sources = 0usize;
    let mut pending = FuturesUnordered::new();
    while next_source < allowed.len() || !pending.is_empty() {
        if cancel.is_cancelled() {
            pending.clear();
            break;
        }
        while pending.len() < MAX_CONCURRENT_FETCHES && next_source < allowed.len() {
            let available = remaining.saturating_sub(reserved);
            if available == 0 {
                break;
            }
            let body_limit = MAX_SOURCE_BYTES.min(available);
            let source = allowed[next_source].clone();
            next_source += 1;
            reserved += body_limit;
            pending.push(async move {
                let fetched = ({
                    let (
                        initial_url,
                        body_limit,
                        headers,
                        request,
                        cancel,
                        limiter,
                        http_auth,
                        auth_hostname,
                        client_certificate,
                    ): (
                        &str,
                        usize,
                        &[(&str, &str)],
                        &ExposureScanRequest,
                        &CancellationToken,
                        &ConnectionRateLimiter,
                        Option<&ResolvedAuth>,
                        &str,
                        Option<&LoadedClientCertificate>,
                    ) = (
                        &source,
                        body_limit,
                        &[],
                        request,
                        cancel,
                        limiter,
                        http_auth,
                        auth_hostname,
                        client_certificate,
                    );
                    async move {
                        fetch_url_inner(
                            initial_url,
                            body_limit,
                            headers,
                            request,
                            cancel,
                            limiter,
                            None,
                            http_auth.map(|auth| (auth, auth_hostname)),
                            client_certificate,
                        )
                        .await
                    }
                })
                .await;
                (source, body_limit, fetched)
            });
        }
        let Some((source, body_limit, fetched)) = pending.next().await else {
            break;
        };
        reserved = reserved.saturating_sub(body_limit);
        remaining = remaining.saturating_sub(fetched.captured_bytes);
        let (report, response) = {
            let (source_url, fetched, catalog, catalog_error): (
                &str,
                Fetched,
                &[CatalogEntry],
                Option<&str>,
            ) = (&source, fetched, &catalog, catalog_error.as_deref());
            let inlined_result: (JavaScriptSource, Option<HttpObservation>) = {
                'inlined_analyze_source: {
                    let final_url = fetched.final_url.as_ref().map(Url::to_string);
                    let Some(response) = fetched.response else {
                        break 'inlined_analyze_source (
                            JavaScriptSource {
                                source_url: source_url.to_owned(),
                                final_url,
                                http_status: None,
                                http_reason: None,
                                captured_size: 0,
                                truncated: false,
                                sha256: None,
                                libraries: Vec::new(),
                                retrieval_error: fetched.error,
                                analysis_error: catalog_error.map(str::to_owned),
                            },
                            None,
                        );
                    };
                    let sha256 = format!("{:x}", Sha256::digest(&response.body));
                    let captured_size = response.body.len();
                    let truncated = response.body_truncated;
                    let status = response.status;
                    let reason = response.reason.clone();
                    let retrieval_error = fetched.error.or_else(|| {
                        (!(200..300).contains(&status)).then(|| format!("HTTP {status} {reason}"))
                    });
                    let libraries = if retrieval_error.is_none() {
                        {
                            let (final_url, source_url, body, truncated, catalog): (
                                Option<&Url>,
                                &str,
                                &[u8],
                                bool,
                                &[CatalogEntry],
                            ) = (
                                fetched.final_url.as_ref(),
                                source_url,
                                &response.body,
                                truncated,
                                catalog,
                            );
                            let inlined_result: Vec<JavaScriptLibrary> = {
                                let effective_url =
                                    final_url.map(Url::as_str).unwrap_or(source_url).to_owned();
                                let parsed_source = Url::parse(source_url).ok();
                                let parsed_effective =
                                    final_url.cloned().or_else(|| parsed_source.clone());
                                let mut uris = vec![source_url];
                                if effective_url != source_url {
                                    uris.push(&effective_url);
                                }
                                let filenames = parsed_source
                                    .iter()
                                    .chain(parsed_effective.iter())
                                    .filter_map(|url| url.path_segments()?.next_back())
                                    .collect::<HashSet<_>>();
                                let content = String::from_utf8_lossy(body);
                                let sha1 =
                                    (!truncated).then(|| format!("{:x}", Sha1::digest(body)));
                                let mut libraries = Vec::new();
                                for url in parsed_source.iter().chain(parsed_effective.iter()) {
                                    for library in {
                                        let (url,): (Option<&Url>,) = (Some(url),);
                                        let inlined_result: Vec<JavaScriptLibrary> = {
                                            'inlined_explicit_url_detection: {
                                                let Some(url) = url else {
                                                    break 'inlined_explicit_url_detection Vec::new(
                                                    );
                                                };
                                                let host = url
                                                    .host_str()
                                                    .unwrap_or_default()
                                                    .to_ascii_lowercase();
                                                let segments = url
                                                    .path_segments()
                                                    .map(|segments| segments.collect::<Vec<_>>())
                                                    .unwrap_or_default();
                                                let detected = match host.as_str() {
        "cdn.jsdelivr.net" if segments.first() == Some(&"npm") => ({
let (segments,): (& [& str],) = (&segments[1..],);
{
'inlined_package_spec: {

    let first = *match segments.first() { Some(value) => value, None => break 'inlined_package_spec None };
    if first.starts_with('@') {
        let second = *match segments.get(1) { Some(value) => value, None => break 'inlined_package_spec None };
        let (name, version) = {
let (value,): (& str,) = (second,);
let inlined_result: (String , Option < String >) = {

    value
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or_else(
            || (value.to_owned(), None),
            |(name, version)| (name.to_owned(), Some(version.to_owned())),
        )

};
inlined_result
};
        break 'inlined_package_spec Some((format!("{first}/{name}"), version));
    }
    let (name, version) = {
let (value,): (& str,) = (first,);
let inlined_result: (String , Option < String >) = {

    value
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or_else(
            || (value.to_owned(), None),
            |(name, version)| (name.to_owned(), Some(version.to_owned())),
        )

};
inlined_result
};
    (!name.is_empty()).then_some((name, version))

}
}

})
            .map(|(package, version)| (package, version, "jsDelivr npm URL".to_owned())),
        "unpkg.com" | "www.unpkg.com" => ({
let (segments,): (& [& str],) = (&segments,);
{
'inlined_package_spec: {

    let first = *match segments.first() { Some(value) => value, None => break 'inlined_package_spec None };
    if first.starts_with('@') {
        let second = *match segments.get(1) { Some(value) => value, None => break 'inlined_package_spec None };
        let (name, version) = {
let (value,): (& str,) = (second,);
let inlined_result: (String , Option < String >) = {

    value
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or_else(
            || (value.to_owned(), None),
            |(name, version)| (name.to_owned(), Some(version.to_owned())),
        )

};
inlined_result
};
        break 'inlined_package_spec Some((format!("{first}/{name}"), version));
    }
    let (name, version) = {
let (value,): (& str,) = (first,);
let inlined_result: (String , Option < String >) = {

    value
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or_else(
            || (value.to_owned(), None),
            |(name, version)| (name.to_owned(), Some(version.to_owned())),
        )

};
inlined_result
};
    (!name.is_empty()).then_some((name, version))

}
}

})
            .map(|(package, version)| (package, version, "unpkg URL".to_owned())),
        "esm.sh" | "www.esm.sh" => {
            let start = segments
                .iter()
                .position(|segment| !({
let (segment,): (& str,) = (segment,);
{

    segment.is_empty()
        || segment
            .strip_prefix('v')
            .is_some_and(|value| value.chars().all(|character| character.is_ascii_digit()))

}

}))
                .unwrap_or(segments.len());
            ({
let (segments,): (& [& str],) = (&segments[start..],);
{
'inlined_package_spec: {

    let first = *match segments.first() { Some(value) => value, None => break 'inlined_package_spec None };
    if first.starts_with('@') {
        let second = *match segments.get(1) { Some(value) => value, None => break 'inlined_package_spec None };
        let (name, version) = {
let (value,): (& str,) = (second,);
let inlined_result: (String , Option < String >) = {

    value
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or_else(
            || (value.to_owned(), None),
            |(name, version)| (name.to_owned(), Some(version.to_owned())),
        )

};
inlined_result
};
        break 'inlined_package_spec Some((format!("{first}/{name}"), version));
    }
    let (name, version) = {
let (value,): (& str,) = (first,);
let inlined_result: (String , Option < String >) = {

    value
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or_else(
            || (value.to_owned(), None),
            |(name, version)| (name.to_owned(), Some(version.to_owned())),
        )

};
inlined_result
};
    (!name.is_empty()).then_some((name, version))

}
}

})
                .map(|(package, version)| (package, version, "esm.sh URL".to_owned()))
        }
        "cdn.skypack.dev" => ({
let (segments,): (& [& str],) = (&segments,);
{
'inlined_package_spec: {

    let first = *match segments.first() { Some(value) => value, None => break 'inlined_package_spec None };
    if first.starts_with('@') {
        let second = *match segments.get(1) { Some(value) => value, None => break 'inlined_package_spec None };
        let (name, version) = {
let (value,): (& str,) = (second,);
let inlined_result: (String , Option < String >) = {

    value
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or_else(
            || (value.to_owned(), None),
            |(name, version)| (name.to_owned(), Some(version.to_owned())),
        )

};
inlined_result
};
        break 'inlined_package_spec Some((format!("{first}/{name}"), version));
    }
    let (name, version) = {
let (value,): (& str,) = (first,);
let inlined_result: (String , Option < String >) = {

    value
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or_else(
            || (value.to_owned(), None),
            |(name, version)| (name.to_owned(), Some(version.to_owned())),
        )

};
inlined_result
};
    (!name.is_empty()).then_some((name, version))

}
}

})
            .map(|(package, version)| (package, version, "Skypack URL".to_owned())),
        "cdnjs.cloudflare.com" if segments.get(0..2) == Some(&["ajax", "libs"]) => {
            segments.get(2).zip(segments.get(3)).map(|(name, version)| {
                (
                    (*name).to_owned(),
                    Some((*version).to_owned()),
                    "cdnjs URL".to_owned(),
                )
            })
        }
        "ajax.googleapis.com" if segments.get(0..2) == Some(&["ajax", "libs"]) => {
            segments.get(2).zip(segments.get(3)).map(|(name, version)| {
                (
                    (*name).to_owned(),
                    Some((*version).to_owned()),
                    "Google Hosted Libraries URL".to_owned(),
                )
            })
        }
        "code.jquery.com" => segments.last().and_then(|filename| {
            JQUERY_CDN_PATTERN.captures(filename).map(|captures| {
                (
                    "jquery".to_owned(),
                    captures.get(1).map(|version| version.as_str().to_owned()),
                    "jQuery CDN URL".to_owned(),
                )
            })
        }),
        _ => None,
    };
                                                detected
                                                    .map(|(name, version, evidence)| {
                                                        JavaScriptLibrary {
                                                            npm_package: matches!(
                                                                host.as_str(),
                                                                "cdn.jsdelivr.net"
                                                                    | "unpkg.com"
                                                                    | "www.unpkg.com"
                                                                    | "esm.sh"
                                                                    | "www.esm.sh"
                                                                    | "cdn.skypack.dev"
                                                                    | "code.jquery.com"
                                                            )
                                                            .then(|| name.clone()),
                                                            name,
                                                            installed_version: version,
                                                            latest_version: None,
                                                            status:
                                                                TechnologyVersionStatus::Unknown,
                                                            evidence: vec![evidence],
                                                            check_error: None,
                                                        }
                                                    })
                                                    .into_iter()
                                                    .collect()
                                            }
                                        };
                                        inlined_result
                                    } {
                                        ({
                                            let (libraries, incoming): (
                                                &mut Vec<JavaScriptLibrary>,
                                                JavaScriptLibrary,
                                            ) = (&mut libraries, library);

                                            let matching = libraries.iter_mut().find(|existing| {
                                                existing.installed_version
                                                    == incoming.installed_version
                                                    && match (
                                                        &existing.npm_package,
                                                        &incoming.npm_package,
                                                    ) {
                                                        (Some(left), Some(right)) => {
                                                            left.eq_ignore_ascii_case(right)
                                                        }
                                                        _ => existing
                                                            .name
                                                            .eq_ignore_ascii_case(&incoming.name),
                                                    }
                                            });
                                            if let Some(existing) = matching {
                                                if existing.npm_package.is_none() {
                                                    existing.npm_package = incoming.npm_package;
                                                }
                                                existing.evidence.extend(incoming.evidence);
                                                existing.evidence.sort();
                                                existing.evidence.dedup();
                                            } else {
                                                libraries.push(incoming);
                                            }
                                        });
                                    }
                                }

                                for entry in catalog {
                                    let mut matches = Vec::new();
                                    for regex in &entry.uri {
                                        for uri in &uris {
                                            if let Some(version) = {
                                                let (regex, text): (&Regex, &str) = (regex, uri);
                                                {
                                                    'inlined_regex_version: {
                                                        let version = match match regex
                                                            .captures(text)
                                                        {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_regex_version None;
                                                            }
                                                        }
                                                        .name("nancy_version")
                                                        {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_regex_version None;
                                                            }
                                                        }
                                                        .as_str()
                                                        .to_owned();
                                                        {
                                                            let (mut version,): (String,) =
                                                                (version,);
                                                            {
                                                                for suffix in [".min", "-min"] {
                                                                    if let Some(candidate) =
                                                                        version.strip_suffix(suffix)
                                                                        && Version::parse(
                                                                            candidate
                                                                                .trim_start_matches(
                                                                                    ['v', 'V'],
                                                                                ),
                                                                        )
                                                                        .is_ok()
                                                                    {
                                                                        version.truncate(
                                                                            candidate.len(),
                                                                        );
                                                                        break;
                                                                    }
                                                                }
                                                                ({
                                                                    let (version,): (&str,) =
                                                                        (&version,);
                                                                    {
                                                                        !version.is_empty()
        && version.starts_with(|character: char| character.is_ascii_digit())
        && version.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
                                                                    }
                                                                })
                                                                .then_some(version)
                                                            }
                                                        }
                                                    }
                                                }
                                            } {
                                                matches.push((
                                                    version,
                                                    "RetireJS URI extractor".to_owned(),
                                                ));
                                            }
                                        }
                                    }
                                    for regex in &entry.filename {
                                        for filename in &filenames {
                                            if let Some(version) = {
                                                let (regex, text): (&Regex, &str) =
                                                    (regex, filename);
                                                {
                                                    'inlined_regex_version: {
                                                        let version = match match regex
                                                            .captures(text)
                                                        {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_regex_version None;
                                                            }
                                                        }
                                                        .name("nancy_version")
                                                        {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_regex_version None;
                                                            }
                                                        }
                                                        .as_str()
                                                        .to_owned();
                                                        {
                                                            let (mut version,): (String,) =
                                                                (version,);
                                                            {
                                                                for suffix in [".min", "-min"] {
                                                                    if let Some(candidate) =
                                                                        version.strip_suffix(suffix)
                                                                        && Version::parse(
                                                                            candidate
                                                                                .trim_start_matches(
                                                                                    ['v', 'V'],
                                                                                ),
                                                                        )
                                                                        .is_ok()
                                                                    {
                                                                        version.truncate(
                                                                            candidate.len(),
                                                                        );
                                                                        break;
                                                                    }
                                                                }
                                                                ({
                                                                    let (version,): (&str,) =
                                                                        (&version,);
                                                                    {
                                                                        !version.is_empty()
        && version.starts_with(|character: char| character.is_ascii_digit())
        && version.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
                                                                    }
                                                                })
                                                                .then_some(version)
                                                            }
                                                        }
                                                    }
                                                }
                                            } {
                                                matches.push((
                                                    version,
                                                    "RetireJS filename extractor".to_owned(),
                                                ));
                                            }
                                        }
                                    }
                                    for regex in &entry.content {
                                        if let Some(version) = {
                                            let (regex, text): (&Regex, &str) = (regex, &content);
                                            {
                                                'inlined_regex_version: {
                                                    let version =
                                                        match match regex.captures(text) {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_regex_version None;
                                                            }
                                                        }
                                                        .name("nancy_version")
                                                        {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_regex_version None;
                                                            }
                                                        }
                                                        .as_str()
                                                        .to_owned();
                                                    {
                                                        let (mut version,): (String,) = (version,);
                                                        {
                                                            for suffix in [".min", "-min"] {
                                                                if let Some(candidate) =
                                                                    version.strip_suffix(suffix)
                                                                    && Version::parse(
                                                                        candidate
                                                                            .trim_start_matches([
                                                                                'v', 'V',
                                                                            ]),
                                                                    )
                                                                    .is_ok()
                                                                {
                                                                    version
                                                                        .truncate(candidate.len());
                                                                    break;
                                                                }
                                                            }
                                                            ({
                                                                let (version,): (&str,) =
                                                                    (&version,);
                                                                {
                                                                    !version.is_empty()
        && version.starts_with(|character: char| character.is_ascii_digit())
        && version.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
                                                                }
                                                            })
                                                            .then_some(version)
                                                        }
                                                    }
                                                }
                                            }
                                        } {
                                            matches.push((
                                                version,
                                                "RetireJS content extractor".to_owned(),
                                            ));
                                        }
                                    }
                                    for extractor in &entry.replacements {
                                        if let Some(captures) = extractor.regex.captures(&content) {
                                            let mut version = String::new();
                                            captures.expand(&extractor.replacement, &mut version);
                                            if let Some(version) =
                                                {
                                                    let (mut version,): (String,) = (version,);
                                                    {
                                                        for suffix in [".min", "-min"] {
                                                            if let Some(candidate) =
                                                                version.strip_suffix(suffix)
                                                                && Version::parse(
                                                                    candidate.trim_start_matches([
                                                                        'v', 'V',
                                                                    ]),
                                                                )
                                                                .is_ok()
                                                            {
                                                                version.truncate(candidate.len());
                                                                break;
                                                            }
                                                        }
                                                        ({
                                                            let (version,): (&str,) = (&version,);
                                                            {
                                                                !version.is_empty()
        && version.starts_with(|character: char| character.is_ascii_digit())
        && version.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
                                                            }
                                                        })
                                                        .then_some(version)
                                                    }
                                                }
                                            {
                                                matches.push((
                                                    version,
                                                    "RetireJS replacement extractor".to_owned(),
                                                ));
                                            }
                                        }
                                    }
                                    if let Some(version) = sha1
                                        .as_ref()
                                        .and_then(|hash| entry.hashes.get(hash))
                                        .cloned()
                                    {
                                        matches.push((
                                            version,
                                            "RetireJS SHA-1 hash extractor".to_owned(),
                                        ));
                                    }
                                    for (version, evidence) in matches {
                                        ({
                                            let (libraries, incoming): (
                                                &mut Vec<JavaScriptLibrary>,
                                                JavaScriptLibrary,
                                            ) = (
                                                &mut libraries,
                                                JavaScriptLibrary {
                                                    name: entry.name.clone(),
                                                    npm_package: entry.npm_package.clone(),
                                                    installed_version: Some(version),
                                                    latest_version: None,
                                                    status: TechnologyVersionStatus::Unknown,
                                                    evidence: vec![evidence],
                                                    check_error: None,
                                                },
                                            );

                                            let matching = libraries.iter_mut().find(|existing| {
                                                existing.installed_version
                                                    == incoming.installed_version
                                                    && match (
                                                        &existing.npm_package,
                                                        &incoming.npm_package,
                                                    ) {
                                                        (Some(left), Some(right)) => {
                                                            left.eq_ignore_ascii_case(right)
                                                        }
                                                        _ => existing
                                                            .name
                                                            .eq_ignore_ascii_case(&incoming.name),
                                                    }
                                            });
                                            if let Some(existing) = matching {
                                                if existing.npm_package.is_none() {
                                                    existing.npm_package = incoming.npm_package;
                                                }
                                                existing.evidence.extend(incoming.evidence);
                                                existing.evidence.sort();
                                                existing.evidence.dedup();
                                            } else {
                                                libraries.push(incoming);
                                            }
                                        });
                                    }
                                }
                                libraries.sort_by(|left, right| {
                                    left.name
                                        .cmp(&right.name)
                                        .then(left.installed_version.cmp(&right.installed_version))
                                });
                                libraries
                            };
                            inlined_result
                        }
                    } else {
                        Vec::new()
                    };
                    (
                        JavaScriptSource {
                            source_url: source_url.to_owned(),
                            final_url,
                            http_status: Some(status),
                            http_reason: Some(reason),
                            captured_size,
                            truncated,
                            sha256: Some(sha256),
                            libraries,
                            retrieval_error,
                            analysis_error: catalog_error.map(str::to_owned),
                        },
                        Some(response),
                    )
                }
            };
            inlined_result
        };
        if let Some(response) = response {
            capture_cache.insert(source.clone(), response);
        }
        source_cache.insert(source, report);
        completed_sources += 1;
        send_phase_progress(
            progress,
            ExposureScanPhase::JavaScriptAnalysis,
            ExposureScanPhaseState::Running,
            0.10 + 0.55 * completed_sources as f32 / allowed.len().max(1) as f32,
            format!(
                "Analyzed {completed_sources} / {} JavaScript sources",
                allowed.len()
            ),
        );
    }

    if cancel.is_cancelled() {
        let missing = allowed
            .iter()
            .filter(|source| !source_cache.contains_key(*source))
            .cloned()
            .collect::<Vec<_>>();
        for source in missing {
            source_cache.insert(source.clone(), {
                let (source, error): (&str, &str) = (&source, "JavaScript analysis cancelled");
                {
                    JavaScriptSource {
                        source_url: source.to_owned(),
                        final_url: None,
                        http_status: None,
                        http_reason: None,
                        captured_size: 0,
                        truncated: false,
                        sha256: None,
                        libraries: Vec::new(),
                        retrieval_error: Some(error.to_owned()),
                        analysis_error: None,
                    }
                }
            });
        }
    } else if next_source < allowed.len() {
        for source in &allowed[next_source..] {
            source_cache.insert(source.clone(), {
                let (source, error): (&str, &str) =
                    (source, "32 MiB JavaScript scan limit reached");
                {
                    JavaScriptSource {
                        source_url: source.to_owned(),
                        final_url: None,
                        http_status: None,
                        http_reason: None,
                        captured_size: 0,
                        truncated: false,
                        sha256: None,
                        libraries: Vec::new(),
                        retrieval_error: Some(error.to_owned()),
                        analysis_error: None,
                    }
                }
            });
        }
    }
    for source in &limited {
        source_cache.insert(source.clone(), {
            let (source, error): (&str, &str) =
                (source, "256-source JavaScript scan limit reached");
            {
                JavaScriptSource {
                    source_url: source.to_owned(),
                    final_url: None,
                    http_status: None,
                    http_reason: None,
                    captured_size: 0,
                    truncated: false,
                    sha256: None,
                    libraries: Vec::new(),
                    retrieval_error: Some(error.to_owned()),
                    analysis_error: None,
                }
            }
        });
    }
    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::JavaScriptAnalysis,
            ExposureScanPhaseState::Running,
            0.65,
            format!("Analyzed {} JavaScript sources", allowed.len()),
        );
    }
    ({
let (sources, request, cancel, limiter, enrichment, progress,): (_, & ExposureScanRequest, & CancellationToken, & ConnectionRateLimiter, & mut EnrichmentState, & Option < Sender < ExposureScanProgress > >,) = (source_cache.values_mut(), request, cancel, limiter, enrichment, progress,);
async move {

    enrichment.start();
    let mut sources = sources.collect::<Vec<_>>();
    let mut packages = HashMap::new();
    for source in &sources {
        for library in &source.libraries {
            if library.installed_version.is_some()
                && let Some(package) = &library.npm_package
            {
                packages
                    .entry(package.to_ascii_lowercase())
                    .or_insert_with(|| package.clone());
            }
        }
    }
    let mut requests = packages
        .into_iter()
        .map(|(key, package)| {
            let url = {
let (package,): (& str,) = (&package,);
{

    let package = package.to_ascii_lowercase();
    let encoded = utf8_percent_encode(&package, NON_ALPHANUMERIC).to_string();
    format!("https://registry.npmjs.org/{encoded}")

}

};
            (key, package, url)
        })
        .collect::<Vec<_>>();
    requests.sort_by(|left, right| left.0.cmp(&right.0));

    let mut results = HashMap::new();
    let mut uncached = Vec::new();
    for (key, package, url) in requests {
        if let Some(fetched) = enrichment.cached(&url) {
            results.insert(key, {
let (fetched,): (Fetched,) = (fetched,);
let inlined_result: NpmResult = {
'inlined_npm_result: {

    let Some(response) = fetched.response else {
        break 'inlined_npm_result NpmResult {
            latest: None,
            error: fetched
                .error
                .or_else(|| Some("npm returned no response".to_owned())),
        };
    };
    if let Some(error) = fetched.error {
        break 'inlined_npm_result NpmResult {
            latest: None,
            error: Some(error),
        };
    }
    if !(200..300).contains(&response.status) {
        break 'inlined_npm_result NpmResult {
            latest: None,
            error: Some(format!("npm returned HTTP {}", response.status)),
        };
    }
    if response.body_truncated {
        break 'inlined_npm_result NpmResult {
            latest: None,
            error: Some("npm metadata exceeded the remaining byte limit".to_owned()),
        };
    }
    match serde_json::from_slice::<serde_json::Value>(&response.body) {
        Ok(value) => NpmResult {
            latest: value
                .get("versions")
                .and_then(serde_json::Value::as_object)
                .into_iter()
                .flat_map(|versions| versions.keys())
                .filter_map(|version| Version::parse(version.trim_start_matches(['v', 'V'])).ok())
                .filter(|version| version.pre.is_empty())
                .max()
                .map(|version| version.to_string())
                .or_else(|| {
                    value
                        .get("dist-tags")
                        .and_then(|tags| tags.get("latest"))
                        .and_then(serde_json::Value::as_str)
                        .and_then(|version| Version::parse(version).ok())
                        .filter(|version| version.pre.is_empty())
                        .map(|version| version.to_string())
                }),
            error: None,
        },
        Err(error) => NpmResult {
            latest: None,
            error: Some(format!("invalid npm metadata: {error}")),
        },
    }

}
};
inlined_result
});
        } else {
            uncached.push((key, package, url));
        }
    }

    let metadata_total = results.len() + uncached.len();
    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::JavaScriptAnalysis,
            ExposureScanPhaseState::Running,
            0.65 + 0.25 * results.len() as f32 / metadata_total.max(1) as f32,
            format!(
                "Checked {} / {metadata_total} library metadata records",
                results.len()
            ),
        );
    }

    let context = enrichment.fetch_context();
    let mut pending = FuturesUnordered::new();
    let mut next = 0usize;
    let mut reserved = 0usize;
    while next < uncached.len() || !pending.is_empty() {
        while pending.len() < MAX_CONCURRENT_FETCHES && next < uncached.len() {
            if enrichment.stop_error(cancel).is_some() {
                break;
            }
            let available = (enrichment).remaining_bytes.saturating_sub(reserved);
            if available == 0 {
                break;
            }
            let body_limit = MAX_METADATA_BYTES.min(available);
            let (key, package, url) = uncached[next].clone();
            next += 1;
            if !cancel.is_cancelled() {
                send_phase_progress(
                    progress,
                    ExposureScanPhase::JavaScriptAnalysis,
                    ExposureScanPhaseState::Running,
                    0.65 + 0.25 * results.len() as f32 / metadata_total.max(1) as f32,
                    format!("Fetching metadata for {package}"),
                );
            }
            reserved += body_limit;
            let context = context.clone();
            pending.push(async move {
                let fetched = fetch_metadata_url(
                    &url,
                    body_limit,
                    &[("Accept", "application/vnd.npm.install-v1+json")],
                    request,
                    cancel,
                    limiter,
                    context,
                )
                .await;
                (key, package, url, body_limit, fetched)
            });
        }
        let Some((key, _package, url, body_limit, fetched)) = pending.next().await else {
            break;
        };
        reserved = reserved.saturating_sub(body_limit);
        ({
let (inlined_self, url, fetched,): (& mut EnrichmentState, String, Fetched,) = (&mut *(enrichment), url, fetched.clone(),);
'inlined_store: {

        if inlined_self.metadata.contains_key(&url) {
            break 'inlined_store;
        }
        inlined_self.remaining_bytes = inlined_self.remaining_bytes.saturating_sub(fetched.captured_bytes);
        inlined_self.metadata.insert(url, fetched);

}
});
        results.insert(key, {
let (fetched,): (Fetched,) = (fetched,);
let inlined_result: NpmResult = {
'inlined_npm_result: {

    let Some(response) = fetched.response else {
        break 'inlined_npm_result NpmResult {
            latest: None,
            error: fetched
                .error
                .or_else(|| Some("npm returned no response".to_owned())),
        };
    };
    if let Some(error) = fetched.error {
        break 'inlined_npm_result NpmResult {
            latest: None,
            error: Some(error),
        };
    }
    if !(200..300).contains(&response.status) {
        break 'inlined_npm_result NpmResult {
            latest: None,
            error: Some(format!("npm returned HTTP {}", response.status)),
        };
    }
    if response.body_truncated {
        break 'inlined_npm_result NpmResult {
            latest: None,
            error: Some("npm metadata exceeded the remaining byte limit".to_owned()),
        };
    }
    match serde_json::from_slice::<serde_json::Value>(&response.body) {
        Ok(value) => NpmResult {
            latest: value
                .get("versions")
                .and_then(serde_json::Value::as_object)
                .into_iter()
                .flat_map(|versions| versions.keys())
                .filter_map(|version| Version::parse(version.trim_start_matches(['v', 'V'])).ok())
                .filter(|version| version.pre.is_empty())
                .max()
                .map(|version| version.to_string())
                .or_else(|| {
                    value
                        .get("dist-tags")
                        .and_then(|tags| tags.get("latest"))
                        .and_then(serde_json::Value::as_str)
                        .and_then(|version| Version::parse(version).ok())
                        .filter(|version| version.pre.is_empty())
                        .map(|version| version.to_string())
                }),
            error: None,
        },
        Err(error) => NpmResult {
            latest: None,
            error: Some(format!("invalid npm metadata: {error}")),
        },
    }

}
};
inlined_result
});
        if !cancel.is_cancelled() {
            send_phase_progress(
                progress,
                ExposureScanPhase::JavaScriptAnalysis,
                ExposureScanPhaseState::Running,
                0.65 + 0.25 * results.len() as f32 / metadata_total.max(1) as f32,
                format!(
                    "Checked {} / {metadata_total} library metadata records",
                    results.len()
                ),
            );
        }
    }
    if next < uncached.len() {
        let error = enrichment
            .stop_error(cancel)
            .unwrap_or(METADATA_LIMIT_ERROR)
            .to_owned();
        for (key, _, _) in &uncached[next..] {
            results.insert(
                key.clone(),
                NpmResult {
                    latest: None,
                    error: Some(error.clone()),
                },
            );
        }
    }

    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::JavaScriptAnalysis,
            ExposureScanPhaseState::Running,
            0.90,
            format!("Checked {metadata_total} library metadata records"),
        );
    }

    for source in &mut sources {
        for library in &mut source.libraries {
            ({
let (library, results,): (& mut JavaScriptLibrary, & HashMap < String , NpmResult >,) = (library, &results,);
'inlined_apply_npm_result: {

    let Some(installed) = library.installed_version.as_deref() else {
        library.status = TechnologyVersionStatus::Unverifiable;
        library.check_error = Some("No exact installed version was detected".to_owned());
        break 'inlined_apply_npm_result;
    };
    let Some(package) = library.npm_package.clone() else {
        library.status = TechnologyVersionStatus::NotChecked;
        library.check_error = Some("No verified npm package mapping".to_owned());
        break 'inlined_apply_npm_result;
    };
    let Some(result) = results.get(&package.to_ascii_lowercase()).cloned() else {
        library.status = TechnologyVersionStatus::NotChecked;
        library.check_error = Some(METADATA_LIMIT_ERROR.to_owned());
        break 'inlined_apply_npm_result;
    };
    library.latest_version = result.latest.clone();
    if let Some(error) = result.error {
        library.status = TechnologyVersionStatus::NotChecked;
        library.check_error = Some(error);
        break 'inlined_apply_npm_result;
    }
    let Some(latest) = library.latest_version.as_deref() else {
        library.status = TechnologyVersionStatus::NotChecked;
        library.check_error = Some("npm metadata has no stable release".to_owned());
        break 'inlined_apply_npm_result;
    };
    library.status = {
let (installed, latest,): (& str, & str,) = (installed, latest,);
let inlined_result: TechnologyVersionStatus = {
'inlined_compare_versions: {

    let Ok(installed) = Version::parse(installed.trim_start_matches(['v', 'V'])) else {
        break 'inlined_compare_versions TechnologyVersionStatus::Unverifiable;
    };
    let Ok(latest) = Version::parse(latest.trim_start_matches(['v', 'V'])) else {
        break 'inlined_compare_versions TechnologyVersionStatus::Unverifiable;
    };
    if !installed.pre.is_empty() || !latest.pre.is_empty() {
        break 'inlined_compare_versions TechnologyVersionStatus::Prerelease;
    }
    match installed.cmp(&latest) {
        Ordering::Equal => TechnologyVersionStatus::Current,
        Ordering::Greater => TechnologyVersionStatus::NewerThanLatest,
        Ordering::Less if installed.major != latest.major => TechnologyVersionStatus::OutdatedMajor,
        Ordering::Less if installed.minor != latest.minor => TechnologyVersionStatus::OutdatedMinor,
        Ordering::Less => TechnologyVersionStatus::OutdatedPatch,
    }

}
};
inlined_result
};
    if library.status == TechnologyVersionStatus::Unverifiable {
        library.check_error =
            Some("Installed or latest version is not exact semantic versioning".to_owned());
    }

}
});
        }
    }

}
})
    .await;
    let mut captured_responses: Vec<CapturedScriptResponse> = Vec::new();
    let attachment_total = source_locations.len();
    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::JavaScriptAnalysis,
            ExposureScanPhaseState::Running,
            0.90,
            format!("Attaching 0 / {attachment_total} source results"),
        );
    }
    for (attachment_index, (endpoint_index, source)) in source_locations.into_iter().enumerate() {
        if let Some(report) = source_cache.get(&source) {
            endpoints[endpoint_index]
                .javascript_sources
                .push(report.clone());
        }
        if let Some(captured) = captured_responses
            .iter_mut()
            .find(|captured| captured.source_url == source)
        {
            captured.endpoint_indices.push(endpoint_index);
        } else if let Some(response) = capture_cache.remove(&source) {
            captured_responses.push(CapturedScriptResponse {
                endpoint_indices: vec![endpoint_index],
                source_url: source,
                response,
            });
        }
        if !cancel.is_cancelled() {
            let attached = attachment_index + 1;
            send_phase_progress(
                progress,
                ExposureScanPhase::JavaScriptAnalysis,
                ExposureScanPhaseState::Running,
                0.90 + 0.10 * attached as f32 / attachment_total.max(1) as f32,
                format!("Attached {attached} / {attachment_total} source results"),
            );
        }
    }
    for endpoint in endpoints.iter_mut() {
        endpoint
            .javascript_sources
            .sort_by(|left, right| left.source_url.cmp(&right.source_url));
    }
    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::JavaScriptAnalysis,
            ExposureScanPhaseState::Complete,
            1.0,
            format!("Analyzed {} JavaScript sources", allowed.len()),
        );
    }

    AnalysisReport {
        warnings,
        captured_responses,
    }
}

pub(super) async fn fetch_url(
    initial_url: &str,
    body_limit: usize,
    headers: &[(&str, &str)],
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
) -> Fetched {
    fetch_url_inner(
        initial_url,
        body_limit,
        headers,
        request,
        cancel,
        limiter,
        None,
        None,
        None,
    )
    .await
}

pub(super) async fn fetch_metadata_url(
    initial_url: &str,
    body_limit: usize,
    headers: &[(&str, &str)],
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
    context: MetadataFetchContext,
) -> Fetched {
    if Instant::now() >= context.deadline {
        return {
            let (initial_url, error): (&str, &str) = (initial_url, ENRICHMENT_DEADLINE_ERROR);
            {
                Fetched {
                    final_url: Url::parse(initial_url).ok(),
                    response: None,
                    error: Some(error.to_owned()),
                    captured_bytes: 0,
                }
            }
        };
    }
    tokio::select! {
            _ = cancel.cancelled() => {
    let (initial_url, error,): (& str, & str,) = (initial_url, ENRICHMENT_CANCELLED_ERROR,);
    let inlined_result: Fetched = {

        Fetched {
            final_url: Url::parse(initial_url).ok(),
            response: None,
            error: Some(error.to_owned()),
            captured_bytes: 0,
        }

    };
    inlined_result
    },
            _ = tokio::time::sleep_until(context.deadline) => {
                {
    let (initial_url, error,): (& str, & str,) = (initial_url, ENRICHMENT_DEADLINE_ERROR,);
    let inlined_result: Fetched = {

        Fetched {
            final_url: Url::parse(initial_url).ok(),
            response: None,
            error: Some(error.to_owned()),
            captured_bytes: 0,
        }

    };
    inlined_result
    }
            }
            fetched = fetch_url_inner(
                initial_url,
                body_limit,
                headers,
                request,
                cancel,
                limiter,
                Some(context.resolutions),
                None,
                None,
            ) => fetched,
        }
}

async fn fetch_url_inner(
    initial_url: &str,
    body_limit: usize,
    headers: &[(&str, &str)],
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
    resolutions: Option<ResolutionCache>,
    http_auth: Option<(&ResolvedAuth, &str)>,
    client_certificate: Option<&LoadedClientCertificate>,
) -> Fetched {
    let mut url = match Url::parse(initial_url) {
        Ok(mut url) => {
            url.set_fragment(None);
            url
        }
        Err(error) => {
            return Fetched {
                final_url: None,
                response: None,
                error: Some(format!("invalid URL: {error}")),
                captured_bytes: 0,
            };
        }
    };
    let mut last_response = None;
    let mut captured_bytes = 0usize;
    for redirect_count in 0..=3 {
        if cancel.is_cancelled() {
            return Fetched {
                final_url: Some(url),
                response: last_response,
                error: Some("Technology analysis cancelled".to_owned()),
                captured_bytes,
            };
        }
        if !matches!(url.scheme(), "http" | "https") {
            return Fetched {
                final_url: Some(url),
                response: last_response,
                error: Some("redirect destination is not HTTP(S)".to_owned()),
                captured_bytes,
            };
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Fetched {
                final_url: Some(url),
                response: last_response,
                error: Some("URL credentials are not permitted".to_owned()),
                captured_bytes,
            };
        }
        let Some(hostname) = url.host_str().map(str::to_owned) else {
            return Fetched {
                final_url: Some(url),
                response: last_response,
                error: Some("URL has no hostname".to_owned()),
                captured_bytes,
            };
        };
        let addresses = match ({
            let (hostname, cancel, cache): (&str, &CancellationToken, Option<&ResolutionCache>) =
                (&hostname, cancel, resolutions.as_ref());
            async move {
                let Some(cache) = cache else {
                    return ({
let (hostname, cancel,): (& str, & CancellationToken,) = (hostname, cancel,);
async move {

    let addresses = if let Ok(address) = hostname.parse::<IpAddr>() {
        vec![address]
    } else {
        let mut trace = DnsTrace::default();
        tokio::select! {
            _ = cancel.cancelled() => return Err("Technology analysis cancelled".to_owned()),
            result = resolve_host(hostname, &mut trace) => result?,
        }
        trace.addresses
    };
    if addresses.is_empty() {
        return Err(format!("{hostname} resolved to no addresses"));
    }
    if let Some((address, reason)) = addresses
        .iter()
        .find_map(|address| non_public_reason(*address).map(|reason| (*address, reason)))
    {
        return Err(format!(
            "rejected non-public destination {address} for {hostname}: {reason}"
        ));
    }
    let mut seen = HashSet::new();
    Ok(addresses
        .into_iter()
        .filter(|address| seen.insert(*address))
        .collect())

}
}).await;
                };
                let cell = {
                    let mut cache = cache.lock().await;
                    cache
                        .entry(hostname.to_ascii_lowercase())
                        .or_insert_with(|| Arc::new(OnceCell::new()))
                        .clone()
                };
                cell.get_or_init(|| {
let (hostname, cancel,): (& str, & CancellationToken,) = (hostname, cancel,);
async move {

    let addresses = if let Ok(address) = hostname.parse::<IpAddr>() {
        vec![address]
    } else {
        let mut trace = DnsTrace::default();
        tokio::select! {
            _ = cancel.cancelled() => return Err("Technology analysis cancelled".to_owned()),
            result = resolve_host(hostname, &mut trace) => result?,
        }
        trace.addresses
    };
    if addresses.is_empty() {
        return Err(format!("{hostname} resolved to no addresses"));
    }
    if let Some((address, reason)) = addresses
        .iter()
        .find_map(|address| non_public_reason(*address).map(|reason| (*address, reason)))
    {
        return Err(format!(
            "rejected non-public destination {address} for {hostname}: {reason}"
        ));
    }
    let mut seen = HashSet::new();
    Ok(addresses
        .into_iter()
        .filter(|address| seen.insert(*address))
        .collect())

}
})
        .await
        .clone()
            }
        })
        .await
        {
            Ok(addresses) => addresses,
            Err(error) => {
                return Fetched {
                    final_url: Some(url),
                    response: last_response,
                    error: Some(error),
                    captured_bytes,
                };
            }
        };
        let port = match url.port_or_known_default() {
            Some(port) => port,
            None => {
                return Fetched {
                    final_url: Some(url),
                    response: last_response,
                    error: Some("URL has no usable port".to_owned()),
                    captured_bytes,
                };
            }
        };
        let path = url_path(&url);
        let scan = ScanContext {
            hostname: &hostname,
            request,
            cancel,
            limiter,
            client_certificate: client_certificate
                .filter(|certificate| certificate.applies_to(&hostname)),
        };
        let mut response = None;
        let mut errors = Vec::new();
        let response_limit = body_limit.saturating_sub(captured_bytes);
        if response_limit == 0 {
            return Fetched {
                final_url: Some(url),
                response: last_response,
                error: Some("Response metadata byte limit reached during redirects".to_owned()),
                captured_bytes,
            };
        }
        let mut request_headers = headers.to_vec();
        if let Some((auth, auth_hostname)) = http_auth
            && hostname.eq_ignore_ascii_case(auth_hostname)
        {
            request_headers.push((auth.header_name, auth.header_value.as_str()));
        }
        for ip in addresses {
            let context = ProbeContext { ip, port, scan };
            match single_http_request(
                context,
                url.scheme(),
                "GET",
                &path,
                &request_headers,
                response_limit,
                None,
            )
            .await
            {
                Ok(observation) => {
                    response = Some(observation);
                    break;
                }
                Err(error) => errors.push(format!("{ip}: {error}")),
            }
        }
        let Some(mut response) = response else {
            return Fetched {
                final_url: Some(url),
                response: last_response,
                error: Some(errors.join("; ")),
                captured_bytes,
            };
        };
        captured_bytes = captured_bytes.saturating_add(response.body.len());
        response.url = url.to_string();
        let location = response.redirect_location.clone();
        last_response = Some(response);
        let Some(location) = location else {
            return Fetched {
                final_url: Some(url),
                response: last_response,
                error: None,
                captured_bytes,
            };
        };
        let next = match url.join(&location) {
            Ok(mut next) => {
                next.set_fragment(None);
                next
            }
            Err(error) => {
                return Fetched {
                    final_url: Some(url),
                    response: last_response,
                    error: Some(format!("invalid redirect: {error}")),
                    captured_bytes,
                };
            }
        };
        if redirect_count == 3 {
            return Fetched {
                final_url: Some(next),
                response: last_response,
                error: Some("redirect limit exceeded".to_owned()),
                captured_bytes,
            };
        }
        url = next;
    }
    unreachable!()
}

impl EnrichmentState {
    pub(super) fn store(&mut self, url: String, fetched: Fetched) {
        if self.metadata.contains_key(&url) {
            return;
        }
        self.remaining_bytes = self.remaining_bytes.saturating_sub(fetched.captured_bytes);
        self.metadata.insert(url, fetched);
    }
}
