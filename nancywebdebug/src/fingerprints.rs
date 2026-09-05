use super::javascript;
use super::technology::CapturedTechnologyResource;
use super::{
    Confidence, ConnectionRateLimiter, EndpointScan, ExposureScanPhase, ExposureScanPhaseState,
    ExposureScanProgress, ExposureScanRequest, HttpObservation, ProductDetection, ProductLayer,
    TechnologyFileType, WebTechnologyDetection, send_phase_progress,
};
use crate::persistence;
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::{
    BufferQueue, CharacterTokens, EndTag, StartTag, TagToken, Token, TokenSink, TokenSinkResult,
    Tokenizer,
};
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock, mpsc::Sender};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;
use url::Url;

pub(crate) const FINGERPRINTS_URL: &str =
    "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/main/fingerprints_data.json";
pub(crate) const CATEGORIES_URL: &str =
    "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/main/categories_data.json";
const CACHE_FILE: &str = "technology-fingerprints.json";
const CACHE_SCHEMA_VERSION: u32 = 1;
const MAX_FINGERPRINT_BYTES: usize = 8 * 1024 * 1024;
const MAX_CATEGORY_BYTES: usize = 256 * 1024;
const MAX_CACHE_BYTES: usize = MAX_FINGERPRINT_BYTES + MAX_CATEGORY_BYTES + 64 * 1024;
const MAX_PATTERN_BYTES: usize = 16 * 1024;
const REGEX_SIZE_LIMIT: usize = 512 * 1024;
const REGEX_SET_SIZE_LIMIT: usize = 16 * 1024 * 1024;
const REGEX_BATCH_SIZE: usize = 256;

#[derive(Clone)]
pub(crate) enum InitializationStatus {
    NotStarted,
    Pending,
    Ready {
        warning: Option<String>,
        using_curated_fallback: bool,
    },
}

#[derive(Clone)]
struct InitializationInfo {
    warning: Option<String>,
    using_curated_fallback: bool,
}

enum StateValue {
    NotStarted,
    Pending,
    Ready {
        catalog: Option<Arc<Catalog>>,
        info: InitializationInfo,
    },
}

struct SharedState {
    value: Mutex<StateValue>,
}

#[derive(Serialize, Deserialize)]
struct CacheEnvelope {
    schema_version: u32,
    retrieved_unix_seconds: u64,
    source_urls: SourceUrls,
    fingerprint_data: Value,
    category_definitions: Value,
}

#[derive(Serialize, Deserialize)]
struct SourceUrls {
    fingerprints: String,
    categories: String,
}

#[derive(Deserialize)]
struct RawFingerprints {
    apps: BTreeMap<String, RawFingerprint>,
}

#[derive(Default, Deserialize)]
struct RawFingerprint {
    #[serde(default)]
    cats: Vec<u32>,
    #[serde(default)]
    cookies: HashMap<String, String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    html: Vec<String>,
    #[serde(default, rename = "scriptSrc")]
    script_src: Vec<String>,
    #[serde(default, rename = "scripts")]
    scripts: Vec<String>,
    #[serde(default)]
    meta: HashMap<String, Vec<String>>,
    #[serde(default)]
    implies: Vec<String>,
}

#[derive(Deserialize)]
struct RawCategory {
    name: String,
}

struct Catalog {
    technologies: Vec<Technology>,
    lookup: HashMap<String, usize>,
    headers: HashMap<String, Vec<CompiledPattern>>,
    cookies: HashMap<String, Vec<CompiledPattern>>,
    meta: HashMap<String, Vec<CompiledPattern>>,
    html: MatcherBank,
    script_sources: MatcherBank,
    scripts: MatcherBank,
    warnings: Vec<String>,
}

struct Technology {
    name: String,
    categories: Vec<String>,
    implies: Vec<Implication>,
}

struct Implication {
    target: String,
    confidence: Option<u16>,
}

struct CompiledPattern {
    technology: usize,
    expression: String,
    regex: Option<Regex>,
    confidence: u16,
    version: Option<String>,
}

#[derive(Default)]
struct MatcherBank {
    always: Vec<CompiledPattern>,
    batches: Vec<MatcherBatch>,
}

struct MatcherBatch {
    set: RegexSet,
    patterns: Vec<CompiledPattern>,
}

#[derive(Default)]
struct CompileStats {
    incompatible: usize,
    oversized: usize,
}

#[derive(Clone)]
pub(super) struct CapturedScriptResponse {
    pub endpoint_indices: Vec<usize>,
    pub source_url: String,
    pub response: HttpObservation,
}

#[derive(Default)]
struct HtmlSignals {
    meta: Vec<(String, String)>,
    script_sources: Vec<String>,
    inline_scripts: Vec<String>,
}

#[derive(Default)]
struct HtmlState {
    signals: HtmlSignals,
    in_script: bool,
    script: String,
}

#[derive(Default)]
struct HtmlSink(RefCell<HtmlState>);

#[derive(Default)]
struct AccumulatedDetection {
    name: String,
    categories: BTreeSet<String>,
    version: Option<String>,
    version_confidence: u16,
    score: u16,
    confidence_floor: Confidence,
    signal_keys: HashSet<String>,
    evidence_urls: BTreeSet<String>,
    evidence: BTreeSet<String>,
}

struct MatchContext<'a> {
    key: &'a str,
    label: &'a str,
    url: &'a str,
}

impl TokenSink for HtmlSink {
    type Handle = ();

    fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
        let mut state = self.0.borrow_mut();
        match token {
            TagToken(tag) if tag.kind == StartTag => {
                let name = tag.name.as_ref().to_ascii_lowercase();
                let attribute = |wanted: &str| {
                    tag.attrs
                        .iter()
                        .find(|item| item.name.local.as_ref().eq_ignore_ascii_case(wanted))
                        .map(|item| item.value.to_string())
                };
                if name == "meta" {
                    if let (Some(name), Some(content)) = (attribute("name"), attribute("content")) {
                        state
                            .signals
                            .meta
                            .push((name.to_ascii_lowercase(), content));
                    }
                } else if name == "script" {
                    if let Some(source) = attribute("src").filter(|value| !value.trim().is_empty())
                    {
                        state.signals.script_sources.push(source);
                    } else {
                        state.in_script = true;
                        state.script.clear();
                    }
                }
                if tag.self_closing && name == "script" {
                    state.in_script = false;
                }
            }
            TagToken(tag)
                if tag.kind == EndTag && tag.name.as_ref().eq_ignore_ascii_case("script") =>
            {
                if state.in_script && !state.script.trim().is_empty() {
                    let script = std::mem::take(&mut state.script);
                    state.signals.inline_scripts.push(script);
                }
                state.in_script = false;
            }
            CharacterTokens(value) if state.in_script => {
                state.script.push_str(&value);
            }
            _ => {}
        }
        TokenSinkResult::Continue
    }
}

fn shared_state() -> &'static SharedState {
    static STATE: OnceLock<SharedState> = OnceLock::new();
    STATE.get_or_init(|| SharedState {
        value: Mutex::new(StateValue::NotStarted),
    })
}

pub(crate) fn initialization_status() -> InitializationStatus {
    let state = shared_state().value.lock().unwrap();
    match &*state {
        StateValue::NotStarted => InitializationStatus::NotStarted,
        StateValue::Pending => InitializationStatus::Pending,
        StateValue::Ready { info, .. } => InitializationStatus::Ready {
            warning: info.warning.clone(),
            using_curated_fallback: info.using_curated_fallback,
        },
    }
}

pub(crate) fn start_initialization(force: bool) -> bool {
    let mut state = shared_state().value.lock().unwrap();
    match &*state {
        StateValue::Pending => false,
        StateValue::Ready { .. } if !force => false,
        _ => {
            *state = StateValue::Pending;
            true
        }
    }
}

pub(crate) async fn run_started_initialization() {
    let result = refresh_catalog().await;
    complete_initialization(result);
}

pub(crate) fn complete_runtime_failure(error: String) {
    complete_initialization(cached_or_fallback(error));
}

pub(crate) async fn ensure_initialized() {
    loop {
        match initialization_status() {
            InitializationStatus::Ready { .. } => return,
            InitializationStatus::NotStarted => {
                if start_initialization(false) {
                    run_started_initialization().await;
                    return;
                }
            }
            InitializationStatus::Pending => {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await
            }
        }
    }
}

async fn refresh_catalog() -> Result<(Arc<Catalog>, InitializationInfo), InitializationInfo> {
    let request = ExposureScanRequest::default();
    let cancel = CancellationToken::new();
    let limiter = ConnectionRateLimiter::new(20);
    let (fingerprints, categories) = tokio::join!(
        fetch_document(
            FINGERPRINTS_URL,
            MAX_FINGERPRINT_BYTES,
            &request,
            &cancel,
            &limiter
        ),
        fetch_document(
            CATEGORIES_URL,
            MAX_CATEGORY_BYTES,
            &request,
            &cancel,
            &limiter
        )
    );
    let remote = fingerprints.and_then(|fingerprint_data| {
        categories.map(|category_definitions| CacheEnvelope {
            schema_version: CACHE_SCHEMA_VERSION,
            retrieved_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            source_urls: SourceUrls {
                fingerprints: FINGERPRINTS_URL.to_owned(),
                categories: CATEGORIES_URL.to_owned(),
            },
            fingerprint_data,
            category_definitions,
        })
    });
    match remote.and_then(|envelope| {
        let catalog = compile_envelope(&envelope)?;
        Ok((envelope, catalog))
    }) {
        Ok((envelope, catalog)) => {
            let warning =
                persistence::write_json_with_backup(CACHE_FILE, &envelope, MAX_CACHE_BYTES)
                    .err()
                    .map(|error| {
                        format!("Web technology catalog cache could not be updated: {error}")
                    });
            Ok((
                Arc::new(catalog),
                InitializationInfo {
                    warning,
                    using_curated_fallback: false,
                },
            ))
        }
        Err(error) => cached_or_fallback(error),
    }
}

async fn fetch_document(
    url: &str,
    limit: usize,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
) -> Result<Value, String> {
    let fetched = javascript::fetch_url(
        url,
        limit,
        &[("Accept", "application/json")],
        request,
        cancel,
        limiter,
    )
    .await;
    if let Some(error) = fetched.error {
        return Err(format!("{url}: {error}"));
    }
    let response = fetched
        .response
        .ok_or_else(|| format!("{url}: no response"))?;
    if !(200..300).contains(&response.status) {
        return Err(format!("{url}: HTTP {}", response.status));
    }
    if response.body_truncated {
        return Err(format!("{url}: response exceeded {limit} bytes"));
    }
    serde_json::from_slice(&response.body).map_err(|error| format!("{url}: invalid JSON: {error}"))
}

fn cached_or_fallback(
    remote_error: String,
) -> Result<(Arc<Catalog>, InitializationInfo), InitializationInfo> {
    match load_cached_catalog() {
        Ok((catalog, used_backup)) => Ok((
            Arc::new(catalog),
            InitializationInfo {
                warning: Some(format!(
                    "Web technology catalog refresh failed; using the last valid {}cache: {remote_error}",
                    if used_backup { "backup " } else { "" }
                )),
                using_curated_fallback: false,
            },
        )),
        Err(cache_error) => Err(InitializationInfo {
            warning: Some(format!(
                "Web technology catalog unavailable; using curated fingerprints: {remote_error}; {cache_error}"
            )),
            using_curated_fallback: true,
        }),
    }
}

fn load_cached_catalog() -> Result<(Catalog, bool), String> {
    let (envelope, used_backup) = persistence::read_json_with_backup(
        CACHE_FILE,
        MAX_CACHE_BYTES,
        |envelope: &CacheEnvelope| compile_envelope(envelope).map(|_| ()),
    )?;
    Ok((compile_envelope(&envelope)?, used_backup))
}

fn complete_initialization(result: Result<(Arc<Catalog>, InitializationInfo), InitializationInfo>) {
    let (catalog, info) = match result {
        Ok((catalog, info)) => (Some(catalog), info),
        Err(info) => (None, info),
    };
    *shared_state().value.lock().unwrap() = StateValue::Ready { catalog, info };
}

fn validate_envelope(envelope: &CacheEnvelope) -> Result<(), String> {
    if envelope.schema_version != CACHE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported fingerprint cache schema {}",
            envelope.schema_version
        ));
    }
    if envelope.retrieved_unix_seconds == 0 {
        return Err("fingerprint cache retrieval timestamp is missing".to_owned());
    }
    if envelope.source_urls.fingerprints.is_empty() || envelope.source_urls.categories.is_empty() {
        return Err("fingerprint cache source URLs are missing".to_owned());
    }
    let fingerprint_bytes = serde_json::to_vec(&envelope.fingerprint_data)
        .map_err(|error| format!("invalid cached fingerprint data: {error}"))?
        .len();
    if fingerprint_bytes > MAX_FINGERPRINT_BYTES {
        return Err("cached fingerprint data exceeds the 8 MiB limit".to_owned());
    }
    let category_bytes = serde_json::to_vec(&envelope.category_definitions)
        .map_err(|error| format!("invalid cached category definitions: {error}"))?
        .len();
    if category_bytes > MAX_CATEGORY_BYTES {
        return Err("cached category definitions exceed the 256 KiB limit".to_owned());
    }
    Ok(())
}

fn compile_envelope(envelope: &CacheEnvelope) -> Result<Catalog, String> {
    validate_envelope(envelope)?;
    let raw: RawFingerprints = serde_json::from_value(envelope.fingerprint_data.clone())
        .map_err(|error| format!("invalid fingerprint data: {error}"))?;
    let raw_categories: BTreeMap<String, RawCategory> =
        serde_json::from_value(envelope.category_definitions.clone())
            .map_err(|error| format!("invalid category definitions: {error}"))?;
    if raw.apps.is_empty() || raw_categories.is_empty() {
        return Err("fingerprint catalog is empty".to_owned());
    }
    let categories = raw_categories
        .into_iter()
        .filter_map(|(id, category)| id.parse::<u32>().ok().map(|id| (id, category.name)))
        .collect::<HashMap<_, _>>();
    if categories.is_empty() {
        return Err("fingerprint category definitions contain no numeric IDs".to_owned());
    }
    compile_catalog(raw, &categories)
}

fn compile_catalog(
    raw: RawFingerprints,
    categories: &HashMap<u32, String>,
) -> Result<Catalog, String> {
    let mut stats = CompileStats::default();
    let mut technologies = Vec::with_capacity(raw.apps.len());
    let mut sources = Vec::with_capacity(raw.apps.len());
    for (name, fingerprint) in raw.apps {
        let technology_categories = fingerprint
            .cats
            .iter()
            .filter_map(|id| categories.get(id).cloned())
            .collect::<Vec<_>>();
        let implies = fingerprint
            .implies
            .iter()
            .filter_map(|value| parse_implication(value))
            .collect();
        technologies.push(Technology {
            name,
            categories: technology_categories,
            implies,
        });
        sources.push(fingerprint);
    }
    let lookup = technologies
        .iter()
        .enumerate()
        .map(|(index, technology)| (technology.name.to_ascii_lowercase(), index))
        .collect::<HashMap<_, _>>();
    let mut headers = HashMap::<String, Vec<CompiledPattern>>::new();
    let mut cookies = HashMap::<String, Vec<CompiledPattern>>::new();
    let mut meta = HashMap::<String, Vec<CompiledPattern>>::new();
    let mut html = Vec::new();
    let mut script_sources = Vec::new();
    let mut scripts = Vec::new();
    for (technology, fingerprint) in sources.into_iter().enumerate() {
        for (name, pattern) in fingerprint.headers {
            if let Some(pattern) = compile_pattern(technology, &pattern, &mut stats) {
                headers
                    .entry(name.to_ascii_lowercase())
                    .or_default()
                    .push(pattern);
            }
        }
        for (name, pattern) in fingerprint.cookies {
            if let Some(pattern) = compile_pattern(technology, &pattern, &mut stats) {
                cookies
                    .entry(name.to_ascii_lowercase())
                    .or_default()
                    .push(pattern);
            }
        }
        for (name, patterns) in fingerprint.meta {
            for pattern in patterns {
                if let Some(pattern) = compile_pattern(technology, &pattern, &mut stats) {
                    meta.entry(name.to_ascii_lowercase())
                        .or_default()
                        .push(pattern);
                }
            }
        }
        for pattern in fingerprint.html {
            if let Some(pattern) = compile_pattern(technology, &pattern, &mut stats) {
                html.push(pattern);
            }
        }
        for pattern in fingerprint.script_src {
            if let Some(pattern) = compile_pattern(technology, &pattern, &mut stats) {
                script_sources.push(pattern);
            }
        }
        for pattern in fingerprint.scripts {
            if let Some(pattern) = compile_pattern(technology, &pattern, &mut stats) {
                scripts.push(pattern);
            }
        }
    }
    let html = MatcherBank::compile(html, &mut stats);
    let script_sources = MatcherBank::compile(script_sources, &mut stats);
    let scripts = MatcherBank::compile(scripts, &mut stats);
    let mut warnings = Vec::new();
    if stats.incompatible > 0 || stats.oversized > 0 {
        warnings.push(format!(
            "Web technology catalog skipped {} incompatible and {} oversized passive pattern(s)",
            stats.incompatible, stats.oversized
        ));
    }
    Ok(Catalog {
        technologies,
        lookup,
        headers,
        cookies,
        meta,
        html,
        script_sources,
        scripts,
        warnings,
    })
}

fn compile_pattern(
    technology: usize,
    source: &str,
    stats: &mut CompileStats,
) -> Option<CompiledPattern> {
    let mut parts = source.split("\\;");
    let expression = parts.next().unwrap_or_default().to_owned();
    let mut confidence = 100u16;
    let mut version = None;
    for tag in parts {
        if let Some(value) = tag.strip_prefix("confidence:") {
            confidence = value.parse::<u16>().unwrap_or(100).clamp(1, 100);
        } else if let Some(value) = tag.strip_prefix("version:") {
            version = Some(value.to_owned());
        }
    }
    if expression.len() > MAX_PATTERN_BYTES {
        stats.oversized += 1;
        return None;
    }
    let regex = if expression.is_empty() {
        None
    } else {
        match RegexBuilder::new(&expression)
            .case_insensitive(true)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
        {
            Ok(regex) => Some(regex),
            Err(_) => {
                stats.incompatible += 1;
                return None;
            }
        }
    };
    Some(CompiledPattern {
        technology,
        expression,
        regex,
        confidence,
        version,
    })
}

fn parse_implication(source: &str) -> Option<Implication> {
    let mut parts = source.split("\\;");
    let target = parts.next()?.trim().to_ascii_lowercase();
    if target.is_empty() {
        return None;
    }
    let confidence = parts.find_map(|tag| {
        tag.strip_prefix("confidence:")
            .and_then(|value| value.parse::<u16>().ok())
            .map(|value| value.clamp(1, 100))
    });
    Some(Implication { target, confidence })
}

impl MatcherBank {
    fn compile(patterns: Vec<CompiledPattern>, stats: &mut CompileStats) -> Self {
        let mut bank = Self::default();
        let mut regular = Vec::new();
        for pattern in patterns {
            if pattern.regex.is_none() {
                bank.always.push(pattern);
            } else {
                regular.push(pattern);
            }
        }
        while !regular.is_empty() {
            let count = REGEX_BATCH_SIZE.min(regular.len());
            let batch = regular.drain(..count).collect::<Vec<_>>();
            compile_batch(batch, &mut bank.batches, stats);
        }
        bank
    }

    fn visit_matches(&self, text: &str, mut visit: impl FnMut(&CompiledPattern, Option<String>)) {
        for pattern in &self.always {
            visit(pattern, None);
        }
        for batch in &self.batches {
            for index in batch.set.matches(text).into_iter() {
                let pattern = &batch.patterns[index];
                visit(pattern, pattern_version(pattern, text));
            }
        }
    }
}

fn compile_batch(
    patterns: Vec<CompiledPattern>,
    batches: &mut Vec<MatcherBatch>,
    stats: &mut CompileStats,
) {
    let expressions = patterns
        .iter()
        .map(|pattern| pattern.expression.as_str())
        .collect::<Vec<_>>();
    match RegexSetBuilder::new(expressions)
        .case_insensitive(true)
        .size_limit(REGEX_SET_SIZE_LIMIT)
        .build()
    {
        Ok(set) => batches.push(MatcherBatch { set, patterns }),
        Err(_) if patterns.len() > 1 => {
            let mut left = patterns;
            let right = left.split_off(left.len() / 2);
            compile_batch(left, batches, stats);
            compile_batch(right, batches, stats);
        }
        Err(_) => stats.incompatible += 1,
    }
}

fn pattern_version(pattern: &CompiledPattern, text: &str) -> Option<String> {
    let template = pattern.version.as_deref()?;
    let captures = pattern.regex.as_ref()?.captures(text)?;
    let mut result = template.to_owned();
    for index in 1..captures.len() {
        let marker = format!("\\{index}");
        let value = captures.get(index).map_or("", |capture| capture.as_str());
        let conditional = format!("{marker}?");
        while let Some(start) = result.find(&conditional) {
            let branch_start = start + conditional.len();
            let end = result[branch_start..]
                .find("\\;")
                .map(|offset| branch_start + offset)
                .unwrap_or(result.len());
            let branch = &result[branch_start..end];
            let (when_present, when_missing) = branch.split_once(':').unwrap_or((branch, ""));
            let replacement = if value.is_empty() {
                when_missing
            } else {
                when_present
            }
            .to_owned();
            result.replace_range(start..end, &replacement);
        }
        result = result.replace(&marker, value);
    }
    let result = result.trim().trim_start_matches(['v', 'V']).to_owned();
    (!result.is_empty()).then_some(result)
}

fn match_single_pattern(pattern: &CompiledPattern, text: &str) -> Option<Option<String>> {
    match &pattern.regex {
        None => Some(None),
        Some(regex) if regex.is_match(text) => Some(pattern_version(pattern, text)),
        Some(_) => None,
    }
}

pub(super) fn detect(
    endpoints: &mut [EndpointScan],
    resources: &[CapturedTechnologyResource],
    scripts: &[CapturedScriptResponse],
    cancel: &CancellationToken,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> Vec<String> {
    let response_total = endpoints
        .iter()
        .map(|endpoint| endpoint.http.len())
        .sum::<usize>();
    let script_total = scripts
        .iter()
        .map(|script| script.endpoint_indices.len())
        .sum::<usize>();
    let work_total = response_total + resources.len() + script_total + endpoints.len();
    let mut completed = 0usize;
    send_phase_progress(
        progress,
        ExposureScanPhase::Fingerprinting,
        ExposureScanPhaseState::Running,
        0.0,
        format!("Scanning {response_total} HTTP responses"),
    );
    let (catalog, info) = {
        let state = shared_state().value.lock().unwrap();
        match &*state {
            StateValue::Ready { catalog, info } => (catalog.clone(), info.clone()),
            _ => (
                None,
                InitializationInfo {
                    warning: Some(
                        "Web technology catalog initialization did not complete".to_owned(),
                    ),
                    using_curated_fallback: true,
                },
            ),
        }
    };
    let mut warnings = info.warning.into_iter().collect::<Vec<_>>();
    let mut accumulated = endpoints
        .iter()
        .map(seed_curated_detections)
        .collect::<Vec<_>>();
    if let Some(catalog) = &catalog {
        warnings.extend(catalog.warnings.iter().cloned());
    }
    for (index, endpoint) in endpoints.iter().enumerate() {
        for response in &endpoint.http {
            if cancel.is_cancelled() {
                break;
            }
            if let Some(catalog) = &catalog {
                catalog.scan_response(
                    &mut accumulated[index],
                    &response.url,
                    response.status,
                    &response.headers,
                    &response.body,
                    None,
                );
            }
            completed += 1;
            send_fingerprint_progress(
                progress,
                completed,
                work_total,
                format!("HTTP response: {}", sanitize_url(&response.url)),
            );
        }
        if cancel.is_cancelled() {
            break;
        }
    }
    if !cancel.is_cancelled() {
        for resource in resources {
            if cancel.is_cancelled() {
                break;
            }
            if let (Some(catalog), Some(index)) = (
                catalog.as_ref(),
                endpoints.iter().position(|endpoint| {
                    endpoint.ip == resource.ip && endpoint.port == resource.port
                }),
            ) {
                let script = resource.detected_file_types.iter().any(|item| {
                    matches!(
                        item.file_type,
                        TechnologyFileType::JavaScript
                            | TechnologyFileType::Jsx
                            | TechnologyFileType::TypeScript
                            | TechnologyFileType::Tsx
                    )
                });
                catalog.scan_response(
                    &mut accumulated[index],
                    &resource.url,
                    200,
                    &resource.headers,
                    &resource.body,
                    Some(script),
                );
            }
            completed += 1;
            send_fingerprint_progress(
                progress,
                completed,
                work_total,
                format!("Resource: {}", sanitize_url(&resource.url)),
            );
        }
    }
    if !cancel.is_cancelled() {
        'scripts: for script in scripts {
            for &endpoint_index in &script.endpoint_indices {
                if cancel.is_cancelled() {
                    break 'scripts;
                }
                if let (Some(catalog), Some(target)) =
                    (catalog.as_ref(), accumulated.get_mut(endpoint_index))
                {
                    catalog.scan_external_script(target, &script.source_url, &script.response);
                }
                completed += 1;
                send_fingerprint_progress(
                    progress,
                    completed,
                    work_total,
                    format!("Script: {}", sanitize_url(&script.source_url)),
                );
            }
        }
    }
    if !cancel.is_cancelled() {
        for (endpoint, detections) in endpoints.iter_mut().zip(accumulated) {
            if cancel.is_cancelled() {
                break;
            }
            let mut detections = detections
                .into_values()
                .map(finalize_detection)
                .collect::<Vec<_>>();
            detections.sort_by(|left, right| {
                left.name
                    .to_ascii_lowercase()
                    .cmp(&right.name.to_ascii_lowercase())
            });
            promote_detections(&mut endpoint.products, &detections);
            endpoint.web_technologies = detections;
            completed += 1;
            send_fingerprint_progress(
                progress,
                completed,
                work_total,
                format!("Finalized {}:{}", endpoint.ip, endpoint.port),
            );
        }
    }
    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::Fingerprinting,
            ExposureScanPhaseState::Complete,
            1.0,
            format!("Processed {work_total} fingerprint inputs"),
        );
    }
    warnings.sort();
    warnings.dedup();
    warnings
}

fn send_fingerprint_progress(
    progress: &Option<Sender<ExposureScanProgress>>,
    completed: usize,
    total: usize,
    text: String,
) {
    send_phase_progress(
        progress,
        ExposureScanPhase::Fingerprinting,
        ExposureScanPhaseState::Running,
        completed as f32 / total.max(1) as f32,
        text,
    );
}

fn seed_curated_detections(endpoint: &EndpointScan) -> HashMap<String, AccumulatedDetection> {
    let mut detections = HashMap::<String, AccumulatedDetection>::new();
    for product in &endpoint.products {
        let key = product.name.to_ascii_lowercase();
        let detection = detections.entry(key).or_default();
        detection.name = product.name.clone();
        detection.categories.insert(product.layer.to_string());
        detection.confidence_floor = detection.confidence_floor.max(product.confidence);
        if product.version.is_some()
            && (detection.version.is_none()
                || confidence_score(product.confidence) >= detection.version_confidence)
        {
            detection.version = product.version.clone();
            detection.version_confidence = confidence_score(product.confidence);
        }
        detection.evidence.extend(product.evidence.iter().cloned());
    }
    detections
}

impl Catalog {
    fn scan_response(
        &self,
        detections: &mut HashMap<String, AccumulatedDetection>,
        response_url: &str,
        status: u16,
        response_headers: &[(String, String)],
        body: &[u8],
        script_override: Option<bool>,
    ) {
        let url = sanitize_url(response_url);
        let mut headers = HashMap::<String, Vec<&str>>::new();
        for (name, value) in response_headers {
            headers
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(value);
        }
        for (name, values) in &headers {
            let combined = values.join(", ");
            if let Some(patterns) = self.headers.get(name) {
                for pattern in patterns {
                    if let Some(version) = match_single_pattern(pattern, &combined) {
                        let key = format!("header:{name}:{url}");
                        let label = format!("header {name}");
                        self.add_match(
                            detections,
                            pattern,
                            version,
                            MatchContext {
                                key: &key,
                                label: &label,
                                url: &url,
                            },
                        );
                    }
                }
            }
        }
        for value in headers.get("set-cookie").into_iter().flatten() {
            if let Some((name, cookie_value)) = cookie_name_value(value)
                && let Some(patterns) = self.cookies.get(&name)
            {
                for pattern in patterns {
                    if let Some(version) = match_single_pattern(pattern, cookie_value) {
                        let key = format!("cookie:{name}:{url}");
                        let label = format!("cookie {name}");
                        self.add_match(
                            detections,
                            pattern,
                            version,
                            MatchContext {
                                key: &key,
                                label: &label,
                                url: &url,
                            },
                        );
                    }
                }
            }
        }
        let text = String::from_utf8_lossy(body);
        let is_script =
            script_override.unwrap_or_else(|| response_is_script(response_url, response_headers));
        if is_script {
            if (200..300).contains(&status) {
                let key = format!("script-content:{url}");
                self.scripts.visit_matches(&text, |pattern, version| {
                    self.add_match(
                        detections,
                        pattern,
                        version,
                        MatchContext {
                            key: &key,
                            label: "external script content",
                            url: &url,
                        },
                    );
                });
            }
            let key = format!("script-url:{url}");
            self.script_sources.visit_matches(&url, |pattern, version| {
                self.add_match(
                    detections,
                    pattern,
                    version,
                    MatchContext {
                        key: &key,
                        label: "script URL",
                        url: &url,
                    },
                );
            });
            return;
        }
        let html_key = format!("html:{url}");
        self.html.visit_matches(&text, |pattern, version| {
            self.add_match(
                detections,
                pattern,
                version,
                MatchContext {
                    key: &html_key,
                    label: "HTML signature",
                    url: &url,
                },
            );
        });
        let signals = parse_html(&text);
        for (name, content) in signals.meta {
            if let Some(patterns) = self.meta.get(&name) {
                for pattern in patterns {
                    if let Some(version) = match_single_pattern(pattern, &content) {
                        let key = format!("meta:{name}:{url}");
                        let label = format!("meta {name}");
                        self.add_match(
                            detections,
                            pattern,
                            version,
                            MatchContext {
                                key: &key,
                                label: &label,
                                url: &url,
                            },
                        );
                    }
                }
            }
        }
        for source in signals.script_sources {
            let source = resolve_script_url(response_url, &source);
            let key = format!("script-url:{source}");
            self.script_sources
                .visit_matches(&source, |pattern, version| {
                    self.add_match(
                        detections,
                        pattern,
                        version,
                        MatchContext {
                            key: &key,
                            label: "script URL",
                            url: &source,
                        },
                    );
                });
        }
        for (index, script) in signals.inline_scripts.into_iter().enumerate() {
            let key = format!("inline-script:{url}:{index}");
            self.scripts.visit_matches(&script, |pattern, version| {
                self.add_match(
                    detections,
                    pattern,
                    version,
                    MatchContext {
                        key: &key,
                        label: "inline script content",
                        url: &url,
                    },
                );
            });
        }
    }

    fn scan_external_script(
        &self,
        detections: &mut HashMap<String, AccumulatedDetection>,
        source_url: &str,
        response: &HttpObservation,
    ) {
        let source = sanitize_url(source_url);
        let response_url = sanitize_url(&response.url);
        self.scan_response(
            detections,
            &response.url,
            response.status,
            &response.headers,
            &response.body,
            Some(true),
        );
        if source != response_url {
            let key = format!("script-url:{source}");
            self.script_sources
                .visit_matches(&source, |pattern, version| {
                    self.add_match(
                        detections,
                        pattern,
                        version,
                        MatchContext {
                            key: &key,
                            label: "script URL",
                            url: &source,
                        },
                    );
                });
        }
    }

    fn add_match(
        &self,
        detections: &mut HashMap<String, AccumulatedDetection>,
        pattern: &CompiledPattern,
        version: Option<String>,
        context: MatchContext<'_>,
    ) {
        let mut path = HashSet::new();
        self.add_recursive(
            detections,
            pattern.technology,
            pattern.confidence,
            version,
            &context,
            &mut path,
            None,
        );
    }

    fn add_recursive(
        &self,
        detections: &mut HashMap<String, AccumulatedDetection>,
        technology_index: usize,
        confidence: u16,
        version: Option<String>,
        context: &MatchContext<'_>,
        path: &mut HashSet<usize>,
        implied_by: Option<&str>,
    ) {
        if !path.insert(technology_index) {
            return;
        }
        let technology = &self.technologies[technology_index];
        let identity = technology.name.to_ascii_lowercase();
        let key = implied_by.map_or_else(
            || context.key.to_owned(),
            |parent| format!("{}:implied:{parent}>{identity}", context.key),
        );
        let detection = detections.entry(identity.clone()).or_default();
        detection.name = technology.name.clone();
        detection
            .categories
            .extend(technology.categories.iter().cloned());
        if detection.signal_keys.insert(key) {
            detection.score = detection.score.saturating_add(confidence).min(100);
        }
        if let Some(version) = version.filter(|value| !value.is_empty())
            && (detection.version.is_none()
                || confidence > detection.version_confidence
                || (confidence == detection.version_confidence
                    && version.len() > detection.version.as_deref().map_or(0, str::len)))
        {
            detection.version = Some(version);
            detection.version_confidence = confidence;
        }
        detection.evidence_urls.insert(context.url.to_owned());
        detection.evidence.insert(match implied_by {
            Some(parent) => format!(
                "implied by {parent} from {} at {}",
                context.label, context.url
            ),
            None => format!("{} at {}", context.label, context.url),
        });
        for implication in &technology.implies {
            if let Some(target) = self.lookup.get(&implication.target).copied() {
                let implied_confidence =
                    implication.confidence.unwrap_or(confidence).min(confidence);
                self.add_recursive(
                    detections,
                    target,
                    implied_confidence,
                    None,
                    context,
                    path,
                    Some(&technology.name),
                );
            }
        }
        path.remove(&technology_index);
    }
}

fn parse_html(text: &str) -> HtmlSignals {
    let input = BufferQueue::default();
    input.push_back(StrTendril::from(text));
    let tokenizer = Tokenizer::new(HtmlSink::default(), Default::default());
    let _ = tokenizer.feed(&input);
    tokenizer.end();
    tokenizer.sink.0.into_inner().signals
}

fn cookie_name_value(value: &str) -> Option<(String, &str)> {
    let pair = value.split(';').next()?.trim();
    let (name, value) = pair.split_once('=')?;
    let name = name.trim().to_ascii_lowercase();
    (!name.is_empty()).then_some((name, value.trim()))
}

fn response_is_script(url: &str, headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type") && {
            let value = value.to_ascii_lowercase();
            value.contains("javascript") || value.contains("ecmascript")
        }
    }) || Url::parse(url)
        .ok()
        .is_some_and(|url| url.path().to_ascii_lowercase().ends_with(".js"))
}

fn resolve_script_url(document_url: &str, source: &str) -> String {
    Url::parse(document_url)
        .ok()
        .and_then(|base| base.join(source).ok())
        .map(|url| sanitize_url(url.as_str()))
        .unwrap_or_else(|| sanitize_url(source))
}

fn sanitize_url(source: &str) -> String {
    let Ok(mut url) = Url::parse(source) else {
        return source.chars().take(512).collect();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn finalize_detection(detection: AccumulatedDetection) -> WebTechnologyDetection {
    let confidence = detection.confidence_floor.max(match detection.score {
        100 => Confidence::High,
        50..=99 => Confidence::Medium,
        1..=49 => Confidence::Low,
        _ => Confidence::None,
    });
    WebTechnologyDetection {
        name: detection.name,
        category_names: detection.categories.into_iter().collect(),
        version: detection.version,
        confidence,
        evidence_urls: detection.evidence_urls.into_iter().collect(),
        evidence: detection.evidence.into_iter().collect(),
    }
}

fn confidence_score(confidence: Confidence) -> u16 {
    match confidence {
        Confidence::None => 0,
        Confidence::Low => 25,
        Confidence::Medium => 75,
        Confidence::High => 100,
    }
}

fn promote_detections(products: &mut Vec<ProductDetection>, detections: &[WebTechnologyDetection]) {
    for detection in detections {
        for layer in detection
            .category_names
            .iter()
            .filter_map(|name| category_layer(name))
        {
            let evidence = detection.evidence.clone();
            let name = if matches!(layer, ProductLayer::Server | ProductLayer::Proxy) {
                match crate::web_server::canonical_product_name(&detection.name) {
                    Some(name) => name,
                    None => detection.name.as_str(),
                }
            } else {
                detection.name.as_str()
            };
            if let Some(existing) = products
                .iter_mut()
                .find(|product| product.layer == layer && product.name.eq_ignore_ascii_case(name))
            {
                let previous_confidence = existing.confidence;
                if detection.version.is_some()
                    && (existing.version.is_none() || detection.confidence >= previous_confidence)
                {
                    existing.version = detection.version.clone();
                }
                existing.confidence = existing.confidence.max(detection.confidence);
                existing.evidence.extend(evidence);
                existing.evidence.sort();
                existing.evidence.dedup();
            } else {
                products.push(ProductDetection {
                    name: name.to_owned(),
                    layer,
                    version: detection.version.clone(),
                    confidence: detection.confidence,
                    evidence,
                });
            }
        }
    }
    products.sort_by(|left, right| {
        left.layer.to_string().cmp(&right.layer.to_string()).then(
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase()),
        )
    });
}

fn category_layer(name: &str) -> Option<ProductLayer> {
    Some(match name.to_ascii_lowercase().as_str() {
        "cms" => ProductLayer::Cms,
        "ecommerce" | "ecommerce frontends" => ProductLayer::Ecommerce,
        "javascript frameworks" | "web frameworks" | "mobile frameworks" | "ui frameworks" => {
            ProductLayer::Framework
        }
        "programming languages" => ProductLayer::Runtime,
        "web servers" | "web server extensions" => ProductLayer::Server,
        "cdn" => ProductLayer::Cdn,
        "caching" | "reverse proxies" | "load balancers" => ProductLayer::Proxy,
        "paas" | "iaas" | "hosting" => ProductLayer::Cloud,
        _ => return None,
    })
}
