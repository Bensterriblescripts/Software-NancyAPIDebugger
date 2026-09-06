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
const REGEX_SIZE_LIMIT: usize = 4 * 1024 * 1024;
const COMPATIBILITY_BACKTRACK_LIMIT: usize = 100_000;
const COMPATIBILITY_DFA_SIZE_LIMIT: usize = 2 * 1024 * 1024;
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
    value: StateValue,
    refresh_in_progress: bool,
    refresh_queued: bool,
}

fn shared_state() -> &'static Mutex<SharedState> {
    static STATE: OnceLock<Mutex<SharedState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(SharedState {
            value: StateValue::NotStarted,
            refresh_in_progress: false,
            refresh_queued: false,
        })
    })
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
    id: usize,
    location: String,
    technology: usize,
    expression: String,
    matcher: PatternMatcher,
    confidence: u16,
    version: Option<String>,
}

enum PatternMatcher {
    Presence,
    Standard(Regex),
    Compatibility(fancy_regex::Regex),
}

#[derive(Default)]
struct MatcherBank {
    always: Vec<CompiledPattern>,
    batches: Vec<MatcherBatch>,
    individual: Vec<CompiledPattern>,
}

struct MatcherBatch {
    set: RegexSet,
    patterns: Vec<CompiledPattern>,
}

#[derive(Default)]
struct CompileStats {
    total: usize,
    syntax: usize,
    compiled_size: usize,
    oversized: usize,
    warnings: Vec<String>,
}

struct MatchState<'a> {
    cancel: &'a CancellationToken,
    disabled: HashSet<usize>,
    warnings: Vec<String>,
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
    signal_scores: HashMap<String, u16>,
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

pub(crate) fn initialization_status() -> InitializationStatus {
    let state = shared_state()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    match &state.value {
        StateValue::NotStarted => InitializationStatus::NotStarted,
        StateValue::Pending => InitializationStatus::Pending,
        StateValue::Ready { info, .. } => InitializationStatus::Ready {
            warning: info.warning.clone(),
            using_curated_fallback: info.using_curated_fallback,
        },
    }
}

pub(crate) fn start_initialization(force: bool) -> bool {
    let mut state = shared_state()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if state.refresh_in_progress {
        state.refresh_queued |= force;
        return false;
    }
    if matches!(state.value, StateValue::Ready { .. }) && !force {
        return false;
    }
    state.refresh_in_progress = true;
    if matches!(state.value, StateValue::NotStarted) {
        state.value = StateValue::Pending;
    }
    true
}

pub(crate) async fn run_started_initialization() {
    prepare_initial_catalog();
    loop {
        let result = refresh_catalog().await;
        if !complete_initialization(result) {
            return;
        }
    }
}

async fn fetch_catalog_envelope() -> Result<CacheEnvelope, String> {
    let request = ExposureScanRequest::default();
    let cancel = CancellationToken::new();
    let limiter = ConnectionRateLimiter::new(20);
    let (fingerprints, categories) = tokio::join!(
        fetch_catalog_json(
            FINGERPRINTS_URL,
            MAX_FINGERPRINT_BYTES,
            &request,
            &cancel,
            &limiter,
        ),
        fetch_catalog_json(
            CATEGORIES_URL,
            MAX_CATEGORY_BYTES,
            &request,
            &cancel,
            &limiter,
        ),
    );
    Ok(CacheEnvelope {
        schema_version: CACHE_SCHEMA_VERSION,
        retrieved_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        source_urls: SourceUrls {
            fingerprints: FINGERPRINTS_URL.to_owned(),
            categories: CATEGORIES_URL.to_owned(),
        },
        fingerprint_data: fingerprints?,
        category_definitions: categories?,
    })
}

async fn fetch_catalog_json(
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

async fn refresh_catalog() -> Result<(Arc<Catalog>, InitializationInfo), String> {
    let envelope = fetch_catalog_envelope().await?;
    let catalog = Arc::new(compile_envelope(&envelope)?);
    let warning = persistence::write_json_with_backup(CACHE_FILE, &envelope, MAX_CACHE_BYTES)
        .err()
        .map(|error| format!("Web technology catalog cache could not be updated: {error}"));
    Ok((
        catalog,
        InitializationInfo {
            warning,
            using_curated_fallback: false,
        },
    ))
}

pub(crate) fn spawn_initialization(
    force: bool,
    complete: impl Fn(Result<(), String>) + Send + Sync + 'static,
) {
    if !start_initialization(force) {
        return;
    }
    crate::worker::spawn(
        "Fingerprint initialization",
        || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("Unable to create async runtime: {error}"))?;
            runtime.block_on(run_started_initialization());
            Ok(())
        },
        move |result| {
            if let Err(error) = &result {
                complete_worker_failure(error.clone());
            }
            complete(result);
        },
    );
}

fn complete_worker_failure(error: String) {
    let mut state = shared_state()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let catalog = match &state.value {
        StateValue::Ready { catalog, .. } => catalog.clone(),
        _ => None,
    };
    let using_curated_fallback = catalog.is_none();
    state.value = StateValue::Ready {
        catalog,
        info: InitializationInfo {
            warning: Some(format!(
                "{error}; using {}",
                if using_curated_fallback {
                    "curated fingerprints"
                } else {
                    "the last valid catalog"
                }
            )),
            using_curated_fallback,
        },
    };
    state.refresh_in_progress = false;
    state.refresh_queued = false;
    shared_state().clear_poison();
}

pub(crate) async fn ensure_initialized() {
    loop {
        match initialization_status() {
            InitializationStatus::Ready { .. } => return,
            InitializationStatus::NotStarted => spawn_initialization(false, |_| {}),
            InitializationStatus::Pending => {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await
            }
        }
    }
}

fn load_cached_catalog() -> Result<(Catalog, bool), String> {
    let catalog = RefCell::new(None);
    let (_, used_backup) = persistence::read_json_with_backup(
        CACHE_FILE,
        MAX_CACHE_BYTES,
        |envelope: &CacheEnvelope| {
            let compiled = compile_envelope(envelope)?;
            *catalog.borrow_mut() = Some(compiled);
            Ok(())
        },
    )?;
    catalog
        .into_inner()
        .map(|catalog| (catalog, used_backup))
        .ok_or_else(|| "fingerprint cache validation produced no catalog".to_owned())
}

fn prepare_initial_catalog() {
    if matches!(
        shared_state()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .value,
        StateValue::Ready { .. }
    ) {
        return;
    }
    let (catalog, info) = match load_cached_catalog() {
        Ok((catalog, used_backup)) => (
            Some(Arc::new(catalog)),
            InitializationInfo {
                warning: used_backup
                    .then(|| "Web technology catalog loaded from the backup cache".to_owned()),
                using_curated_fallback: false,
            },
        ),
        Err(error) => (
            None,
            InitializationInfo {
                warning: Some(format!(
                    "Web technology catalog cache unavailable; using curated fingerprints: {error}"
                )),
                using_curated_fallback: true,
            },
        ),
    };
    shared_state()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .value = StateValue::Ready { catalog, info };
}

fn complete_initialization(result: Result<(Arc<Catalog>, InitializationInfo), String>) -> bool {
    let mut state = shared_state()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (catalog, info) = match result {
        Ok((catalog, info)) => (Some(catalog), info),
        Err(error) => {
            let catalog = match &state.value {
                StateValue::Ready { catalog, .. } => catalog.clone(),
                _ => None,
            };
            let using_curated_fallback = catalog.is_none();
            let source = if using_curated_fallback {
                "curated fingerprints"
            } else {
                "the last valid catalog"
            };
            (
                catalog,
                InitializationInfo {
                    warning: Some(format!(
                        "Web technology catalog refresh failed; using {source}: {error}"
                    )),
                    using_curated_fallback,
                },
            )
        }
    };
    let previous = std::mem::replace(&mut state.value, StateValue::Ready { catalog, info });
    let refresh_again = std::mem::take(&mut state.refresh_queued);
    state.refresh_in_progress = refresh_again;
    drop(state);
    drop(previous);
    refresh_again
}

fn compile_envelope(envelope: &CacheEnvelope) -> Result<Catalog, String> {
    ({
        let (envelope,): (&CacheEnvelope,) = (envelope,);
        let inlined_result: Result<(), String> = {
            'inlined_validate_envelope: {
                if envelope.schema_version != CACHE_SCHEMA_VERSION {
                    break 'inlined_validate_envelope Err(format!(
                        "unsupported fingerprint cache schema {}",
                        envelope.schema_version
                    ));
                }
                if envelope.retrieved_unix_seconds == 0 {
                    break 'inlined_validate_envelope Err(
                        "fingerprint cache retrieval timestamp is missing".to_owned(),
                    );
                }
                if envelope.source_urls.fingerprints.is_empty()
                    || envelope.source_urls.categories.is_empty()
                {
                    break 'inlined_validate_envelope Err(
                        "fingerprint cache source URLs are missing".to_owned(),
                    );
                }
                let fingerprint_bytes = match serde_json::to_vec(&envelope.fingerprint_data)
                    .map_err(|error| format!("invalid cached fingerprint data: {error}"))
                {
                    Ok(value) => value,
                    Err(error) => {
                        break 'inlined_validate_envelope Err(::core::convert::From::from(error));
                    }
                }
                .len();
                if fingerprint_bytes > MAX_FINGERPRINT_BYTES {
                    break 'inlined_validate_envelope Err(
                        "cached fingerprint data exceeds the 8 MiB limit".to_owned(),
                    );
                }
                let category_bytes = match serde_json::to_vec(&envelope.category_definitions)
                    .map_err(|error| format!("invalid cached category definitions: {error}"))
                {
                    Ok(value) => value,
                    Err(error) => {
                        break 'inlined_validate_envelope Err(::core::convert::From::from(error));
                    }
                }
                .len();
                if category_bytes > MAX_CATEGORY_BYTES {
                    break 'inlined_validate_envelope Err(
                        "cached category definitions exceed the 256 KiB limit".to_owned(),
                    );
                }
                Ok(())
            }
        };
        inlined_result
    })?;
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
            .filter_map(|value| {
                let (source,): (&str,) = (value,);
                {
                    'inlined_parse_implication: {
                        let mut parts = source.split("\\;");
                        let target = match parts.next() {
                            Some(value) => value,
                            None => break 'inlined_parse_implication None,
                        }
                        .trim()
                        .to_ascii_lowercase();
                        if target.is_empty() {
                            break 'inlined_parse_implication None;
                        }
                        let confidence = parts.find_map(|tag| {
                            tag.strip_prefix("confidence:")
                                .and_then(|value| value.parse::<u16>().ok())
                                .map(|value| value.clamp(1, 100))
                        });
                        Some(Implication { target, confidence })
                    }
                }
            })
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
        let mut compile = |field: &str, index, source: &str| {
            let (technology, name, field, index, source, stats): (
                usize,
                &str,
                &str,
                usize,
                &str,
                &mut CompileStats,
            ) = (
                technology,
                &technologies[technology].name,
                field,
                index,
                source,
                &mut stats,
            );
            {
                'inlined_compile_pattern: {
                    let id = stats.total;
                    stats.total += 1;
                    let location = format!("{name} {field}[{index}]");
                    let source = match (name, field, source) {
                        ("PubTech", "scriptSrc", r"pubtech-cmp-v(.+?)(?:-esm)?\.js;version:\1") => {
                            r"pubtech-cmp-v(.+?)(?:-esm)?\.js\;version:\1"
                        }
                        _ => source,
                    };
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
                        stats.warnings.push(format!(
            "Web technology pattern {location} skipped (oversized expression): {} bytes exceeds {MAX_PATTERN_BYTES} bytes",
            expression.len()
        ));
                        break 'inlined_compile_pattern None;
                    }
                    let matcher = if expression.is_empty() {
                        PatternMatcher::Presence
                    } else {
                        match RegexBuilder::new(&expression)
                            .case_insensitive(true)
                            .size_limit(REGEX_SIZE_LIMIT)
                            .build()
                        {
                            Ok(regex) => PatternMatcher::Standard(regex),
                            Err(error @ regex::Error::Syntax(_)) => {
                                match fancy_regex::RegexBuilder::new(&expression)
                                    .case_insensitive(true)
                                    .unicode_mode(true)
                                    .backtrack_limit(COMPATIBILITY_BACKTRACK_LIMIT)
                                    .delegate_size_limit(REGEX_SIZE_LIMIT)
                                    .delegate_dfa_size_limit(COMPATIBILITY_DFA_SIZE_LIMIT)
                                    .build()
                                {
                                    Ok(regex) => PatternMatcher::Compatibility(regex),
                                    Err(compatibility_error) => {
                                        let size_failure = matches!(
                                            &compatibility_error,
                                            fancy_regex::Error::CompileError(error)
                                                if matches!(error.as_ref(), fancy_regex::CompileError::InnerError(error)
                                                    if error.size_limit().is_some())
                                        );
                                        let reason = if size_failure {
                                            stats.compiled_size += 1;
                                            "compiled-size failure"
                                        } else {
                                            stats.syntax += 1;
                                            "syntax failure"
                                        };
                                        stats.warnings.push(format!(
                            "Web technology pattern {location} skipped ({reason}): standard compiler: {error}; compatibility compiler: {compatibility_error}"
                        ));
                                        break 'inlined_compile_pattern None;
                                    }
                                }
                            }
                            Err(error) => {
                                let reason = if matches!(error, regex::Error::CompiledTooBig(_)) {
                                    stats.compiled_size += 1;
                                    "compiled-size failure"
                                } else {
                                    stats.syntax += 1;
                                    "syntax failure"
                                };
                                stats.warnings.push(format!(
                                    "Web technology pattern {location} skipped ({reason}): {error}"
                                ));
                                break 'inlined_compile_pattern None;
                            }
                        }
                    };
                    Some(CompiledPattern {
                        id,
                        location,
                        technology,
                        expression,
                        matcher,
                        confidence,
                        version,
                    })
                }
            }
        };
        for (name, pattern) in fingerprint.headers {
            if let Some(pattern) = compile(&format!("headers[{name:?}]"), 0, &pattern) {
                headers
                    .entry(name.to_ascii_lowercase())
                    .or_default()
                    .push(pattern);
            }
        }
        for (name, pattern) in fingerprint.cookies {
            if let Some(pattern) = compile(&format!("cookies[{name:?}]"), 0, &pattern) {
                cookies
                    .entry(name.to_ascii_lowercase())
                    .or_default()
                    .push(pattern);
            }
        }
        for (name, patterns) in fingerprint.meta {
            for (index, pattern) in patterns.into_iter().enumerate() {
                if let Some(pattern) = compile(&format!("meta[{name:?}]"), index, &pattern) {
                    meta.entry(name.to_ascii_lowercase())
                        .or_default()
                        .push(pattern);
                }
            }
        }
        for (index, pattern) in fingerprint.html.into_iter().enumerate() {
            if let Some(pattern) = compile("html", index, &pattern) {
                html.push(pattern);
            }
        }
        for (index, pattern) in fingerprint.script_src.into_iter().enumerate() {
            if let Some(pattern) = compile("scriptSrc", index, &pattern) {
                script_sources.push(pattern);
            }
        }
        for (index, pattern) in fingerprint.scripts.into_iter().enumerate() {
            if let Some(pattern) = compile("scripts", index, &pattern) {
                scripts.push(pattern);
            }
        }
    }
    let html = {
        let (patterns,): (Vec<CompiledPattern>,) = (html,);
        let inlined_result: MatcherBank = {
            let mut bank = MatcherBank::default();
            let mut regular = Vec::new();
            for pattern in patterns {
                match &pattern.matcher {
                    PatternMatcher::Presence => bank.always.push(pattern),
                    PatternMatcher::Standard(_) => regular.push(pattern),
                    PatternMatcher::Compatibility(_) => bank.individual.push(pattern),
                }
            }
            while !regular.is_empty() {
                let count = REGEX_BATCH_SIZE.min(regular.len());
                let batch = regular.drain(..count).collect::<Vec<_>>();
                compile_batch(batch, &mut bank);
            }
            bank
        };
        inlined_result
    };
    let script_sources = {
        let (patterns,): (Vec<CompiledPattern>,) = (script_sources,);
        let inlined_result: MatcherBank = {
            let mut bank = MatcherBank::default();
            let mut regular = Vec::new();
            for pattern in patterns {
                match &pattern.matcher {
                    PatternMatcher::Presence => bank.always.push(pattern),
                    PatternMatcher::Standard(_) => regular.push(pattern),
                    PatternMatcher::Compatibility(_) => bank.individual.push(pattern),
                }
            }
            while !regular.is_empty() {
                let count = REGEX_BATCH_SIZE.min(regular.len());
                let batch = regular.drain(..count).collect::<Vec<_>>();
                compile_batch(batch, &mut bank);
            }
            bank
        };
        inlined_result
    };
    let scripts = {
        let (patterns,): (Vec<CompiledPattern>,) = (scripts,);
        let inlined_result: MatcherBank = {
            let mut bank = MatcherBank::default();
            let mut regular = Vec::new();
            for pattern in patterns {
                match &pattern.matcher {
                    PatternMatcher::Presence => bank.always.push(pattern),
                    PatternMatcher::Standard(_) => regular.push(pattern),
                    PatternMatcher::Compatibility(_) => bank.individual.push(pattern),
                }
            }
            while !regular.is_empty() {
                let count = REGEX_BATCH_SIZE.min(regular.len());
                let batch = regular.drain(..count).collect::<Vec<_>>();
                compile_batch(batch, &mut bank);
            }
            bank
        };
        inlined_result
    };
    let mut warnings = stats.warnings;
    if stats.syntax > 0 || stats.compiled_size > 0 || stats.oversized > 0 {
        warnings.insert(0, format!(
            "Web technology catalog skipped passive patterns: {} syntax failure(s), {} compiled-size failure(s), {} oversized expression(s)",
            stats.syntax, stats.compiled_size, stats.oversized
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

fn compile_batch(patterns: Vec<CompiledPattern>, bank: &mut MatcherBank) {
    let expressions = patterns
        .iter()
        .map(|pattern| pattern.expression.as_str())
        .collect::<Vec<_>>();
    match RegexSetBuilder::new(expressions)
        .case_insensitive(true)
        .size_limit(REGEX_SET_SIZE_LIMIT)
        .build()
    {
        Ok(set) => bank.batches.push(MatcherBatch { set, patterns }),
        Err(_) if patterns.len() > 1 => {
            let mut left = patterns;
            let right = left.split_off(left.len() / 2);
            compile_batch(left, bank);
            compile_batch(right, bank);
        }
        Err(_) => bank.individual.extend(patterns),
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
        let state = shared_state()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match &state.value {
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
    let mut catalogs = catalog.as_deref().into_iter().collect::<Vec<_>>();
    match {
        let inlined_result: &'static Result<Catalog, String> = {
            static CATALOG: OnceLock<Result<Catalog, String>> = OnceLock::new();
            CATALOG.get_or_init(|| {
                let raw = serde_json::from_str(include_str!("bundled_fingerprints.json"))
                    .map_err(|error| format!("invalid bundled fingerprints: {error}"))?;
                let categories = [
                    (1, "CMS"),
                    (2, "Ecommerce"),
                    (3, "Web servers"),
                    (4, "CDN"),
                    (5, "PaaS"),
                ]
                .into_iter()
                .map(|(id, name)| (id, name.to_owned()))
                .collect();
                compile_catalog(raw, &categories)
            })
        };
        inlined_result
    } {
        Ok(catalog) => catalogs.push(catalog),
        Err(error) => warnings.push(error.clone()),
    }
    let mut accumulated = endpoints
        .iter()
        .map(|endpoint: &EndpointScan| {
            let mut detections = HashMap::<String, AccumulatedDetection>::new();
            for product in &endpoint.products {
                let key = product.name.to_ascii_lowercase();
                let detection = detections.entry(key).or_default();
                detection.name = product.name.clone();
                detection.categories.insert(product.layer.to_string());
                detection.confidence_floor = detection.confidence_floor.max(product.confidence);
                if product.version.is_some()
                    && (detection.version.is_none()
                        || ({
                            let (confidence,): (Confidence,) = (product.confidence,);
                            let inlined_result: u16 = {
                                match confidence {
                                    Confidence::None => 0,
                                    Confidence::Low => 25,
                                    Confidence::Medium => 75,
                                    Confidence::High => 100,
                                }
                            };
                            inlined_result
                        }) >= detection.version_confidence)
                {
                    detection.version = product.version.clone();
                    detection.version_confidence = {
                        let (confidence,): (Confidence,) = (product.confidence,);
                        let inlined_result: u16 = {
                            match confidence {
                                Confidence::None => 0,
                                Confidence::Low => 25,
                                Confidence::Medium => 75,
                                Confidence::High => 100,
                            }
                        };
                        inlined_result
                    };
                }
                detection.evidence.extend(product.evidence.iter().cloned());
            }
            detections
        })
        .collect::<Vec<_>>();
    for catalog in &catalogs {
        warnings.extend(catalog.warnings.iter().cloned());
    }
    let mut match_states = catalogs
        .iter()
        .map(|_| {
            let (cancel,): (&'_ CancellationToken,) = (cancel,);
            {
                MatchState {
                    cancel,
                    disabled: HashSet::new(),
                    warnings: Vec::new(),
                }
            }
        })
        .collect::<Vec<_>>();
    for (index, endpoint) in endpoints.iter().enumerate() {
        for response in &endpoint.http {
            if cancel.is_cancelled() {
                break;
            }
            for (catalog, state) in catalogs.iter().zip(&mut match_states) {
                ({
                    let (
                        inlined_self,
                        detections,
                        response_url,
                        status,
                        response_headers,
                        body,
                        script_override,
                        state,
                    ): (
                        &Catalog,
                        &mut HashMap<String, AccumulatedDetection>,
                        &str,
                        u16,
                        &[(String, String)],
                        &[u8],
                        Option<bool>,
                        &mut MatchState<'_>,
                    ) = (
                        &(catalog),
                        &mut accumulated[index],
                        &response.url,
                        response.status,
                        &response.headers,
                        &response.body,
                        None,
                        state,
                    );
                    'inlined_scan_response: {
                        if state.cancel.is_cancelled() {
                            break 'inlined_scan_response;
                        }
                        let url = {
                            let (source,): (&str,) = (response_url,);
                            let inlined_result: String = {
                                'inlined_sanitize_url: {
                                    let Ok(mut url) = Url::parse(source) else {
                                        break 'inlined_sanitize_url source
                                            .chars()
                                            .take(512)
                                            .collect();
                                    };
                                    let _ = url.set_username("");
                                    let _ = url.set_password(None);
                                    url.set_query(None);
                                    url.set_fragment(None);
                                    url.to_string()
                                }
                            };
                            inlined_result
                        };
                        let mut headers = HashMap::<String, Vec<&str>>::new();
                        for (name, value) in response_headers {
                            headers
                                .entry(name.to_ascii_lowercase())
                                .or_default()
                                .push(value);
                        }
                        for (name, values) in &headers {
                            let combined = values.join(", ");
                            if let Some(patterns) = inlined_self.headers.get(name) {
                                for pattern in patterns {
                                    if let Some(version) = {
                                        let (pattern, text, state): (
                                            &CompiledPattern,
                                            &str,
                                            &mut MatchState<'_>,
                                        ) = (pattern, &combined, state);
                                        let inlined_result: Option<Option<String>> = {
                                            'inlined_match_single_pattern: {
                                                if state.cancel.is_cancelled() {
                                                    break 'inlined_match_single_pattern None;
                                                }
                                                match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                            }
                                        };
                                        inlined_result
                                    } {
                                        let key = format!("header:{name}:{url}");
                                        let label = format!("header {name}");
                                        ({
                                            let (
                                                inlined_self,
                                                detections,
                                                pattern,
                                                version,
                                                context,
                                            ): (
                                                &Catalog,
                                                &mut HashMap<String, AccumulatedDetection>,
                                                &CompiledPattern,
                                                Option<String>,
                                                MatchContext<'_>,
                                            ) = (
                                                &(inlined_self),
                                                detections,
                                                pattern,
                                                version,
                                                MatchContext {
                                                    key: &key,
                                                    label: &label,
                                                    url: &url,
                                                },
                                            );

                                            let mut path = HashSet::new();
                                            inlined_self.add_recursive(
                                                detections,
                                                pattern.technology,
                                                pattern.confidence,
                                                version,
                                                &context,
                                                &mut path,
                                                None,
                                            );
                                        });
                                    }
                                }
                            }
                        }
                        for value in headers.get("set-cookie").into_iter().flatten() {
                            if let Some((name, cookie_value)) = ({
                                let (value,): (&str,) = (value,);
                                {
                                    'inlined_cookie_name_value: {
                                        let pair = match value.split(';').next() {
                                            Some(value) => value,
                                            None => break 'inlined_cookie_name_value None,
                                        }
                                        .trim();
                                        let (name, value) = match pair.split_once('=') {
                                            Some(value) => value,
                                            None => break 'inlined_cookie_name_value None,
                                        };
                                        let name = name.trim().to_ascii_lowercase();
                                        (!name.is_empty()).then_some((name, value.trim()))
                                    }
                                }
                            }) && let Some(patterns) = inlined_self.cookies.get(&name)
                            {
                                for pattern in patterns {
                                    if let Some(version) = {
                                        let (pattern, text, state): (
                                            &CompiledPattern,
                                            &str,
                                            &mut MatchState<'_>,
                                        ) = (pattern, cookie_value, state);
                                        let inlined_result: Option<Option<String>> = {
                                            'inlined_match_single_pattern: {
                                                if state.cancel.is_cancelled() {
                                                    break 'inlined_match_single_pattern None;
                                                }
                                                match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                            }
                                        };
                                        inlined_result
                                    } {
                                        let key = format!("cookie:{name}:{url}");
                                        let label = format!("cookie {name}");
                                        ({
                                            let (
                                                inlined_self,
                                                detections,
                                                pattern,
                                                version,
                                                context,
                                            ): (
                                                &Catalog,
                                                &mut HashMap<String, AccumulatedDetection>,
                                                &CompiledPattern,
                                                Option<String>,
                                                MatchContext<'_>,
                                            ) = (
                                                &(inlined_self),
                                                detections,
                                                pattern,
                                                version,
                                                MatchContext {
                                                    key: &key,
                                                    label: &label,
                                                    url: &url,
                                                },
                                            );

                                            let mut path = HashSet::new();
                                            inlined_self.add_recursive(
                                                detections,
                                                pattern.technology,
                                                pattern.confidence,
                                                version,
                                                &context,
                                                &mut path,
                                                None,
                                            );
                                        });
                                    }
                                }
                            }
                        }
                        let text = String::from_utf8_lossy(body);
                        let is_script = script_override.unwrap_or_else(|| {
                            let (url, headers): (&str, &[(String, String)]) =
                                (response_url, response_headers);
                            {
                                headers.iter().any(|(name, value)| {
                                    name.eq_ignore_ascii_case("content-type") && {
                                        let value = value.to_ascii_lowercase();
                                        value.contains("javascript") || value.contains("ecmascript")
                                    }
                                }) || Url::parse(url).ok().is_some_and(|url| {
                                    url.path().to_ascii_lowercase().ends_with(".js")
                                })
                            }
                        });
                        if is_script {
                            if (200..300).contains(&status) {
                                let key = format!("script-content:{url}");
                                ({
                                    let (inlined_self, text, state, mut visit): (
                                        &MatcherBank,
                                        &str,
                                        &mut MatchState<'_>,
                                        _,
                                    ) = (
                                        &(inlined_self.scripts),
                                        &text,
                                        state,
                                        |pattern, version| {
                                            ({
                                                let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                                key: &key,
                                label: "external script content",
                                url: &url,
                            },);

                                                let mut path = HashSet::new();
                                                inlined_self.add_recursive(
                                                    detections,
                                                    pattern.technology,
                                                    pattern.confidence,
                                                    version,
                                                    &context,
                                                    &mut path,
                                                    None,
                                                );
                                            });
                                        },
                                    );
                                    'inlined_visit_matches: {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        for pattern in &inlined_self.always {
                                            visit(pattern, None);
                                        }
                                        for batch in &inlined_self.batches {
                                            if state.cancel.is_cancelled() {
                                                break 'inlined_visit_matches;
                                            }
                                            for index in batch.set.matches(text).into_iter() {
                                                let pattern = &batch.patterns[index];
                                                visit(pattern, {
                                                    let (pattern, text): (&CompiledPattern, &str) =
                                                        (pattern, text);
                                                    let inlined_result: Option<String> = {
                                                        'inlined_pattern_version: {
                                                            let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
                                                            let PatternMatcher::Standard(regex) =
                                                                &pattern.matcher
                                                            else {
                                                                break 'inlined_pattern_version None;
                                                            };
                                                            let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
                                                            {
                                                                let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                                let inlined_result: Option<String> = {
                                                                    let mut result =
                                                                        template.to_owned();
                                                                    for index in 1..capture_count {
                                                                        let marker =
                                                                            format!("\\{index}");
                                                                        let value = capture(index);
                                                                        let conditional =
                                                                            format!("{marker}?");
                                                                        while let Some(start) =
                                                                            result
                                                                                .find(&conditional)
                                                                        {
                                                                            let branch_start = start
                                                                                + conditional.len();
                                                                            let end = result
                                                                                [branch_start..]
                                                                                .find("\\;")
                                                                                .map(|offset| {
                                                                                    branch_start
                                                                                        + offset
                                                                                })
                                                                                .unwrap_or(
                                                                                    result.len(),
                                                                                );
                                                                            let branch = &result
                                                                                [branch_start..end];
                                                                            let (
                                                                                when_present,
                                                                                when_missing,
                                                                            ) = branch
                                                                                .split_once(':')
                                                                                .unwrap_or((
                                                                                    branch, "",
                                                                                ));
                                                                            let replacement =
                                                                                if value.is_empty()
                                                                                {
                                                                                    when_missing
                                                                                } else {
                                                                                    when_present
                                                                                }
                                                                                .to_owned();
                                                                            result.replace_range(
                                                                                start..end,
                                                                                &replacement,
                                                                            );
                                                                        }
                                                                        result = result.replace(
                                                                            &marker, value,
                                                                        );
                                                                    }
                                                                    let result = result
                                                                        .trim()
                                                                        .trim_start_matches([
                                                                            'v', 'V',
                                                                        ])
                                                                        .to_owned();
                                                                    (!result.is_empty())
                                                                        .then_some(result)
                                                                };
                                                                inlined_result
                                                            }
                                                        }
                                                    };
                                                    inlined_result
                                                });
                                            }
                                        }
                                        for pattern in &inlined_self.individual {
                                            if state.cancel.is_cancelled() {
                                                break 'inlined_visit_matches;
                                            }
                                            if let Some(version) = {
                                                let (pattern, text, state): (
                                                    &CompiledPattern,
                                                    &str,
                                                    &mut MatchState<'_>,
                                                ) = (pattern, text, state);
                                                let inlined_result: Option<Option<String>> = {
                                                    'inlined_match_single_pattern: {
                                                        if state.cancel.is_cancelled() {
                                                            break 'inlined_match_single_pattern None;
                                                        }
                                                        match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                    }
                                                };
                                                inlined_result
                                            } {
                                                visit(pattern, version);
                                            }
                                        }
                                    }
                                });
                            }
                            let key = format!("script-url:{url}");
                            ({
                                let (inlined_self, text, state, mut visit): (
                                    &MatcherBank,
                                    &str,
                                    &mut MatchState<'_>,
                                    _,
                                ) = (
                                    &(inlined_self.script_sources),
                                    &url,
                                    state,
                                    |pattern, version| {
                                        ({
                                            let (
                                                inlined_self,
                                                detections,
                                                pattern,
                                                version,
                                                context,
                                            ): (
                                                &Catalog,
                                                &mut HashMap<String, AccumulatedDetection>,
                                                &CompiledPattern,
                                                Option<String>,
                                                MatchContext<'_>,
                                            ) = (
                                                &(inlined_self),
                                                detections,
                                                pattern,
                                                version,
                                                MatchContext {
                                                    key: &key,
                                                    label: "script URL",
                                                    url: &url,
                                                },
                                            );

                                            let mut path = HashSet::new();
                                            inlined_self.add_recursive(
                                                detections,
                                                pattern.technology,
                                                pattern.confidence,
                                                version,
                                                &context,
                                                &mut path,
                                                None,
                                            );
                                        });
                                    },
                                );
                                'inlined_visit_matches: {
                                    if state.cancel.is_cancelled() {
                                        break 'inlined_visit_matches;
                                    }
                                    for pattern in &inlined_self.always {
                                        visit(pattern, None);
                                    }
                                    for batch in &inlined_self.batches {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        for index in batch.set.matches(text).into_iter() {
                                            let pattern = &batch.patterns[index];
                                            visit(pattern, {
                                                let (pattern, text): (&CompiledPattern, &str) =
                                                    (pattern, text);
                                                let inlined_result: Option<String> = {
                                                    'inlined_pattern_version: {
                                                        let template = match pattern
                                                            .version
                                                            .as_deref()
                                                        {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_pattern_version None;
                                                            }
                                                        };
                                                        let PatternMatcher::Standard(regex) =
                                                            &pattern.matcher
                                                        else {
                                                            break 'inlined_pattern_version None;
                                                        };
                                                        let captures = match regex.captures(text) {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_pattern_version None;
                                                            }
                                                        };
                                                        {
                                                            let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                            let inlined_result: Option<String> = {
                                                                let mut result =
                                                                    template.to_owned();
                                                                for index in 1..capture_count {
                                                                    let marker =
                                                                        format!("\\{index}");
                                                                    let value = capture(index);
                                                                    let conditional =
                                                                        format!("{marker}?");
                                                                    while let Some(start) =
                                                                        result.find(&conditional)
                                                                    {
                                                                        let branch_start = start
                                                                            + conditional.len();
                                                                        let end = result
                                                                            [branch_start..]
                                                                            .find("\\;")
                                                                            .map(|offset| {
                                                                                branch_start
                                                                                    + offset
                                                                            })
                                                                            .unwrap_or(
                                                                                result.len(),
                                                                            );
                                                                        let branch = &result
                                                                            [branch_start..end];
                                                                        let (
                                                                            when_present,
                                                                            when_missing,
                                                                        ) = branch
                                                                            .split_once(':')
                                                                            .unwrap_or((
                                                                                branch, "",
                                                                            ));
                                                                        let replacement =
                                                                            if value.is_empty() {
                                                                                when_missing
                                                                            } else {
                                                                                when_present
                                                                            }
                                                                            .to_owned();
                                                                        result.replace_range(
                                                                            start..end,
                                                                            &replacement,
                                                                        );
                                                                    }
                                                                    result = result
                                                                        .replace(&marker, value);
                                                                }
                                                                let result = result
                                                                    .trim()
                                                                    .trim_start_matches(['v', 'V'])
                                                                    .to_owned();
                                                                (!result.is_empty())
                                                                    .then_some(result)
                                                            };
                                                            inlined_result
                                                        }
                                                    }
                                                };
                                                inlined_result
                                            });
                                        }
                                    }
                                    for pattern in &inlined_self.individual {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        if let Some(version) = {
                                            let (pattern, text, state): (
                                                &CompiledPattern,
                                                &str,
                                                &mut MatchState<'_>,
                                            ) = (pattern, text, state);
                                            let inlined_result: Option<Option<String>> = {
                                                'inlined_match_single_pattern: {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_match_single_pattern None;
                                                    }
                                                    match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                }
                                            };
                                            inlined_result
                                        } {
                                            visit(pattern, version);
                                        }
                                    }
                                }
                            });
                            break 'inlined_scan_response;
                        }
                        let html_key = format!("html:{url}");
                        ({
                            let (inlined_self, text, state, mut visit): (
                                &MatcherBank,
                                &str,
                                &mut MatchState<'_>,
                                _,
                            ) = (&(inlined_self.html), &text, state, |pattern, version| {
                                ({
                                    let (inlined_self, detections, pattern, version, context): (
                                        &Catalog,
                                        &mut HashMap<String, AccumulatedDetection>,
                                        &CompiledPattern,
                                        Option<String>,
                                        MatchContext<'_>,
                                    ) = (
                                        &(inlined_self),
                                        detections,
                                        pattern,
                                        version,
                                        MatchContext {
                                            key: &html_key,
                                            label: "HTML signature",
                                            url: &url,
                                        },
                                    );

                                    let mut path = HashSet::new();
                                    inlined_self.add_recursive(
                                        detections,
                                        pattern.technology,
                                        pattern.confidence,
                                        version,
                                        &context,
                                        &mut path,
                                        None,
                                    );
                                });
                            });
                            'inlined_visit_matches: {
                                if state.cancel.is_cancelled() {
                                    break 'inlined_visit_matches;
                                }
                                for pattern in &inlined_self.always {
                                    visit(pattern, None);
                                }
                                for batch in &inlined_self.batches {
                                    if state.cancel.is_cancelled() {
                                        break 'inlined_visit_matches;
                                    }
                                    for index in batch.set.matches(text).into_iter() {
                                        let pattern = &batch.patterns[index];
                                        visit(pattern, {
                                            let (pattern, text): (&CompiledPattern, &str) =
                                                (pattern, text);
                                            let inlined_result: Option<String> = {
                                                'inlined_pattern_version: {
                                                    let template = match pattern.version.as_deref()
                                                    {
                                                        Some(value) => value,
                                                        None => {
                                                            break 'inlined_pattern_version None;
                                                        }
                                                    };
                                                    let PatternMatcher::Standard(regex) =
                                                        &pattern.matcher
                                                    else {
                                                        break 'inlined_pattern_version None;
                                                    };
                                                    let captures = match regex.captures(text) {
                                                        Some(value) => value,
                                                        None => {
                                                            break 'inlined_pattern_version None;
                                                        }
                                                    };
                                                    {
                                                        let (template, capture_count, capture): (
                                                            &str,
                                                            usize,
                                                            _,
                                                        ) = (template, captures.len(), |index| {
                                                            captures
                                                                .get(index)
                                                                .map_or("", |capture| {
                                                                    capture.as_str()
                                                                })
                                                        });
                                                        let inlined_result: Option<String> = {
                                                            let mut result = template.to_owned();
                                                            for index in 1..capture_count {
                                                                let marker = format!("\\{index}");
                                                                let value = capture(index);
                                                                let conditional =
                                                                    format!("{marker}?");
                                                                while let Some(start) =
                                                                    result.find(&conditional)
                                                                {
                                                                    let branch_start =
                                                                        start + conditional.len();
                                                                    let end = result
                                                                        [branch_start..]
                                                                        .find("\\;")
                                                                        .map(|offset| {
                                                                            branch_start + offset
                                                                        })
                                                                        .unwrap_or(result.len());
                                                                    let branch =
                                                                        &result[branch_start..end];
                                                                    let (
                                                                        when_present,
                                                                        when_missing,
                                                                    ) = branch
                                                                        .split_once(':')
                                                                        .unwrap_or((branch, ""));
                                                                    let replacement =
                                                                        if value.is_empty() {
                                                                            when_missing
                                                                        } else {
                                                                            when_present
                                                                        }
                                                                        .to_owned();
                                                                    result.replace_range(
                                                                        start..end,
                                                                        &replacement,
                                                                    );
                                                                }
                                                                result =
                                                                    result.replace(&marker, value);
                                                            }
                                                            let result = result
                                                                .trim()
                                                                .trim_start_matches(['v', 'V'])
                                                                .to_owned();
                                                            (!result.is_empty()).then_some(result)
                                                        };
                                                        inlined_result
                                                    }
                                                }
                                            };
                                            inlined_result
                                        });
                                    }
                                }
                                for pattern in &inlined_self.individual {
                                    if state.cancel.is_cancelled() {
                                        break 'inlined_visit_matches;
                                    }
                                    if let Some(version) = {
                                        let (pattern, text, state): (
                                            &CompiledPattern,
                                            &str,
                                            &mut MatchState<'_>,
                                        ) = (pattern, text, state);
                                        let inlined_result: Option<Option<String>> = {
                                            'inlined_match_single_pattern: {
                                                if state.cancel.is_cancelled() {
                                                    break 'inlined_match_single_pattern None;
                                                }
                                                match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                            }
                                        };
                                        inlined_result
                                    } {
                                        visit(pattern, version);
                                    }
                                }
                            }
                        });
                        let signals = {
                            let (text,): (&str,) = (&text,);
                            let inlined_result: HtmlSignals = {
                                let input = BufferQueue::default();
                                input.push_back(StrTendril::from(text));
                                let tokenizer =
                                    Tokenizer::new(HtmlSink::default(), Default::default());
                                let _ = tokenizer.feed(&input);
                                tokenizer.end();
                                tokenizer.sink.0.into_inner().signals
                            };
                            inlined_result
                        };
                        for (name, content) in signals.meta {
                            if let Some(patterns) = inlined_self.meta.get(&name) {
                                for pattern in patterns {
                                    if let Some(version) = {
                                        let (pattern, text, state): (
                                            &CompiledPattern,
                                            &str,
                                            &mut MatchState<'_>,
                                        ) = (pattern, &content, state);
                                        let inlined_result: Option<Option<String>> = {
                                            'inlined_match_single_pattern: {
                                                if state.cancel.is_cancelled() {
                                                    break 'inlined_match_single_pattern None;
                                                }
                                                match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                            }
                                        };
                                        inlined_result
                                    } {
                                        let key = format!("meta:{name}:{url}");
                                        let label = format!("meta {name}");
                                        ({
                                            let (
                                                inlined_self,
                                                detections,
                                                pattern,
                                                version,
                                                context,
                                            ): (
                                                &Catalog,
                                                &mut HashMap<String, AccumulatedDetection>,
                                                &CompiledPattern,
                                                Option<String>,
                                                MatchContext<'_>,
                                            ) = (
                                                &(inlined_self),
                                                detections,
                                                pattern,
                                                version,
                                                MatchContext {
                                                    key: &key,
                                                    label: &label,
                                                    url: &url,
                                                },
                                            );

                                            let mut path = HashSet::new();
                                            inlined_self.add_recursive(
                                                detections,
                                                pattern.technology,
                                                pattern.confidence,
                                                version,
                                                &context,
                                                &mut path,
                                                None,
                                            );
                                        });
                                    }
                                }
                            }
                        }
                        for source in signals.script_sources {
                            let source = {
                                let (document_url, source): (&str, &str) = (response_url, &source);
                                let inlined_result: String = {
                                    Url::parse(document_url)
                                        .ok()
                                        .and_then(|base| base.join(source).ok())
                                        .map(|url| {
                                            let (source,): (&str,) = (url.as_str(),);
                                            let inlined_result: String = {
                                                'inlined_sanitize_url: {
                                                    let Ok(mut url) = Url::parse(source) else {
                                                        break 'inlined_sanitize_url source
                                                            .chars()
                                                            .take(512)
                                                            .collect();
                                                    };
                                                    let _ = url.set_username("");
                                                    let _ = url.set_password(None);
                                                    url.set_query(None);
                                                    url.set_fragment(None);
                                                    url.to_string()
                                                }
                                            };
                                            inlined_result
                                        })
                                        .unwrap_or_else(|| {
                                            let (source,): (&str,) = (source,);
                                            let inlined_result: String = {
                                                'inlined_sanitize_url: {
                                                    let Ok(mut url) = Url::parse(source) else {
                                                        break 'inlined_sanitize_url source
                                                            .chars()
                                                            .take(512)
                                                            .collect();
                                                    };
                                                    let _ = url.set_username("");
                                                    let _ = url.set_password(None);
                                                    url.set_query(None);
                                                    url.set_fragment(None);
                                                    url.to_string()
                                                }
                                            };
                                            inlined_result
                                        })
                                };
                                inlined_result
                            };
                            let key = format!("script-url:{source}");
                            ({
                                let (inlined_self, text, state, mut visit): (
                                    &MatcherBank,
                                    &str,
                                    &mut MatchState<'_>,
                                    _,
                                ) = (
                                    &(inlined_self.script_sources),
                                    &source,
                                    state,
                                    |pattern, version| {
                                        ({
                                            let (
                                                inlined_self,
                                                detections,
                                                pattern,
                                                version,
                                                context,
                                            ): (
                                                &Catalog,
                                                &mut HashMap<String, AccumulatedDetection>,
                                                &CompiledPattern,
                                                Option<String>,
                                                MatchContext<'_>,
                                            ) = (
                                                &(inlined_self),
                                                detections,
                                                pattern,
                                                version,
                                                MatchContext {
                                                    key: &key,
                                                    label: "script URL",
                                                    url: &source,
                                                },
                                            );

                                            let mut path = HashSet::new();
                                            inlined_self.add_recursive(
                                                detections,
                                                pattern.technology,
                                                pattern.confidence,
                                                version,
                                                &context,
                                                &mut path,
                                                None,
                                            );
                                        });
                                    },
                                );
                                'inlined_visit_matches: {
                                    if state.cancel.is_cancelled() {
                                        break 'inlined_visit_matches;
                                    }
                                    for pattern in &inlined_self.always {
                                        visit(pattern, None);
                                    }
                                    for batch in &inlined_self.batches {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        for index in batch.set.matches(text).into_iter() {
                                            let pattern = &batch.patterns[index];
                                            visit(pattern, {
                                                let (pattern, text): (&CompiledPattern, &str) =
                                                    (pattern, text);
                                                let inlined_result: Option<String> = {
                                                    'inlined_pattern_version: {
                                                        let template = match pattern
                                                            .version
                                                            .as_deref()
                                                        {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_pattern_version None;
                                                            }
                                                        };
                                                        let PatternMatcher::Standard(regex) =
                                                            &pattern.matcher
                                                        else {
                                                            break 'inlined_pattern_version None;
                                                        };
                                                        let captures = match regex.captures(text) {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_pattern_version None;
                                                            }
                                                        };
                                                        {
                                                            let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                            let inlined_result: Option<String> = {
                                                                let mut result =
                                                                    template.to_owned();
                                                                for index in 1..capture_count {
                                                                    let marker =
                                                                        format!("\\{index}");
                                                                    let value = capture(index);
                                                                    let conditional =
                                                                        format!("{marker}?");
                                                                    while let Some(start) =
                                                                        result.find(&conditional)
                                                                    {
                                                                        let branch_start = start
                                                                            + conditional.len();
                                                                        let end = result
                                                                            [branch_start..]
                                                                            .find("\\;")
                                                                            .map(|offset| {
                                                                                branch_start
                                                                                    + offset
                                                                            })
                                                                            .unwrap_or(
                                                                                result.len(),
                                                                            );
                                                                        let branch = &result
                                                                            [branch_start..end];
                                                                        let (
                                                                            when_present,
                                                                            when_missing,
                                                                        ) = branch
                                                                            .split_once(':')
                                                                            .unwrap_or((
                                                                                branch, "",
                                                                            ));
                                                                        let replacement =
                                                                            if value.is_empty() {
                                                                                when_missing
                                                                            } else {
                                                                                when_present
                                                                            }
                                                                            .to_owned();
                                                                        result.replace_range(
                                                                            start..end,
                                                                            &replacement,
                                                                        );
                                                                    }
                                                                    result = result
                                                                        .replace(&marker, value);
                                                                }
                                                                let result = result
                                                                    .trim()
                                                                    .trim_start_matches(['v', 'V'])
                                                                    .to_owned();
                                                                (!result.is_empty())
                                                                    .then_some(result)
                                                            };
                                                            inlined_result
                                                        }
                                                    }
                                                };
                                                inlined_result
                                            });
                                        }
                                    }
                                    for pattern in &inlined_self.individual {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        if let Some(version) = {
                                            let (pattern, text, state): (
                                                &CompiledPattern,
                                                &str,
                                                &mut MatchState<'_>,
                                            ) = (pattern, text, state);
                                            let inlined_result: Option<Option<String>> = {
                                                'inlined_match_single_pattern: {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_match_single_pattern None;
                                                    }
                                                    match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                }
                                            };
                                            inlined_result
                                        } {
                                            visit(pattern, version);
                                        }
                                    }
                                }
                            });
                        }
                        for (index, script) in signals.inline_scripts.into_iter().enumerate() {
                            let key = format!("inline-script:{url}:{index}");
                            ({
                                let (inlined_self, text, state, mut visit): (
                                    &MatcherBank,
                                    &str,
                                    &mut MatchState<'_>,
                                    _,
                                ) = (
                                    &(inlined_self.scripts),
                                    &script,
                                    state,
                                    |pattern, version| {
                                        ({
                                            let (
                                                inlined_self,
                                                detections,
                                                pattern,
                                                version,
                                                context,
                                            ): (
                                                &Catalog,
                                                &mut HashMap<String, AccumulatedDetection>,
                                                &CompiledPattern,
                                                Option<String>,
                                                MatchContext<'_>,
                                            ) = (
                                                &(inlined_self),
                                                detections,
                                                pattern,
                                                version,
                                                MatchContext {
                                                    key: &key,
                                                    label: "inline script content",
                                                    url: &url,
                                                },
                                            );

                                            let mut path = HashSet::new();
                                            inlined_self.add_recursive(
                                                detections,
                                                pattern.technology,
                                                pattern.confidence,
                                                version,
                                                &context,
                                                &mut path,
                                                None,
                                            );
                                        });
                                    },
                                );
                                'inlined_visit_matches: {
                                    if state.cancel.is_cancelled() {
                                        break 'inlined_visit_matches;
                                    }
                                    for pattern in &inlined_self.always {
                                        visit(pattern, None);
                                    }
                                    for batch in &inlined_self.batches {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        for index in batch.set.matches(text).into_iter() {
                                            let pattern = &batch.patterns[index];
                                            visit(pattern, {
                                                let (pattern, text): (&CompiledPattern, &str) =
                                                    (pattern, text);
                                                let inlined_result: Option<String> = {
                                                    'inlined_pattern_version: {
                                                        let template = match pattern
                                                            .version
                                                            .as_deref()
                                                        {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_pattern_version None;
                                                            }
                                                        };
                                                        let PatternMatcher::Standard(regex) =
                                                            &pattern.matcher
                                                        else {
                                                            break 'inlined_pattern_version None;
                                                        };
                                                        let captures = match regex.captures(text) {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_pattern_version None;
                                                            }
                                                        };
                                                        {
                                                            let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                            let inlined_result: Option<String> = {
                                                                let mut result =
                                                                    template.to_owned();
                                                                for index in 1..capture_count {
                                                                    let marker =
                                                                        format!("\\{index}");
                                                                    let value = capture(index);
                                                                    let conditional =
                                                                        format!("{marker}?");
                                                                    while let Some(start) =
                                                                        result.find(&conditional)
                                                                    {
                                                                        let branch_start = start
                                                                            + conditional.len();
                                                                        let end = result
                                                                            [branch_start..]
                                                                            .find("\\;")
                                                                            .map(|offset| {
                                                                                branch_start
                                                                                    + offset
                                                                            })
                                                                            .unwrap_or(
                                                                                result.len(),
                                                                            );
                                                                        let branch = &result
                                                                            [branch_start..end];
                                                                        let (
                                                                            when_present,
                                                                            when_missing,
                                                                        ) = branch
                                                                            .split_once(':')
                                                                            .unwrap_or((
                                                                                branch, "",
                                                                            ));
                                                                        let replacement =
                                                                            if value.is_empty() {
                                                                                when_missing
                                                                            } else {
                                                                                when_present
                                                                            }
                                                                            .to_owned();
                                                                        result.replace_range(
                                                                            start..end,
                                                                            &replacement,
                                                                        );
                                                                    }
                                                                    result = result
                                                                        .replace(&marker, value);
                                                                }
                                                                let result = result
                                                                    .trim()
                                                                    .trim_start_matches(['v', 'V'])
                                                                    .to_owned();
                                                                (!result.is_empty())
                                                                    .then_some(result)
                                                            };
                                                            inlined_result
                                                        }
                                                    }
                                                };
                                                inlined_result
                                            });
                                        }
                                    }
                                    for pattern in &inlined_self.individual {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        if let Some(version) = {
                                            let (pattern, text, state): (
                                                &CompiledPattern,
                                                &str,
                                                &mut MatchState<'_>,
                                            ) = (pattern, text, state);
                                            let inlined_result: Option<Option<String>> = {
                                                'inlined_match_single_pattern: {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_match_single_pattern None;
                                                    }
                                                    match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                }
                                            };
                                            inlined_result
                                        } {
                                            visit(pattern, version);
                                        }
                                    }
                                }
                            });
                        }
                    }
                });
            }
            completed += 1;
            ({
                let (progress, completed, total, text): (
                    &Option<Sender<ExposureScanProgress>>,
                    usize,
                    usize,
                    String,
                ) = (
                    progress,
                    completed,
                    work_total,
                    format!(
                        "HTTP response: {}",
                        ({
                            let (source,): (&str,) = (&response.url,);
                            let inlined_result: String = {
                                'inlined_sanitize_url: {
                                    let Ok(mut url) = Url::parse(source) else {
                                        break 'inlined_sanitize_url source
                                            .chars()
                                            .take(512)
                                            .collect();
                                    };
                                    let _ = url.set_username("");
                                    let _ = url.set_password(None);
                                    url.set_query(None);
                                    url.set_fragment(None);
                                    url.to_string()
                                }
                            };
                            inlined_result
                        })
                    ),
                );

                send_phase_progress(
                    progress,
                    ExposureScanPhase::Fingerprinting,
                    ExposureScanPhaseState::Running,
                    completed as f32 / total.max(1) as f32,
                    text,
                );
            });
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
            if let Some(index) = endpoints
                .iter()
                .position(|endpoint| endpoint.ip == resource.ip && endpoint.port == resource.port)
            {
                let script = resource.detected_file_types.iter().any(|item| {
                    matches!(
                        item.file_type,
                        TechnologyFileType::JavaScript
                            | TechnologyFileType::Jsx
                            | TechnologyFileType::TypeScript
                            | TechnologyFileType::Tsx
                    )
                });
                for (catalog, state) in catalogs.iter().zip(&mut match_states) {
                    ({
                        let (
                            inlined_self,
                            detections,
                            response_url,
                            status,
                            response_headers,
                            body,
                            script_override,
                            state,
                        ): (
                            &Catalog,
                            &mut HashMap<String, AccumulatedDetection>,
                            &str,
                            u16,
                            &[(String, String)],
                            &[u8],
                            Option<bool>,
                            &mut MatchState<'_>,
                        ) = (
                            &(catalog),
                            &mut accumulated[index],
                            &resource.url,
                            200,
                            &resource.headers,
                            &resource.body,
                            Some(script),
                            state,
                        );
                        'inlined_scan_response: {
                            if state.cancel.is_cancelled() {
                                break 'inlined_scan_response;
                            }
                            let url = {
                                let (source,): (&str,) = (response_url,);
                                let inlined_result: String = {
                                    'inlined_sanitize_url: {
                                        let Ok(mut url) = Url::parse(source) else {
                                            break 'inlined_sanitize_url source
                                                .chars()
                                                .take(512)
                                                .collect();
                                        };
                                        let _ = url.set_username("");
                                        let _ = url.set_password(None);
                                        url.set_query(None);
                                        url.set_fragment(None);
                                        url.to_string()
                                    }
                                };
                                inlined_result
                            };
                            let mut headers = HashMap::<String, Vec<&str>>::new();
                            for (name, value) in response_headers {
                                headers
                                    .entry(name.to_ascii_lowercase())
                                    .or_default()
                                    .push(value);
                            }
                            for (name, values) in &headers {
                                let combined = values.join(", ");
                                if let Some(patterns) = inlined_self.headers.get(name) {
                                    for pattern in patterns {
                                        if let Some(version) = {
                                            let (pattern, text, state): (
                                                &CompiledPattern,
                                                &str,
                                                &mut MatchState<'_>,
                                            ) = (pattern, &combined, state);
                                            let inlined_result: Option<Option<String>> = {
                                                'inlined_match_single_pattern: {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_match_single_pattern None;
                                                    }
                                                    match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                }
                                            };
                                            inlined_result
                                        } {
                                            let key = format!("header:{name}:{url}");
                                            let label = format!("header {name}");
                                            ({
                                                let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                                key: &key,
                                label: &label,
                                url: &url,
                            },);

                                                let mut path = HashSet::new();
                                                inlined_self.add_recursive(
                                                    detections,
                                                    pattern.technology,
                                                    pattern.confidence,
                                                    version,
                                                    &context,
                                                    &mut path,
                                                    None,
                                                );
                                            });
                                        }
                                    }
                                }
                            }
                            for value in headers.get("set-cookie").into_iter().flatten() {
                                if let Some((name, cookie_value)) = ({
                                    let (value,): (&str,) = (value,);
                                    {
                                        'inlined_cookie_name_value: {
                                            let pair = match value.split(';').next() {
                                                Some(value) => value,
                                                None => break 'inlined_cookie_name_value None,
                                            }
                                            .trim();
                                            let (name, value) = match pair.split_once('=') {
                                                Some(value) => value,
                                                None => break 'inlined_cookie_name_value None,
                                            };
                                            let name = name.trim().to_ascii_lowercase();
                                            (!name.is_empty()).then_some((name, value.trim()))
                                        }
                                    }
                                }) && let Some(patterns) = inlined_self.cookies.get(&name)
                                {
                                    for pattern in patterns {
                                        if let Some(version) = {
                                            let (pattern, text, state): (
                                                &CompiledPattern,
                                                &str,
                                                &mut MatchState<'_>,
                                            ) = (pattern, cookie_value, state);
                                            let inlined_result: Option<Option<String>> = {
                                                'inlined_match_single_pattern: {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_match_single_pattern None;
                                                    }
                                                    match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                }
                                            };
                                            inlined_result
                                        } {
                                            let key = format!("cookie:{name}:{url}");
                                            let label = format!("cookie {name}");
                                            ({
                                                let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                                key: &key,
                                label: &label,
                                url: &url,
                            },);

                                                let mut path = HashSet::new();
                                                inlined_self.add_recursive(
                                                    detections,
                                                    pattern.technology,
                                                    pattern.confidence,
                                                    version,
                                                    &context,
                                                    &mut path,
                                                    None,
                                                );
                                            });
                                        }
                                    }
                                }
                            }
                            let text = String::from_utf8_lossy(body);
                            let is_script = script_override.unwrap_or_else(|| {
                                let (url, headers): (&str, &[(String, String)]) =
                                    (response_url, response_headers);
                                {
                                    headers.iter().any(|(name, value)| {
                                        name.eq_ignore_ascii_case("content-type") && {
                                            let value = value.to_ascii_lowercase();
                                            value.contains("javascript")
                                                || value.contains("ecmascript")
                                        }
                                    }) || Url::parse(url).ok().is_some_and(|url| {
                                        url.path().to_ascii_lowercase().ends_with(".js")
                                    })
                                }
                            });
                            if is_script {
                                if (200..300).contains(&status) {
                                    let key = format!("script-content:{url}");
                                    ({
                                        let (inlined_self, text, state, mut visit): (
                                            &MatcherBank,
                                            &str,
                                            &mut MatchState<'_>,
                                            _,
                                        ) = (
                                            &(inlined_self.scripts),
                                            &text,
                                            state,
                                            |pattern, version| {
                                                ({
                                                    let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                                key: &key,
                                label: "external script content",
                                url: &url,
                            },);

                                                    let mut path = HashSet::new();
                                                    inlined_self.add_recursive(
                                                        detections,
                                                        pattern.technology,
                                                        pattern.confidence,
                                                        version,
                                                        &context,
                                                        &mut path,
                                                        None,
                                                    );
                                                });
                                            },
                                        );
                                        'inlined_visit_matches: {
                                            if state.cancel.is_cancelled() {
                                                break 'inlined_visit_matches;
                                            }
                                            for pattern in &inlined_self.always {
                                                visit(pattern, None);
                                            }
                                            for batch in &inlined_self.batches {
                                                if state.cancel.is_cancelled() {
                                                    break 'inlined_visit_matches;
                                                }
                                                for index in batch.set.matches(text).into_iter() {
                                                    let pattern = &batch.patterns[index];
                                                    visit(pattern, {
                                                        let (pattern, text): (
                                                            &CompiledPattern,
                                                            &str,
                                                        ) = (pattern, text);
                                                        let inlined_result: Option<String> = {
                                                            'inlined_pattern_version: {
                                                                let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
                                                                let PatternMatcher::Standard(regex) =
                                                                    &pattern.matcher
                                                                else {
                                                                    break 'inlined_pattern_version None;
                                                                };
                                                                let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
                                                                {
                                                                    let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                                    let inlined_result: Option<
                                                                        String,
                                                                    > = {
                                                                        let mut result =
                                                                            template.to_owned();
                                                                        for index in
                                                                            1..capture_count
                                                                        {
                                                                            let marker = format!(
                                                                                "\\{index}"
                                                                            );
                                                                            let value =
                                                                                capture(index);
                                                                            let conditional = format!(
                                                                                "{marker}?"
                                                                            );
                                                                            while let Some(start) =
                                                                                result.find(
                                                                                    &conditional,
                                                                                )
                                                                            {
                                                                                let branch_start = start + conditional.len();
                                                                                let end = result[branch_start..]
                .find("\\;")
                .map(|offset| branch_start + offset)
                .unwrap_or(result.len());
                                                                                let branch = &result[branch_start..end];
                                                                                let (
                                                                                    when_present,
                                                                                    when_missing,
                                                                                ) = branch
                                                                                    .split_once(':')
                                                                                    .unwrap_or((
                                                                                        branch, "",
                                                                                    ));
                                                                                let replacement =
                                                                                    if value
                                                                                        .is_empty()
                                                                                    {
                                                                                        when_missing
                                                                                    } else {
                                                                                        when_present
                                                                                    }
                                                                                    .to_owned();
                                                                                result
                                                                                    .replace_range(
                                                                                    start..end,
                                                                                    &replacement,
                                                                                );
                                                                            }
                                                                            result = result
                                                                                .replace(
                                                                                    &marker, value,
                                                                                );
                                                                        }
                                                                        let result = result
                                                                            .trim()
                                                                            .trim_start_matches([
                                                                                'v', 'V',
                                                                            ])
                                                                            .to_owned();
                                                                        (!result.is_empty())
                                                                            .then_some(result)
                                                                    };
                                                                    inlined_result
                                                                }
                                                            }
                                                        };
                                                        inlined_result
                                                    });
                                                }
                                            }
                                            for pattern in &inlined_self.individual {
                                                if state.cancel.is_cancelled() {
                                                    break 'inlined_visit_matches;
                                                }
                                                if let Some(version) = {
                                                    let (pattern, text, state): (
                                                        &CompiledPattern,
                                                        &str,
                                                        &mut MatchState<'_>,
                                                    ) = (pattern, text, state);
                                                    let inlined_result: Option<Option<String>> = {
                                                        'inlined_match_single_pattern: {
                                                            if state.cancel.is_cancelled() {
                                                                break 'inlined_match_single_pattern None;
                                                            }
                                                            match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                        }
                                                    };
                                                    inlined_result
                                                } {
                                                    visit(pattern, version);
                                                }
                                            }
                                        }
                                    });
                                }
                                let key = format!("script-url:{url}");
                                ({
                                    let (inlined_self, text, state, mut visit): (
                                        &MatcherBank,
                                        &str,
                                        &mut MatchState<'_>,
                                        _,
                                    ) = (
                                        &(inlined_self.script_sources),
                                        &url,
                                        state,
                                        |pattern, version| {
                                            ({
                                                let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                            key: &key,
                            label: "script URL",
                            url: &url,
                        },);

                                                let mut path = HashSet::new();
                                                inlined_self.add_recursive(
                                                    detections,
                                                    pattern.technology,
                                                    pattern.confidence,
                                                    version,
                                                    &context,
                                                    &mut path,
                                                    None,
                                                );
                                            });
                                        },
                                    );
                                    'inlined_visit_matches: {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        for pattern in &inlined_self.always {
                                            visit(pattern, None);
                                        }
                                        for batch in &inlined_self.batches {
                                            if state.cancel.is_cancelled() {
                                                break 'inlined_visit_matches;
                                            }
                                            for index in batch.set.matches(text).into_iter() {
                                                let pattern = &batch.patterns[index];
                                                visit(pattern, {
                                                    let (pattern, text): (&CompiledPattern, &str) =
                                                        (pattern, text);
                                                    let inlined_result: Option<String> = {
                                                        'inlined_pattern_version: {
                                                            let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
                                                            let PatternMatcher::Standard(regex) =
                                                                &pattern.matcher
                                                            else {
                                                                break 'inlined_pattern_version None;
                                                            };
                                                            let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
                                                            {
                                                                let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                                let inlined_result: Option<String> = {
                                                                    let mut result =
                                                                        template.to_owned();
                                                                    for index in 1..capture_count {
                                                                        let marker =
                                                                            format!("\\{index}");
                                                                        let value = capture(index);
                                                                        let conditional =
                                                                            format!("{marker}?");
                                                                        while let Some(start) =
                                                                            result
                                                                                .find(&conditional)
                                                                        {
                                                                            let branch_start = start
                                                                                + conditional.len();
                                                                            let end = result
                                                                                [branch_start..]
                                                                                .find("\\;")
                                                                                .map(|offset| {
                                                                                    branch_start
                                                                                        + offset
                                                                                })
                                                                                .unwrap_or(
                                                                                    result.len(),
                                                                                );
                                                                            let branch = &result
                                                                                [branch_start..end];
                                                                            let (
                                                                                when_present,
                                                                                when_missing,
                                                                            ) = branch
                                                                                .split_once(':')
                                                                                .unwrap_or((
                                                                                    branch, "",
                                                                                ));
                                                                            let replacement =
                                                                                if value.is_empty()
                                                                                {
                                                                                    when_missing
                                                                                } else {
                                                                                    when_present
                                                                                }
                                                                                .to_owned();
                                                                            result.replace_range(
                                                                                start..end,
                                                                                &replacement,
                                                                            );
                                                                        }
                                                                        result = result.replace(
                                                                            &marker, value,
                                                                        );
                                                                    }
                                                                    let result = result
                                                                        .trim()
                                                                        .trim_start_matches([
                                                                            'v', 'V',
                                                                        ])
                                                                        .to_owned();
                                                                    (!result.is_empty())
                                                                        .then_some(result)
                                                                };
                                                                inlined_result
                                                            }
                                                        }
                                                    };
                                                    inlined_result
                                                });
                                            }
                                        }
                                        for pattern in &inlined_self.individual {
                                            if state.cancel.is_cancelled() {
                                                break 'inlined_visit_matches;
                                            }
                                            if let Some(version) = {
                                                let (pattern, text, state): (
                                                    &CompiledPattern,
                                                    &str,
                                                    &mut MatchState<'_>,
                                                ) = (pattern, text, state);
                                                let inlined_result: Option<Option<String>> = {
                                                    'inlined_match_single_pattern: {
                                                        if state.cancel.is_cancelled() {
                                                            break 'inlined_match_single_pattern None;
                                                        }
                                                        match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                    }
                                                };
                                                inlined_result
                                            } {
                                                visit(pattern, version);
                                            }
                                        }
                                    }
                                });
                                break 'inlined_scan_response;
                            }
                            let html_key = format!("html:{url}");
                            ({
                                let (inlined_self, text, state, mut visit): (
                                    &MatcherBank,
                                    &str,
                                    &mut MatchState<'_>,
                                    _,
                                ) = (&(inlined_self.html), &text, state, |pattern, version| {
                                    ({
                                        let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                    key: &html_key,
                    label: "HTML signature",
                    url: &url,
                },);

                                        let mut path = HashSet::new();
                                        inlined_self.add_recursive(
                                            detections,
                                            pattern.technology,
                                            pattern.confidence,
                                            version,
                                            &context,
                                            &mut path,
                                            None,
                                        );
                                    });
                                });
                                'inlined_visit_matches: {
                                    if state.cancel.is_cancelled() {
                                        break 'inlined_visit_matches;
                                    }
                                    for pattern in &inlined_self.always {
                                        visit(pattern, None);
                                    }
                                    for batch in &inlined_self.batches {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        for index in batch.set.matches(text).into_iter() {
                                            let pattern = &batch.patterns[index];
                                            visit(pattern, {
                                                let (pattern, text): (&CompiledPattern, &str) =
                                                    (pattern, text);
                                                let inlined_result: Option<String> = {
                                                    'inlined_pattern_version: {
                                                        let template = match pattern
                                                            .version
                                                            .as_deref()
                                                        {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_pattern_version None;
                                                            }
                                                        };
                                                        let PatternMatcher::Standard(regex) =
                                                            &pattern.matcher
                                                        else {
                                                            break 'inlined_pattern_version None;
                                                        };
                                                        let captures = match regex.captures(text) {
                                                            Some(value) => value,
                                                            None => {
                                                                break 'inlined_pattern_version None;
                                                            }
                                                        };
                                                        {
                                                            let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                            let inlined_result: Option<String> = {
                                                                let mut result =
                                                                    template.to_owned();
                                                                for index in 1..capture_count {
                                                                    let marker =
                                                                        format!("\\{index}");
                                                                    let value = capture(index);
                                                                    let conditional =
                                                                        format!("{marker}?");
                                                                    while let Some(start) =
                                                                        result.find(&conditional)
                                                                    {
                                                                        let branch_start = start
                                                                            + conditional.len();
                                                                        let end = result
                                                                            [branch_start..]
                                                                            .find("\\;")
                                                                            .map(|offset| {
                                                                                branch_start
                                                                                    + offset
                                                                            })
                                                                            .unwrap_or(
                                                                                result.len(),
                                                                            );
                                                                        let branch = &result
                                                                            [branch_start..end];
                                                                        let (
                                                                            when_present,
                                                                            when_missing,
                                                                        ) = branch
                                                                            .split_once(':')
                                                                            .unwrap_or((
                                                                                branch, "",
                                                                            ));
                                                                        let replacement =
                                                                            if value.is_empty() {
                                                                                when_missing
                                                                            } else {
                                                                                when_present
                                                                            }
                                                                            .to_owned();
                                                                        result.replace_range(
                                                                            start..end,
                                                                            &replacement,
                                                                        );
                                                                    }
                                                                    result = result
                                                                        .replace(&marker, value);
                                                                }
                                                                let result = result
                                                                    .trim()
                                                                    .trim_start_matches(['v', 'V'])
                                                                    .to_owned();
                                                                (!result.is_empty())
                                                                    .then_some(result)
                                                            };
                                                            inlined_result
                                                        }
                                                    }
                                                };
                                                inlined_result
                                            });
                                        }
                                    }
                                    for pattern in &inlined_self.individual {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        if let Some(version) = {
                                            let (pattern, text, state): (
                                                &CompiledPattern,
                                                &str,
                                                &mut MatchState<'_>,
                                            ) = (pattern, text, state);
                                            let inlined_result: Option<Option<String>> = {
                                                'inlined_match_single_pattern: {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_match_single_pattern None;
                                                    }
                                                    match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                }
                                            };
                                            inlined_result
                                        } {
                                            visit(pattern, version);
                                        }
                                    }
                                }
                            });
                            let signals = {
                                let (text,): (&str,) = (&text,);
                                let inlined_result: HtmlSignals = {
                                    let input = BufferQueue::default();
                                    input.push_back(StrTendril::from(text));
                                    let tokenizer =
                                        Tokenizer::new(HtmlSink::default(), Default::default());
                                    let _ = tokenizer.feed(&input);
                                    tokenizer.end();
                                    tokenizer.sink.0.into_inner().signals
                                };
                                inlined_result
                            };
                            for (name, content) in signals.meta {
                                if let Some(patterns) = inlined_self.meta.get(&name) {
                                    for pattern in patterns {
                                        if let Some(version) = {
                                            let (pattern, text, state): (
                                                &CompiledPattern,
                                                &str,
                                                &mut MatchState<'_>,
                                            ) = (pattern, &content, state);
                                            let inlined_result: Option<Option<String>> = {
                                                'inlined_match_single_pattern: {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_match_single_pattern None;
                                                    }
                                                    match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                }
                                            };
                                            inlined_result
                                        } {
                                            let key = format!("meta:{name}:{url}");
                                            let label = format!("meta {name}");
                                            ({
                                                let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                                key: &key,
                                label: &label,
                                url: &url,
                            },);

                                                let mut path = HashSet::new();
                                                inlined_self.add_recursive(
                                                    detections,
                                                    pattern.technology,
                                                    pattern.confidence,
                                                    version,
                                                    &context,
                                                    &mut path,
                                                    None,
                                                );
                                            });
                                        }
                                    }
                                }
                            }
                            for source in signals.script_sources {
                                let source = {
                                    let (document_url, source): (&str, &str) =
                                        (response_url, &source);
                                    let inlined_result: String = {
                                        Url::parse(document_url)
                                            .ok()
                                            .and_then(|base| base.join(source).ok())
                                            .map(|url| {
                                                let (source,): (&str,) = (url.as_str(),);
                                                let inlined_result: String = {
                                                    'inlined_sanitize_url: {
                                                        let Ok(mut url) = Url::parse(source) else {
                                                            break 'inlined_sanitize_url source
                                                                .chars()
                                                                .take(512)
                                                                .collect();
                                                        };
                                                        let _ = url.set_username("");
                                                        let _ = url.set_password(None);
                                                        url.set_query(None);
                                                        url.set_fragment(None);
                                                        url.to_string()
                                                    }
                                                };
                                                inlined_result
                                            })
                                            .unwrap_or_else(|| {
                                                let (source,): (&str,) = (source,);
                                                let inlined_result: String = {
                                                    'inlined_sanitize_url: {
                                                        let Ok(mut url) = Url::parse(source) else {
                                                            break 'inlined_sanitize_url source
                                                                .chars()
                                                                .take(512)
                                                                .collect();
                                                        };
                                                        let _ = url.set_username("");
                                                        let _ = url.set_password(None);
                                                        url.set_query(None);
                                                        url.set_fragment(None);
                                                        url.to_string()
                                                    }
                                                };
                                                inlined_result
                                            })
                                    };
                                    inlined_result
                                };
                                let key = format!("script-url:{source}");
                                ({
                                    let (inlined_self, text, state, mut visit): (
                                        &MatcherBank,
                                        &str,
                                        &mut MatchState<'_>,
                                        _,
                                    ) = (
                                        &(inlined_self.script_sources),
                                        &source,
                                        state,
                                        |pattern, version| {
                                            ({
                                                let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                            key: &key,
                            label: "script URL",
                            url: &source,
                        },);

                                                let mut path = HashSet::new();
                                                inlined_self.add_recursive(
                                                    detections,
                                                    pattern.technology,
                                                    pattern.confidence,
                                                    version,
                                                    &context,
                                                    &mut path,
                                                    None,
                                                );
                                            });
                                        },
                                    );
                                    'inlined_visit_matches: {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        for pattern in &inlined_self.always {
                                            visit(pattern, None);
                                        }
                                        for batch in &inlined_self.batches {
                                            if state.cancel.is_cancelled() {
                                                break 'inlined_visit_matches;
                                            }
                                            for index in batch.set.matches(text).into_iter() {
                                                let pattern = &batch.patterns[index];
                                                visit(pattern, {
                                                    let (pattern, text): (&CompiledPattern, &str) =
                                                        (pattern, text);
                                                    let inlined_result: Option<String> = {
                                                        'inlined_pattern_version: {
                                                            let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
                                                            let PatternMatcher::Standard(regex) =
                                                                &pattern.matcher
                                                            else {
                                                                break 'inlined_pattern_version None;
                                                            };
                                                            let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
                                                            {
                                                                let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                                let inlined_result: Option<String> = {
                                                                    let mut result =
                                                                        template.to_owned();
                                                                    for index in 1..capture_count {
                                                                        let marker =
                                                                            format!("\\{index}");
                                                                        let value = capture(index);
                                                                        let conditional =
                                                                            format!("{marker}?");
                                                                        while let Some(start) =
                                                                            result
                                                                                .find(&conditional)
                                                                        {
                                                                            let branch_start = start
                                                                                + conditional.len();
                                                                            let end = result
                                                                                [branch_start..]
                                                                                .find("\\;")
                                                                                .map(|offset| {
                                                                                    branch_start
                                                                                        + offset
                                                                                })
                                                                                .unwrap_or(
                                                                                    result.len(),
                                                                                );
                                                                            let branch = &result
                                                                                [branch_start..end];
                                                                            let (
                                                                                when_present,
                                                                                when_missing,
                                                                            ) = branch
                                                                                .split_once(':')
                                                                                .unwrap_or((
                                                                                    branch, "",
                                                                                ));
                                                                            let replacement =
                                                                                if value.is_empty()
                                                                                {
                                                                                    when_missing
                                                                                } else {
                                                                                    when_present
                                                                                }
                                                                                .to_owned();
                                                                            result.replace_range(
                                                                                start..end,
                                                                                &replacement,
                                                                            );
                                                                        }
                                                                        result = result.replace(
                                                                            &marker, value,
                                                                        );
                                                                    }
                                                                    let result = result
                                                                        .trim()
                                                                        .trim_start_matches([
                                                                            'v', 'V',
                                                                        ])
                                                                        .to_owned();
                                                                    (!result.is_empty())
                                                                        .then_some(result)
                                                                };
                                                                inlined_result
                                                            }
                                                        }
                                                    };
                                                    inlined_result
                                                });
                                            }
                                        }
                                        for pattern in &inlined_self.individual {
                                            if state.cancel.is_cancelled() {
                                                break 'inlined_visit_matches;
                                            }
                                            if let Some(version) = {
                                                let (pattern, text, state): (
                                                    &CompiledPattern,
                                                    &str,
                                                    &mut MatchState<'_>,
                                                ) = (pattern, text, state);
                                                let inlined_result: Option<Option<String>> = {
                                                    'inlined_match_single_pattern: {
                                                        if state.cancel.is_cancelled() {
                                                            break 'inlined_match_single_pattern None;
                                                        }
                                                        match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                    }
                                                };
                                                inlined_result
                                            } {
                                                visit(pattern, version);
                                            }
                                        }
                                    }
                                });
                            }
                            for (index, script) in signals.inline_scripts.into_iter().enumerate() {
                                let key = format!("inline-script:{url}:{index}");
                                ({
                                    let (inlined_self, text, state, mut visit): (
                                        &MatcherBank,
                                        &str,
                                        &mut MatchState<'_>,
                                        _,
                                    ) = (
                                        &(inlined_self.scripts),
                                        &script,
                                        state,
                                        |pattern, version| {
                                            ({
                                                let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                            key: &key,
                            label: "inline script content",
                            url: &url,
                        },);

                                                let mut path = HashSet::new();
                                                inlined_self.add_recursive(
                                                    detections,
                                                    pattern.technology,
                                                    pattern.confidence,
                                                    version,
                                                    &context,
                                                    &mut path,
                                                    None,
                                                );
                                            });
                                        },
                                    );
                                    'inlined_visit_matches: {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        for pattern in &inlined_self.always {
                                            visit(pattern, None);
                                        }
                                        for batch in &inlined_self.batches {
                                            if state.cancel.is_cancelled() {
                                                break 'inlined_visit_matches;
                                            }
                                            for index in batch.set.matches(text).into_iter() {
                                                let pattern = &batch.patterns[index];
                                                visit(pattern, {
                                                    let (pattern, text): (&CompiledPattern, &str) =
                                                        (pattern, text);
                                                    let inlined_result: Option<String> = {
                                                        'inlined_pattern_version: {
                                                            let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
                                                            let PatternMatcher::Standard(regex) =
                                                                &pattern.matcher
                                                            else {
                                                                break 'inlined_pattern_version None;
                                                            };
                                                            let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
                                                            {
                                                                let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                                let inlined_result: Option<String> = {
                                                                    let mut result =
                                                                        template.to_owned();
                                                                    for index in 1..capture_count {
                                                                        let marker =
                                                                            format!("\\{index}");
                                                                        let value = capture(index);
                                                                        let conditional =
                                                                            format!("{marker}?");
                                                                        while let Some(start) =
                                                                            result
                                                                                .find(&conditional)
                                                                        {
                                                                            let branch_start = start
                                                                                + conditional.len();
                                                                            let end = result
                                                                                [branch_start..]
                                                                                .find("\\;")
                                                                                .map(|offset| {
                                                                                    branch_start
                                                                                        + offset
                                                                                })
                                                                                .unwrap_or(
                                                                                    result.len(),
                                                                                );
                                                                            let branch = &result
                                                                                [branch_start..end];
                                                                            let (
                                                                                when_present,
                                                                                when_missing,
                                                                            ) = branch
                                                                                .split_once(':')
                                                                                .unwrap_or((
                                                                                    branch, "",
                                                                                ));
                                                                            let replacement =
                                                                                if value.is_empty()
                                                                                {
                                                                                    when_missing
                                                                                } else {
                                                                                    when_present
                                                                                }
                                                                                .to_owned();
                                                                            result.replace_range(
                                                                                start..end,
                                                                                &replacement,
                                                                            );
                                                                        }
                                                                        result = result.replace(
                                                                            &marker, value,
                                                                        );
                                                                    }
                                                                    let result = result
                                                                        .trim()
                                                                        .trim_start_matches([
                                                                            'v', 'V',
                                                                        ])
                                                                        .to_owned();
                                                                    (!result.is_empty())
                                                                        .then_some(result)
                                                                };
                                                                inlined_result
                                                            }
                                                        }
                                                    };
                                                    inlined_result
                                                });
                                            }
                                        }
                                        for pattern in &inlined_self.individual {
                                            if state.cancel.is_cancelled() {
                                                break 'inlined_visit_matches;
                                            }
                                            if let Some(version) = {
                                                let (pattern, text, state): (
                                                    &CompiledPattern,
                                                    &str,
                                                    &mut MatchState<'_>,
                                                ) = (pattern, text, state);
                                                let inlined_result: Option<Option<String>> = {
                                                    'inlined_match_single_pattern: {
                                                        if state.cancel.is_cancelled() {
                                                            break 'inlined_match_single_pattern None;
                                                        }
                                                        match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                    }
                                                };
                                                inlined_result
                                            } {
                                                visit(pattern, version);
                                            }
                                        }
                                    }
                                });
                            }
                        }
                    });
                }
            }
            completed += 1;
            ({
                let (progress, completed, total, text): (
                    &Option<Sender<ExposureScanProgress>>,
                    usize,
                    usize,
                    String,
                ) = (
                    progress,
                    completed,
                    work_total,
                    format!(
                        "Resource: {}",
                        ({
                            let (source,): (&str,) = (&resource.url,);
                            let inlined_result: String = {
                                'inlined_sanitize_url: {
                                    let Ok(mut url) = Url::parse(source) else {
                                        break 'inlined_sanitize_url source
                                            .chars()
                                            .take(512)
                                            .collect();
                                    };
                                    let _ = url.set_username("");
                                    let _ = url.set_password(None);
                                    url.set_query(None);
                                    url.set_fragment(None);
                                    url.to_string()
                                }
                            };
                            inlined_result
                        })
                    ),
                );

                send_phase_progress(
                    progress,
                    ExposureScanPhase::Fingerprinting,
                    ExposureScanPhaseState::Running,
                    completed as f32 / total.max(1) as f32,
                    text,
                );
            });
        }
    }
    if !cancel.is_cancelled() {
        'scripts: for script in scripts {
            for &endpoint_index in &script.endpoint_indices {
                if cancel.is_cancelled() {
                    break 'scripts;
                }
                if let Some(target) = accumulated.get_mut(endpoint_index) {
                    for (catalog, state) in catalogs.iter().zip(&mut match_states) {
                        ({
                            let (inlined_self, detections, source_url, response, state): (
                                &Catalog,
                                &mut HashMap<String, AccumulatedDetection>,
                                &str,
                                &HttpObservation,
                                &mut MatchState<'_>,
                            ) = (
                                &(catalog),
                                target,
                                &script.source_url,
                                &script.response,
                                state,
                            );

                            let source = {
                                let (source,): (&str,) = (source_url,);
                                let inlined_result: String = {
                                    'inlined_sanitize_url: {
                                        let Ok(mut url) = Url::parse(source) else {
                                            break 'inlined_sanitize_url source
                                                .chars()
                                                .take(512)
                                                .collect();
                                        };
                                        let _ = url.set_username("");
                                        let _ = url.set_password(None);
                                        url.set_query(None);
                                        url.set_fragment(None);
                                        url.to_string()
                                    }
                                };
                                inlined_result
                            };
                            let response_url = {
                                let (source,): (&str,) = (&response.url,);
                                let inlined_result: String = {
                                    'inlined_sanitize_url: {
                                        let Ok(mut url) = Url::parse(source) else {
                                            break 'inlined_sanitize_url source
                                                .chars()
                                                .take(512)
                                                .collect();
                                        };
                                        let _ = url.set_username("");
                                        let _ = url.set_password(None);
                                        url.set_query(None);
                                        url.set_fragment(None);
                                        url.to_string()
                                    }
                                };
                                inlined_result
                            };
                            ({
                                let (
                                    inlined_self,
                                    detections,
                                    response_url,
                                    status,
                                    response_headers,
                                    body,
                                    script_override,
                                    state,
                                ): (
                                    &Catalog,
                                    &mut HashMap<String, AccumulatedDetection>,
                                    &str,
                                    u16,
                                    &[(String, String)],
                                    &[u8],
                                    Option<bool>,
                                    &mut MatchState<'_>,
                                ) = (
                                    &(inlined_self),
                                    detections,
                                    &response.url,
                                    response.status,
                                    &response.headers,
                                    &response.body,
                                    Some(true),
                                    state,
                                );
                                'inlined_scan_response: {
                                    if state.cancel.is_cancelled() {
                                        break 'inlined_scan_response;
                                    }
                                    let url = {
                                        let (source,): (&str,) = (response_url,);
                                        let inlined_result: String = {
                                            'inlined_sanitize_url: {
                                                let Ok(mut url) = Url::parse(source) else {
                                                    break 'inlined_sanitize_url source
                                                        .chars()
                                                        .take(512)
                                                        .collect();
                                                };
                                                let _ = url.set_username("");
                                                let _ = url.set_password(None);
                                                url.set_query(None);
                                                url.set_fragment(None);
                                                url.to_string()
                                            }
                                        };
                                        inlined_result
                                    };
                                    let mut headers = HashMap::<String, Vec<&str>>::new();
                                    for (name, value) in response_headers {
                                        headers
                                            .entry(name.to_ascii_lowercase())
                                            .or_default()
                                            .push(value);
                                    }
                                    for (name, values) in &headers {
                                        let combined = values.join(", ");
                                        if let Some(patterns) = inlined_self.headers.get(name) {
                                            for pattern in patterns {
                                                if let Some(version) = {
                                                    let (pattern, text, state): (
                                                        &CompiledPattern,
                                                        &str,
                                                        &mut MatchState<'_>,
                                                    ) = (pattern, &combined, state);
                                                    let inlined_result: Option<Option<String>> = {
                                                        'inlined_match_single_pattern: {
                                                            if state.cancel.is_cancelled() {
                                                                break 'inlined_match_single_pattern None;
                                                            }
                                                            match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                        }
                                                    };
                                                    inlined_result
                                                } {
                                                    let key = format!("header:{name}:{url}");
                                                    let label = format!("header {name}");
                                                    ({
                                                        let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                                key: &key,
                                label: &label,
                                url: &url,
                            },);

                                                        let mut path = HashSet::new();
                                                        inlined_self.add_recursive(
                                                            detections,
                                                            pattern.technology,
                                                            pattern.confidence,
                                                            version,
                                                            &context,
                                                            &mut path,
                                                            None,
                                                        );
                                                    });
                                                }
                                            }
                                        }
                                    }
                                    for value in headers.get("set-cookie").into_iter().flatten() {
                                        if let Some((name, cookie_value)) = ({
                                            let (value,): (&str,) = (value,);
                                            {
                                                'inlined_cookie_name_value: {
                                                    let pair = match value.split(';').next() {
                                                        Some(value) => value,
                                                        None => {
                                                            break 'inlined_cookie_name_value None;
                                                        }
                                                    }
                                                    .trim();
                                                    let (name, value) = match pair.split_once('=') {
                                                        Some(value) => value,
                                                        None => {
                                                            break 'inlined_cookie_name_value None;
                                                        }
                                                    };
                                                    let name = name.trim().to_ascii_lowercase();
                                                    (!name.is_empty())
                                                        .then_some((name, value.trim()))
                                                }
                                            }
                                        }) && let Some(patterns) =
                                            inlined_self.cookies.get(&name)
                                        {
                                            for pattern in patterns {
                                                if let Some(version) = {
                                                    let (pattern, text, state): (
                                                        &CompiledPattern,
                                                        &str,
                                                        &mut MatchState<'_>,
                                                    ) = (pattern, cookie_value, state);
                                                    let inlined_result: Option<Option<String>> = {
                                                        'inlined_match_single_pattern: {
                                                            if state.cancel.is_cancelled() {
                                                                break 'inlined_match_single_pattern None;
                                                            }
                                                            match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                        }
                                                    };
                                                    inlined_result
                                                } {
                                                    let key = format!("cookie:{name}:{url}");
                                                    let label = format!("cookie {name}");
                                                    ({
                                                        let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                                key: &key,
                                label: &label,
                                url: &url,
                            },);

                                                        let mut path = HashSet::new();
                                                        inlined_self.add_recursive(
                                                            detections,
                                                            pattern.technology,
                                                            pattern.confidence,
                                                            version,
                                                            &context,
                                                            &mut path,
                                                            None,
                                                        );
                                                    });
                                                }
                                            }
                                        }
                                    }
                                    let text = String::from_utf8_lossy(body);
                                    let is_script = script_override.unwrap_or_else(|| {
                                        let (url, headers): (&str, &[(String, String)]) =
                                            (response_url, response_headers);
                                        {
                                            headers.iter().any(|(name, value)| {
                                                name.eq_ignore_ascii_case("content-type") && {
                                                    let value = value.to_ascii_lowercase();
                                                    value.contains("javascript")
                                                        || value.contains("ecmascript")
                                                }
                                            }) || Url::parse(url).ok().is_some_and(|url| {
                                                url.path().to_ascii_lowercase().ends_with(".js")
                                            })
                                        }
                                    });
                                    if is_script {
                                        if (200..300).contains(&status) {
                                            let key = format!("script-content:{url}");
                                            ({
                                                let (inlined_self, text, state, mut visit): (
                                                    &MatcherBank,
                                                    &str,
                                                    &mut MatchState<'_>,
                                                    _,
                                                ) = (
                                                    &(inlined_self.scripts),
                                                    &text,
                                                    state,
                                                    |pattern, version| {
                                                        ({
                                                            let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                                key: &key,
                                label: "external script content",
                                url: &url,
                            },);

                                                            let mut path = HashSet::new();
                                                            inlined_self.add_recursive(
                                                                detections,
                                                                pattern.technology,
                                                                pattern.confidence,
                                                                version,
                                                                &context,
                                                                &mut path,
                                                                None,
                                                            );
                                                        });
                                                    },
                                                );
                                                'inlined_visit_matches: {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_visit_matches;
                                                    }
                                                    for pattern in &inlined_self.always {
                                                        visit(pattern, None);
                                                    }
                                                    for batch in &inlined_self.batches {
                                                        if state.cancel.is_cancelled() {
                                                            break 'inlined_visit_matches;
                                                        }
                                                        for index in
                                                            batch.set.matches(text).into_iter()
                                                        {
                                                            let pattern = &batch.patterns[index];
                                                            visit(pattern, {
                                                                let (pattern, text): (
                                                                    &CompiledPattern,
                                                                    &str,
                                                                ) = (pattern, text);
                                                                let inlined_result: Option<String> = {
                                                                    'inlined_pattern_version: {
                                                                        let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
                                                                        let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
                                                                        let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
                                                                        {
                                                                            let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                                            let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
                                                                            inlined_result
                                                                        }
                                                                    }
                                                                };
                                                                inlined_result
                                                            });
                                                        }
                                                    }
                                                    for pattern in &inlined_self.individual {
                                                        if state.cancel.is_cancelled() {
                                                            break 'inlined_visit_matches;
                                                        }
                                                        if let Some(version) = {
                                                            let (pattern, text, state): (
                                                                &CompiledPattern,
                                                                &str,
                                                                &mut MatchState<'_>,
                                                            ) = (pattern, text, state);
                                                            let inlined_result: Option<
                                                                Option<String>,
                                                            > = {
                                                                'inlined_match_single_pattern: {
                                                                    if state.cancel.is_cancelled() {
                                                                        break 'inlined_match_single_pattern None;
                                                                    }
                                                                    match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                                }
                                                            };
                                                            inlined_result
                                                        } {
                                                            visit(pattern, version);
                                                        }
                                                    }
                                                }
                                            });
                                        }
                                        let key = format!("script-url:{url}");
                                        ({
                                            let (inlined_self, text, state, mut visit): (
                                                &MatcherBank,
                                                &str,
                                                &mut MatchState<'_>,
                                                _,
                                            ) = (
                                                &(inlined_self.script_sources),
                                                &url,
                                                state,
                                                |pattern, version| {
                                                    ({
                                                        let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                            key: &key,
                            label: "script URL",
                            url: &url,
                        },);

                                                        let mut path = HashSet::new();
                                                        inlined_self.add_recursive(
                                                            detections,
                                                            pattern.technology,
                                                            pattern.confidence,
                                                            version,
                                                            &context,
                                                            &mut path,
                                                            None,
                                                        );
                                                    });
                                                },
                                            );
                                            'inlined_visit_matches: {
                                                if state.cancel.is_cancelled() {
                                                    break 'inlined_visit_matches;
                                                }
                                                for pattern in &inlined_self.always {
                                                    visit(pattern, None);
                                                }
                                                for batch in &inlined_self.batches {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_visit_matches;
                                                    }
                                                    for index in batch.set.matches(text).into_iter()
                                                    {
                                                        let pattern = &batch.patterns[index];
                                                        visit(pattern, {
                                                            let (pattern, text): (
                                                                &CompiledPattern,
                                                                &str,
                                                            ) = (pattern, text);
                                                            let inlined_result: Option<String> = {
                                                                'inlined_pattern_version: {
                                                                    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
                                                                    let PatternMatcher::Standard(
                                                                        regex,
                                                                    ) = &pattern.matcher
                                                                    else {
                                                                        break 'inlined_pattern_version None;
                                                                    };
                                                                    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
                                                                    {
                                                                        let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                                        let inlined_result: Option<
                                                                            String,
                                                                        > = {
                                                                            let mut result =
                                                                                template.to_owned();
                                                                            for index in
                                                                                1..capture_count
                                                                            {
                                                                                let marker = format!(
                                                                                    "\\{index}"
                                                                                );
                                                                                let value =
                                                                                    capture(index);
                                                                                let conditional = format!(
                                                                                    "{marker}?"
                                                                                );
                                                                                while let Some(
                                                                                    start,
                                                                                ) = result
                                                                                    .find(
                                                                                    &conditional,
                                                                                ) {
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
                                                                                result = result
                                                                                    .replace(
                                                                                        &marker,
                                                                                        value,
                                                                                    );
                                                                            }
                                                                            let result = result
                                                                                .trim()
                                                                                .trim_start_matches(
                                                                                    ['v', 'V'],
                                                                                )
                                                                                .to_owned();
                                                                            (!result.is_empty())
                                                                                .then_some(result)
                                                                        };
                                                                        inlined_result
                                                                    }
                                                                }
                                                            };
                                                            inlined_result
                                                        });
                                                    }
                                                }
                                                for pattern in &inlined_self.individual {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_visit_matches;
                                                    }
                                                    if let Some(version) = {
                                                        let (pattern, text, state): (
                                                            &CompiledPattern,
                                                            &str,
                                                            &mut MatchState<'_>,
                                                        ) = (pattern, text, state);
                                                        let inlined_result: Option<Option<String>> = {
                                                            'inlined_match_single_pattern: {
                                                                if state.cancel.is_cancelled() {
                                                                    break 'inlined_match_single_pattern None;
                                                                }
                                                                match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                            }
                                                        };
                                                        inlined_result
                                                    } {
                                                        visit(pattern, version);
                                                    }
                                                }
                                            }
                                        });
                                        break 'inlined_scan_response;
                                    }
                                    let html_key = format!("html:{url}");
                                    ({
                                        let (inlined_self, text, state, mut visit): (
                                            &MatcherBank,
                                            &str,
                                            &mut MatchState<'_>,
                                            _,
                                        ) = (
                                            &(inlined_self.html),
                                            &text,
                                            state,
                                            |pattern, version| {
                                                ({
                                                    let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                    key: &html_key,
                    label: "HTML signature",
                    url: &url,
                },);

                                                    let mut path = HashSet::new();
                                                    inlined_self.add_recursive(
                                                        detections,
                                                        pattern.technology,
                                                        pattern.confidence,
                                                        version,
                                                        &context,
                                                        &mut path,
                                                        None,
                                                    );
                                                });
                                            },
                                        );
                                        'inlined_visit_matches: {
                                            if state.cancel.is_cancelled() {
                                                break 'inlined_visit_matches;
                                            }
                                            for pattern in &inlined_self.always {
                                                visit(pattern, None);
                                            }
                                            for batch in &inlined_self.batches {
                                                if state.cancel.is_cancelled() {
                                                    break 'inlined_visit_matches;
                                                }
                                                for index in batch.set.matches(text).into_iter() {
                                                    let pattern = &batch.patterns[index];
                                                    visit(pattern, {
                                                        let (pattern, text): (
                                                            &CompiledPattern,
                                                            &str,
                                                        ) = (pattern, text);
                                                        let inlined_result: Option<String> = {
                                                            'inlined_pattern_version: {
                                                                let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
                                                                let PatternMatcher::Standard(regex) =
                                                                    &pattern.matcher
                                                                else {
                                                                    break 'inlined_pattern_version None;
                                                                };
                                                                let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
                                                                {
                                                                    let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                                    let inlined_result: Option<
                                                                        String,
                                                                    > = {
                                                                        let mut result =
                                                                            template.to_owned();
                                                                        for index in
                                                                            1..capture_count
                                                                        {
                                                                            let marker = format!(
                                                                                "\\{index}"
                                                                            );
                                                                            let value =
                                                                                capture(index);
                                                                            let conditional = format!(
                                                                                "{marker}?"
                                                                            );
                                                                            while let Some(start) =
                                                                                result.find(
                                                                                    &conditional,
                                                                                )
                                                                            {
                                                                                let branch_start = start + conditional.len();
                                                                                let end = result[branch_start..]
                .find("\\;")
                .map(|offset| branch_start + offset)
                .unwrap_or(result.len());
                                                                                let branch = &result[branch_start..end];
                                                                                let (
                                                                                    when_present,
                                                                                    when_missing,
                                                                                ) = branch
                                                                                    .split_once(':')
                                                                                    .unwrap_or((
                                                                                        branch, "",
                                                                                    ));
                                                                                let replacement =
                                                                                    if value
                                                                                        .is_empty()
                                                                                    {
                                                                                        when_missing
                                                                                    } else {
                                                                                        when_present
                                                                                    }
                                                                                    .to_owned();
                                                                                result
                                                                                    .replace_range(
                                                                                    start..end,
                                                                                    &replacement,
                                                                                );
                                                                            }
                                                                            result = result
                                                                                .replace(
                                                                                    &marker, value,
                                                                                );
                                                                        }
                                                                        let result = result
                                                                            .trim()
                                                                            .trim_start_matches([
                                                                                'v', 'V',
                                                                            ])
                                                                            .to_owned();
                                                                        (!result.is_empty())
                                                                            .then_some(result)
                                                                    };
                                                                    inlined_result
                                                                }
                                                            }
                                                        };
                                                        inlined_result
                                                    });
                                                }
                                            }
                                            for pattern in &inlined_self.individual {
                                                if state.cancel.is_cancelled() {
                                                    break 'inlined_visit_matches;
                                                }
                                                if let Some(version) = {
                                                    let (pattern, text, state): (
                                                        &CompiledPattern,
                                                        &str,
                                                        &mut MatchState<'_>,
                                                    ) = (pattern, text, state);
                                                    let inlined_result: Option<Option<String>> = {
                                                        'inlined_match_single_pattern: {
                                                            if state.cancel.is_cancelled() {
                                                                break 'inlined_match_single_pattern None;
                                                            }
                                                            match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                        }
                                                    };
                                                    inlined_result
                                                } {
                                                    visit(pattern, version);
                                                }
                                            }
                                        }
                                    });
                                    let signals = {
                                        let (text,): (&str,) = (&text,);
                                        let inlined_result: HtmlSignals = {
                                            let input = BufferQueue::default();
                                            input.push_back(StrTendril::from(text));
                                            let tokenizer = Tokenizer::new(
                                                HtmlSink::default(),
                                                Default::default(),
                                            );
                                            let _ = tokenizer.feed(&input);
                                            tokenizer.end();
                                            tokenizer.sink.0.into_inner().signals
                                        };
                                        inlined_result
                                    };
                                    for (name, content) in signals.meta {
                                        if let Some(patterns) = inlined_self.meta.get(&name) {
                                            for pattern in patterns {
                                                if let Some(version) = {
                                                    let (pattern, text, state): (
                                                        &CompiledPattern,
                                                        &str,
                                                        &mut MatchState<'_>,
                                                    ) = (pattern, &content, state);
                                                    let inlined_result: Option<Option<String>> = {
                                                        'inlined_match_single_pattern: {
                                                            if state.cancel.is_cancelled() {
                                                                break 'inlined_match_single_pattern None;
                                                            }
                                                            match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                        }
                                                    };
                                                    inlined_result
                                                } {
                                                    let key = format!("meta:{name}:{url}");
                                                    let label = format!("meta {name}");
                                                    ({
                                                        let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                                key: &key,
                                label: &label,
                                url: &url,
                            },);

                                                        let mut path = HashSet::new();
                                                        inlined_self.add_recursive(
                                                            detections,
                                                            pattern.technology,
                                                            pattern.confidence,
                                                            version,
                                                            &context,
                                                            &mut path,
                                                            None,
                                                        );
                                                    });
                                                }
                                            }
                                        }
                                    }
                                    for source in signals.script_sources {
                                        let source = {
                                            let (document_url, source): (&str, &str) =
                                                (response_url, &source);
                                            let inlined_result: String = {
                                                Url::parse(document_url)
        .ok()
        .and_then(|base| base.join(source).ok())
        .map(|url| {
let (source,): (& str,) = (url.as_str(),);
let inlined_result: String = {
'inlined_sanitize_url: {

    let Ok(mut url) = Url::parse(source) else {
        break 'inlined_sanitize_url source.chars().take(512).collect();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()

}
};
inlined_result
})
        .unwrap_or_else(|| {
let (source,): (& str,) = (source,);
let inlined_result: String = {
'inlined_sanitize_url: {

    let Ok(mut url) = Url::parse(source) else {
        break 'inlined_sanitize_url source.chars().take(512).collect();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()

}
};
inlined_result
})
                                            };
                                            inlined_result
                                        };
                                        let key = format!("script-url:{source}");
                                        ({
                                            let (inlined_self, text, state, mut visit): (
                                                &MatcherBank,
                                                &str,
                                                &mut MatchState<'_>,
                                                _,
                                            ) = (
                                                &(inlined_self.script_sources),
                                                &source,
                                                state,
                                                |pattern, version| {
                                                    ({
                                                        let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                            key: &key,
                            label: "script URL",
                            url: &source,
                        },);

                                                        let mut path = HashSet::new();
                                                        inlined_self.add_recursive(
                                                            detections,
                                                            pattern.technology,
                                                            pattern.confidence,
                                                            version,
                                                            &context,
                                                            &mut path,
                                                            None,
                                                        );
                                                    });
                                                },
                                            );
                                            'inlined_visit_matches: {
                                                if state.cancel.is_cancelled() {
                                                    break 'inlined_visit_matches;
                                                }
                                                for pattern in &inlined_self.always {
                                                    visit(pattern, None);
                                                }
                                                for batch in &inlined_self.batches {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_visit_matches;
                                                    }
                                                    for index in batch.set.matches(text).into_iter()
                                                    {
                                                        let pattern = &batch.patterns[index];
                                                        visit(pattern, {
                                                            let (pattern, text): (
                                                                &CompiledPattern,
                                                                &str,
                                                            ) = (pattern, text);
                                                            let inlined_result: Option<String> = {
                                                                'inlined_pattern_version: {
                                                                    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
                                                                    let PatternMatcher::Standard(
                                                                        regex,
                                                                    ) = &pattern.matcher
                                                                    else {
                                                                        break 'inlined_pattern_version None;
                                                                    };
                                                                    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
                                                                    {
                                                                        let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                                        let inlined_result: Option<
                                                                            String,
                                                                        > = {
                                                                            let mut result =
                                                                                template.to_owned();
                                                                            for index in
                                                                                1..capture_count
                                                                            {
                                                                                let marker = format!(
                                                                                    "\\{index}"
                                                                                );
                                                                                let value =
                                                                                    capture(index);
                                                                                let conditional = format!(
                                                                                    "{marker}?"
                                                                                );
                                                                                while let Some(
                                                                                    start,
                                                                                ) = result
                                                                                    .find(
                                                                                    &conditional,
                                                                                ) {
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
                                                                                result = result
                                                                                    .replace(
                                                                                        &marker,
                                                                                        value,
                                                                                    );
                                                                            }
                                                                            let result = result
                                                                                .trim()
                                                                                .trim_start_matches(
                                                                                    ['v', 'V'],
                                                                                )
                                                                                .to_owned();
                                                                            (!result.is_empty())
                                                                                .then_some(result)
                                                                        };
                                                                        inlined_result
                                                                    }
                                                                }
                                                            };
                                                            inlined_result
                                                        });
                                                    }
                                                }
                                                for pattern in &inlined_self.individual {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_visit_matches;
                                                    }
                                                    if let Some(version) = {
                                                        let (pattern, text, state): (
                                                            &CompiledPattern,
                                                            &str,
                                                            &mut MatchState<'_>,
                                                        ) = (pattern, text, state);
                                                        let inlined_result: Option<Option<String>> = {
                                                            'inlined_match_single_pattern: {
                                                                if state.cancel.is_cancelled() {
                                                                    break 'inlined_match_single_pattern None;
                                                                }
                                                                match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                            }
                                                        };
                                                        inlined_result
                                                    } {
                                                        visit(pattern, version);
                                                    }
                                                }
                                            }
                                        });
                                    }
                                    for (index, script) in
                                        signals.inline_scripts.into_iter().enumerate()
                                    {
                                        let key = format!("inline-script:{url}:{index}");
                                        ({
                                            let (inlined_self, text, state, mut visit): (
                                                &MatcherBank,
                                                &str,
                                                &mut MatchState<'_>,
                                                _,
                                            ) = (
                                                &(inlined_self.scripts),
                                                &script,
                                                state,
                                                |pattern, version| {
                                                    ({
                                                        let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                            key: &key,
                            label: "inline script content",
                            url: &url,
                        },);

                                                        let mut path = HashSet::new();
                                                        inlined_self.add_recursive(
                                                            detections,
                                                            pattern.technology,
                                                            pattern.confidence,
                                                            version,
                                                            &context,
                                                            &mut path,
                                                            None,
                                                        );
                                                    });
                                                },
                                            );
                                            'inlined_visit_matches: {
                                                if state.cancel.is_cancelled() {
                                                    break 'inlined_visit_matches;
                                                }
                                                for pattern in &inlined_self.always {
                                                    visit(pattern, None);
                                                }
                                                for batch in &inlined_self.batches {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_visit_matches;
                                                    }
                                                    for index in batch.set.matches(text).into_iter()
                                                    {
                                                        let pattern = &batch.patterns[index];
                                                        visit(pattern, {
                                                            let (pattern, text): (
                                                                &CompiledPattern,
                                                                &str,
                                                            ) = (pattern, text);
                                                            let inlined_result: Option<String> = {
                                                                'inlined_pattern_version: {
                                                                    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
                                                                    let PatternMatcher::Standard(
                                                                        regex,
                                                                    ) = &pattern.matcher
                                                                    else {
                                                                        break 'inlined_pattern_version None;
                                                                    };
                                                                    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
                                                                    {
                                                                        let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                                        let inlined_result: Option<
                                                                            String,
                                                                        > = {
                                                                            let mut result =
                                                                                template.to_owned();
                                                                            for index in
                                                                                1..capture_count
                                                                            {
                                                                                let marker = format!(
                                                                                    "\\{index}"
                                                                                );
                                                                                let value =
                                                                                    capture(index);
                                                                                let conditional = format!(
                                                                                    "{marker}?"
                                                                                );
                                                                                while let Some(
                                                                                    start,
                                                                                ) = result
                                                                                    .find(
                                                                                    &conditional,
                                                                                ) {
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
                                                                                result = result
                                                                                    .replace(
                                                                                        &marker,
                                                                                        value,
                                                                                    );
                                                                            }
                                                                            let result = result
                                                                                .trim()
                                                                                .trim_start_matches(
                                                                                    ['v', 'V'],
                                                                                )
                                                                                .to_owned();
                                                                            (!result.is_empty())
                                                                                .then_some(result)
                                                                        };
                                                                        inlined_result
                                                                    }
                                                                }
                                                            };
                                                            inlined_result
                                                        });
                                                    }
                                                }
                                                for pattern in &inlined_self.individual {
                                                    if state.cancel.is_cancelled() {
                                                        break 'inlined_visit_matches;
                                                    }
                                                    if let Some(version) = {
                                                        let (pattern, text, state): (
                                                            &CompiledPattern,
                                                            &str,
                                                            &mut MatchState<'_>,
                                                        ) = (pattern, text, state);
                                                        let inlined_result: Option<Option<String>> = {
                                                            'inlined_match_single_pattern: {
                                                                if state.cancel.is_cancelled() {
                                                                    break 'inlined_match_single_pattern None;
                                                                }
                                                                match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                            }
                                                        };
                                                        inlined_result
                                                    } {
                                                        visit(pattern, version);
                                                    }
                                                }
                                            }
                                        });
                                    }
                                }
                            });
                            if source != response_url {
                                let key = format!("script-url:{source}");
                                ({
                                    let (inlined_self, text, state, mut visit): (
                                        &MatcherBank,
                                        &str,
                                        &mut MatchState<'_>,
                                        _,
                                    ) = (
                                        &(inlined_self.script_sources),
                                        &source,
                                        state,
                                        |pattern, version| {
                                            ({
                                                let (inlined_self, detections, pattern, version, context,): (& Catalog, & mut HashMap < String , AccumulatedDetection >, & CompiledPattern, Option < String >, MatchContext < '_ >,) = (&(inlined_self), detections, pattern, version, MatchContext {
                            key: &key,
                            label: "script URL",
                            url: &source,
                        },);

                                                let mut path = HashSet::new();
                                                inlined_self.add_recursive(
                                                    detections,
                                                    pattern.technology,
                                                    pattern.confidence,
                                                    version,
                                                    &context,
                                                    &mut path,
                                                    None,
                                                );
                                            });
                                        },
                                    );
                                    'inlined_visit_matches: {
                                        if state.cancel.is_cancelled() {
                                            break 'inlined_visit_matches;
                                        }
                                        for pattern in &inlined_self.always {
                                            visit(pattern, None);
                                        }
                                        for batch in &inlined_self.batches {
                                            if state.cancel.is_cancelled() {
                                                break 'inlined_visit_matches;
                                            }
                                            for index in batch.set.matches(text).into_iter() {
                                                let pattern = &batch.patterns[index];
                                                visit(pattern, {
                                                    let (pattern, text): (&CompiledPattern, &str) =
                                                        (pattern, text);
                                                    let inlined_result: Option<String> = {
                                                        'inlined_pattern_version: {
                                                            let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
                                                            let PatternMatcher::Standard(regex) =
                                                                &pattern.matcher
                                                            else {
                                                                break 'inlined_pattern_version None;
                                                            };
                                                            let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
                                                            {
                                                                let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
                                                                let inlined_result: Option<String> = {
                                                                    let mut result =
                                                                        template.to_owned();
                                                                    for index in 1..capture_count {
                                                                        let marker =
                                                                            format!("\\{index}");
                                                                        let value = capture(index);
                                                                        let conditional =
                                                                            format!("{marker}?");
                                                                        while let Some(start) =
                                                                            result
                                                                                .find(&conditional)
                                                                        {
                                                                            let branch_start = start
                                                                                + conditional.len();
                                                                            let end = result
                                                                                [branch_start..]
                                                                                .find("\\;")
                                                                                .map(|offset| {
                                                                                    branch_start
                                                                                        + offset
                                                                                })
                                                                                .unwrap_or(
                                                                                    result.len(),
                                                                                );
                                                                            let branch = &result
                                                                                [branch_start..end];
                                                                            let (
                                                                                when_present,
                                                                                when_missing,
                                                                            ) = branch
                                                                                .split_once(':')
                                                                                .unwrap_or((
                                                                                    branch, "",
                                                                                ));
                                                                            let replacement =
                                                                                if value.is_empty()
                                                                                {
                                                                                    when_missing
                                                                                } else {
                                                                                    when_present
                                                                                }
                                                                                .to_owned();
                                                                            result.replace_range(
                                                                                start..end,
                                                                                &replacement,
                                                                            );
                                                                        }
                                                                        result = result.replace(
                                                                            &marker, value,
                                                                        );
                                                                    }
                                                                    let result = result
                                                                        .trim()
                                                                        .trim_start_matches([
                                                                            'v', 'V',
                                                                        ])
                                                                        .to_owned();
                                                                    (!result.is_empty())
                                                                        .then_some(result)
                                                                };
                                                                inlined_result
                                                            }
                                                        }
                                                    };
                                                    inlined_result
                                                });
                                            }
                                        }
                                        for pattern in &inlined_self.individual {
                                            if state.cancel.is_cancelled() {
                                                break 'inlined_visit_matches;
                                            }
                                            if let Some(version) = {
                                                let (pattern, text, state): (
                                                    &CompiledPattern,
                                                    &str,
                                                    &mut MatchState<'_>,
                                                ) = (pattern, text, state);
                                                let inlined_result: Option<Option<String>> = {
                                                    'inlined_match_single_pattern: {
                                                        if state.cancel.is_cancelled() {
                                                            break 'inlined_match_single_pattern None;
                                                        }
                                                        match &pattern.matcher {
        PatternMatcher::Presence => Some(None),
        PatternMatcher::Standard(regex) => {
            regex.is_match(text).then(|| {
let (pattern, text,): (& CompiledPattern, & str,) = (pattern, text,);
let inlined_result: Option < String > = {
'inlined_pattern_version: {

    let template = match pattern.version.as_deref() { Some(value) => value, None => break 'inlined_pattern_version None };
    let PatternMatcher::Standard(regex) = &pattern.matcher else {
        break 'inlined_pattern_version None;
    };
    let captures = match regex.captures(text) { Some(value) => value, None => break 'inlined_pattern_version None };
    {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
        captures.get(index).map_or("", |capture| capture.as_str())
    },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}

}
};
inlined_result
})
        }
        PatternMatcher::Compatibility(regex) => {
            if state.disabled.contains(&pattern.id) {
                break 'inlined_match_single_pattern None;
            }
            let matched = if let Some(template) = &pattern.version {
                regex.captures(text).map(|captures| {
                    captures.map(|captures| {
                        {
let (template, capture_count, capture,): (& str, usize, _,) = (template, captures.len(), |index| {
                            captures.get(index).map_or("", |capture| capture.as_str())
                        },);
let inlined_result: Option < String > = {

    let mut result = template.to_owned();
    for index in 1..capture_count {
        let marker = format!("\\{index}");
        let value = capture(index);
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

};
inlined_result
}
                    })
                })
            } else {
                regex.is_match(text).map(|matched| matched.then_some(None))
            };
            match matched {
                Ok(version) => version,
                Err(error) => {
                    if state.disabled.insert(pattern.id) {
                        state.warnings.push(format!(
                            "Web technology pattern {} disabled for the remainder of this scan: {error}",
                            pattern.location
                        ));
                    }
                    None
                }
            }
        }
    }
                                                    }
                                                };
                                                inlined_result
                                            } {
                                                visit(pattern, version);
                                            }
                                        }
                                    }
                                });
                            }
                        });
                    }
                }
                completed += 1;
                ({
                    let (progress, completed, total, text): (
                        &Option<Sender<ExposureScanProgress>>,
                        usize,
                        usize,
                        String,
                    ) = (
                        progress,
                        completed,
                        work_total,
                        format!(
                            "Script: {}",
                            ({
                                let (source,): (&str,) = (&script.source_url,);
                                let inlined_result: String = {
                                    'inlined_sanitize_url: {
                                        let Ok(mut url) = Url::parse(source) else {
                                            break 'inlined_sanitize_url source
                                                .chars()
                                                .take(512)
                                                .collect();
                                        };
                                        let _ = url.set_username("");
                                        let _ = url.set_password(None);
                                        url.set_query(None);
                                        url.set_fragment(None);
                                        url.to_string()
                                    }
                                };
                                inlined_result
                            })
                        ),
                    );

                    send_phase_progress(
                        progress,
                        ExposureScanPhase::Fingerprinting,
                        ExposureScanPhaseState::Running,
                        completed as f32 / total.max(1) as f32,
                        text,
                    );
                });
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
                .map(|detection: AccumulatedDetection| {
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
                })
                .collect::<Vec<_>>();
            detections.sort_by(|left, right| {
                left.name
                    .to_ascii_lowercase()
                    .cmp(&right.name.to_ascii_lowercase())
            });
            ({
                let (products, detections): (
                    &mut Vec<ProductDetection>,
                    &[WebTechnologyDetection],
                ) = (&mut endpoint.products, &detections);

                for detection in detections {
                    for layer in detection.category_names.iter().filter_map(|name| {
                        let (name,): (&str,) = (name,);
                        {
                            'inlined_category_layer: {
                                Some(match name.to_ascii_lowercase().as_str() {
                                    "cms" => ProductLayer::Cms,
                                    "ecommerce" | "ecommerce frontends" => ProductLayer::Ecommerce,
                                    "javascript frameworks"
                                    | "web frameworks"
                                    | "mobile frameworks"
                                    | "ui frameworks" => ProductLayer::Framework,
                                    "programming languages" => ProductLayer::Runtime,
                                    "web servers" | "web server extensions" => ProductLayer::Server,
                                    "cdn" => ProductLayer::Cdn,
                                    "caching" | "reverse proxies" | "load balancers" => {
                                        ProductLayer::Proxy
                                    }
                                    "paas" | "iaas" | "hosting" => ProductLayer::Cloud,
                                    _ => break 'inlined_category_layer None,
                                })
                            }
                        }
                    }) {
                        let evidence = detection.evidence.clone();
                        let name = if matches!(layer, ProductLayer::Server | ProductLayer::Proxy) {
                            match crate::web_server::canonical_product_name(&detection.name) {
                                Some(name) => name,
                                None => detection.name.as_str(),
                            }
                        } else {
                            detection.name.as_str()
                        };
                        if let Some(existing) = products.iter_mut().find(|product| {
                            product.layer == layer && product.name.eq_ignore_ascii_case(name)
                        }) {
                            let previous_confidence = existing.confidence;
                            if detection.version.is_some()
                                && (existing.version.is_none()
                                    || detection.confidence >= previous_confidence)
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
            });
            endpoint.web_technologies = detections;
            completed += 1;
            ({
                let (progress, completed, total, text): (
                    &Option<Sender<ExposureScanProgress>>,
                    usize,
                    usize,
                    String,
                ) = (
                    progress,
                    completed,
                    work_total,
                    format!("Finalized {}:{}", endpoint.ip, endpoint.port),
                );

                send_phase_progress(
                    progress,
                    ExposureScanPhase::Fingerprinting,
                    ExposureScanPhaseState::Running,
                    completed as f32 / total.max(1) as f32,
                    text,
                );
            });
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
    for state in match_states {
        warnings.extend(state.warnings);
    }
    warnings.sort();
    warnings.dedup();
    warnings
}

impl Catalog {
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
        let signal_score = detection.signal_scores.entry(key).or_default();
        if confidence > *signal_score {
            detection.score = detection
                .score
                .saturating_add(confidence - *signal_score)
                .min(100);
            *signal_score = confidence;
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
