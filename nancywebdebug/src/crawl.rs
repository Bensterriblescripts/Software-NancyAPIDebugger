use super::technology::{self, CapturedTechnologyResource};
use super::{
    Confidence, ConnectionRateLimiter, CrawlContact, CrawlContactType, CrawlExternalIndicator,
    CrawlFormAction, CrawlFormControl, CrawlObservedWebSurface, CrawlOrigin, CrawlSkippedUrl,
    CrawledResource, EndpointScan, ExposureFinding, ExposureScanPhase, ExposureScanPhaseState,
    ExposureScanProgress, ExposureScanRequest, HttpObservation, ProbeContext, ScanContext,
    ServiceKind, StreamObservation, TechnologyFileType, TransportProtocol, WebSurfaceType,
    header_values, looks_like_soft_404, non_public_reason, send_phase_progress,
    single_http_request_with_limit, url_host, url_path,
};
use crate::auth::{LoadedClientCertificate, ResolvedAuth};
use crate::diagnostics::DnsTrace;
use crate::request::resolve_host;
use base64::Engine;
use futures_util::stream::{FuturesUnordered, StreamExt};
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::{
    BufferQueue, CharacterTokens, EndTag, StartTag, TagToken, Token, TokenSink, TokenSinkResult,
    Tokenizer,
};
use percent_encoding::percent_decode_str;
use quick_xml::{Reader, events::Event};
use regex::Regex;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{LazyLock, mpsc::Sender};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;
use url::Url;

const BODY_LIMIT: usize = 1024 * 1024;
const DECODE_LIMIT: usize = 64 * 1024;
const CANDIDATE_LIMIT: usize = 256;
const REFERENCE_LIMIT: usize = 2048;
const SKIPPED_LIMIT: usize = 5000;
const TECHNOLOGY_CAPTURE_LIMIT: usize = 512;
const TECHNOLOGY_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const OBSERVED_SURFACE_LIMIT: usize = 2048;
const TECHNOLOGY_ROOT_PROBES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.json",
    "composer.lock",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pyproject.toml",
    "Gemfile",
    "Gemfile.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "packages.config",
    "packages.lock.json",
    "Directory.Packages.props",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
];

static ABSOLUTE_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)https?://[^\s\"'<>\\)\]}]+"#).expect("valid URL regex"));
static PATH_HINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[\"'`]((?:/|\./|\.\./)[A-Za-z0-9_~!$&()*+,;=:@%?./-]{1,2047})[\"'`]"#)
        .expect("valid path regex")
});
static BASE64_HINT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{16,}={0,2}").expect("valid Base64 regex"));
static VERSION_HINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[/ _-])v?[0-9]+(?:\.[0-9]+){1,3}(?:$|[ ;_-])")
        .expect("valid version regex")
});
static SOURCE_MAP_HINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)(?://#|//@|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)")
        .expect("valid source-map regex")
});
static EMAIL_HINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:mailto:[ \t]*)?([a-z0-9!#$%&'*+/=?^_`{|}~-](?:[a-z0-9.!#$%&'*+/=?^_`{|}~-]{0,62}[a-z0-9!#$%&'*+/=?^_`{|}~-])?@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})"#,
    )
    .expect("valid email regex")
});
static PHONE_HINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:tel:[ \t]*)?(?:\+[ \t]?[0-9]|\([0-9]{1,4}\)|[0-9])(?:[0-9 \t()./-]{4,}[0-9])",
    )
    .expect("valid telephone regex")
});

#[derive(Default)]
pub(super) struct CrawlReport {
    pub findings: Vec<ExposureFinding>,
    pub observed_web_surfaces: Vec<CrawlObservedWebSurface>,
    pub origins: Vec<CrawlOrigin>,
    pub resources: Vec<CrawledResource>,
    pub forms: Vec<CrawlFormAction>,
    pub contacts: Vec<CrawlContact>,
    pub external_indicators: Vec<CrawlExternalIndicator>,
    pub skipped_urls: Vec<CrawlSkippedUrl>,
    pub stream_observations: Vec<StreamObservation>,
    pub technology_resources: Vec<CapturedTechnologyResource>,
    pub javascript_candidates: Vec<(IpAddr, u16, String)>,
    technology_bytes: usize,
    resource_records: Vec<CrawlResourceRecord>,
    contact_records: BTreeMap<ContactKey, CrawlContactRecord>,
    technology_version_disclosures: HashSet<TechnologyVersionDisclosureKey>,
    csp_nonce_sources: BTreeMap<Vec<u8>, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TechnologyVersionDisclosureKey {
    ip: IpAddr,
    port: u16,
    header: &'static str,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct OriginKey {
    ip: IpAddr,
    scheme: String,
    hostname: String,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DetectedFileTypeKey {
    file_type: TechnologyFileType,
    confidence: super::Confidence,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ResourceKey {
    ip: IpAddr,
    port: u16,
    url: String,
    depth: usize,
    status: Option<u16>,
    content_type: Option<String>,
    bytes_inspected: usize,
    body_truncated: bool,
    detected_file_types: Vec<DetectedFileTypeKey>,
    error: Option<String>,
}

impl From<&CrawledResource> for ResourceKey {
    fn from(resource: &CrawledResource) -> Self {
        Self {
            ip: resource.ip,
            port: resource.port,
            url: resource.url.clone(),
            depth: resource.depth,
            status: resource.status,
            content_type: resource.content_type.clone(),
            bytes_inspected: resource.bytes_inspected,
            body_truncated: resource.body_truncated,
            detected_file_types: resource
                .detected_file_types
                .iter()
                .map(|detected| DetectedFileTypeKey {
                    file_type: detected.file_type,
                    confidence: detected.confidence,
                    evidence: detected.evidence.clone(),
                })
                .collect(),
            error: resource.error.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FormKey {
    method: String,
    action_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExternalIndicatorKey {
    value: String,
    source_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SkippedUrlKey {
    url: String,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ContactKey {
    contact_type: CrawlContactType,
    normalized_value: String,
}

struct CrawlContactRecord {
    value: String,
    urls: HashSet<String>,
}

struct OriginState {
    report: CrawlOrigin,
    baseline_url: Url,
    baseline: Option<HttpObservation>,
    baseline_complete: bool,
    deferred: Vec<FetchResult>,
}

struct CrawlScope {
    hostname: String,
    ip: bool,
}

impl CrawlScope {
    fn new(hostname: &str) -> Self {
        let hostname = canonical_hostname(hostname);
        let ip = hostname.parse::<IpAddr>().is_ok();
        let hostname = if ip {
            hostname
        } else {
            hostname
                .strip_prefix("www.")
                .unwrap_or(&hostname)
                .to_owned()
        };
        Self { hostname, ip }
    }

    fn allows(&self, hostname: &str) -> bool {
        let hostname = canonical_hostname(hostname);
        hostname == self.hostname
            || (!self.ip
                && hostname
                    .strip_suffix(&self.hostname)
                    .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1))
    }
}

pub(super) fn hostname_in_scope(root_hostname: &str, hostname: &str) -> bool {
    CrawlScope::new(root_hostname).allows(hostname)
}

fn canonical_hostname(hostname: &str) -> String {
    hostname
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[derive(Clone)]
struct HostResolution {
    addresses: Vec<IpAddr>,
    rejected: Vec<(IpAddr, &'static str)>,
    error: Option<String>,
}

struct CrawlSession {
    scope: CrawlScope,
    resolutions: HashMap<String, HostResolution>,
    endpoint_states: HashMap<String, EndpointState>,
    reportable_urls: HashSet<String>,
    query_variants: HashMap<String, HashSet<String>>,
    baseline_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointState {
    Queued,
    InFlight,
    Completed,
}

#[derive(Clone, Copy)]
enum JobProvenance {
    Seed,
    DiscoveredReference,
    Redirect { automatic_probe: bool },
    BaselineCheck,
    AutomaticProbe,
}

impl JobProvenance {
    fn is_automatic_probe(self) -> bool {
        matches!(
            self,
            Self::AutomaticProbe
                | Self::Redirect {
                    automatic_probe: true
                }
        )
    }

    fn is_reportable_url(self) -> bool {
        matches!(
            self,
            Self::Seed
                | Self::DiscoveredReference
                | Self::Redirect {
                    automatic_probe: false
                }
        )
    }

    fn redirect(self) -> Self {
        Self::Redirect {
            automatic_probe: self.is_automatic_probe(),
        }
    }
}

#[derive(Clone)]
struct Job {
    origin: OriginKey,
    url: Url,
    depth: usize,
    source: Option<String>,
    provenance: JobProvenance,
}

struct CrawlResourceRecord {
    resource: CrawledResource,
    url: String,
    provenance: JobProvenance,
    probe_reportable: bool,
}

struct FetchResult {
    job: Job,
    response: Result<HttpObservation, String>,
}

#[derive(Default)]
struct HtmlDiscovery {
    references: Vec<HtmlReference>,
    forms: Vec<HtmlForm>,
    javascript: String,
    base_hrefs: Vec<String>,
}

struct HtmlReference {
    value: String,
    kind: String,
    active: bool,
}

struct HtmlForm {
    action: String,
    method: String,
    encoding: String,
    password: bool,
    controls: Vec<CrawlFormControl>,
}

#[derive(Default)]
struct HtmlState {
    result: HtmlDiscovery,
    forms: Vec<usize>,
    in_script: bool,
}

struct HtmlSink(RefCell<HtmlState>);

impl TokenSink for HtmlSink {
    type Handle = ();

    fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
        let mut state = self.0.borrow_mut();
        match token {
            TagToken(tag) if tag.kind == StartTag => {
                let name = tag.name.as_ref().to_ascii_lowercase();
                let attr = |wanted: &str| {
                    tag.attrs
                        .iter()
                        .find(|item| item.name.local.as_ref().eq_ignore_ascii_case(wanted))
                        .map(|item| item.value.to_string())
                };
                match name.as_str() {
                    "base" => {
                        if let Some(value) = attr("href").filter(|value| !value.trim().is_empty()) {
                            state.result.base_hrefs.push(value);
                        }
                    }
                    "a" | "area" => html_ref(&mut state.result, attr("href"), &name, false),
                    "frame" | "iframe" => html_ref(&mut state.result, attr("src"), &name, true),
                    "script" => {
                        html_ref(&mut state.result, attr("src"), "script", true);
                        state.in_script = true;
                    }
                    "video" | "audio" | "source" => {
                        html_ref(&mut state.result, attr("src"), &name, true);
                    }
                    "link" => {
                        let rel = attr("rel").unwrap_or_default().to_ascii_lowercase();
                        if rel
                            .split_ascii_whitespace()
                            .any(|value| matches!(value, "stylesheet" | "manifest" | "canonical"))
                        {
                            html_ref(
                                &mut state.result,
                                attr("href"),
                                &format!("link:{rel}"),
                                rel.split_ascii_whitespace()
                                    .any(|value| value == "stylesheet"),
                            );
                        }
                    }
                    "meta" => {
                        if attr("http-equiv")
                            .is_some_and(|value| value.eq_ignore_ascii_case("refresh"))
                            && let Some(value) =
                                attr("content").and_then(|value| refresh_url(&value))
                        {
                            state.result.references.push(HtmlReference {
                                value,
                                kind: "refresh".to_owned(),
                                active: false,
                            });
                        }
                    }
                    "form" => {
                        let index = state.result.forms.len();
                        state.result.forms.push(HtmlForm {
                            action: attr("action").unwrap_or_default(),
                            method: attr("method")
                                .unwrap_or_else(|| "GET".to_owned())
                                .to_ascii_uppercase(),
                            encoding: attr("enctype")
                                .unwrap_or_else(|| "application/x-www-form-urlencoded".to_owned()),
                            password: false,
                            controls: Vec::new(),
                        });
                        state.forms.push(index);
                    }
                    "input" => {
                        if let Some(index) = state.forms.last().copied()
                            && let Some(form) = state.result.forms.get_mut(index)
                        {
                            let control_type = attr("type")
                                .unwrap_or_else(|| "text".to_owned())
                                .to_ascii_lowercase();
                            form.password |= control_type == "password";
                            if let Some(control_name) =
                                attr("name").filter(|value| !value.trim().is_empty())
                            {
                                form.controls.push(CrawlFormControl {
                                    name: control_name,
                                    default_value: attr("value")
                                        .map(|value| value.chars().take(512).collect::<String>()),
                                    submit_control: matches!(
                                        control_type.as_str(),
                                        "submit" | "image" | "button"
                                    ),
                                    control_type,
                                });
                            }
                        }
                    }
                    "button" => {
                        if let Some(index) = state.forms.last().copied()
                            && let Some(form) = state.result.forms.get_mut(index)
                            && let Some(control_name) =
                                attr("name").filter(|value| !value.trim().is_empty())
                        {
                            let control_type = attr("type")
                                .unwrap_or_else(|| "submit".to_owned())
                                .to_ascii_lowercase();
                            form.controls.push(CrawlFormControl {
                                name: control_name,
                                default_value: attr("value")
                                    .map(|value| value.chars().take(512).collect::<String>()),
                                submit_control: control_type == "submit",
                                control_type,
                            });
                        }
                    }
                    _ => {}
                }
                if tag.self_closing {
                    if name == "form" {
                        state.forms.pop();
                    } else if name == "script" {
                        state.in_script = false;
                    }
                }
            }
            TagToken(tag) if tag.kind == EndTag => {
                if tag.name.as_ref().eq_ignore_ascii_case("form") {
                    state.forms.pop();
                } else if tag.name.as_ref().eq_ignore_ascii_case("script") {
                    state.in_script = false;
                }
            }
            CharacterTokens(value)
                if state.in_script && state.result.javascript.len() < BODY_LIMIT =>
            {
                let remaining = BODY_LIMIT - state.result.javascript.len();
                state
                    .result
                    .javascript
                    .push_str(&value.chars().take(remaining).collect::<String>());
            }
            _ => {}
        }
        TokenSinkResult::Continue
    }
}

pub(super) async fn run(
    request: &ExposureScanRequest,
    hostname: &str,
    supplied_seed: Option<&Url>,
    endpoints: &[EndpointScan],
    cancel: &CancellationToken,
    progress: &Option<Sender<ExposureScanProgress>>,
    http_auth: Option<&ResolvedAuth>,
    client_certificate: Option<&LoadedClientCertificate>,
) -> CrawlReport {
    send_phase_progress(
        progress,
        ExposureScanPhase::Crawl,
        ExposureScanPhaseState::Running,
        0.0,
        "Preparing crawl queue",
    );
    let mut report = CrawlReport::default();
    let hostname = canonical_hostname(hostname);
    let mut origins = BTreeMap::new();
    let mut queue = VecDeque::new();
    let mut addresses = endpoints
        .iter()
        .filter(|endpoint| matches!(endpoint.service, ServiceKind::Http | ServiceKind::Https))
        .map(|endpoint| endpoint.ip)
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    let mut resolutions = HashMap::new();
    resolutions.insert(
        hostname.clone(),
        HostResolution {
            addresses,
            rejected: Vec::new(),
            error: None,
        },
    );
    let mut session = CrawlSession {
        scope: CrawlScope::new(&hostname),
        resolutions,
        endpoint_states: HashMap::new(),
        reportable_urls: HashSet::new(),
        query_variants: HashMap::new(),
        baseline_path: format!(
            "/nancy-crawl-not-found-{:x}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ),
    };
    let mut seeded_origins = HashSet::new();
    for endpoint in endpoints {
        let scheme = match endpoint.service {
            ServiceKind::Http => "http",
            ServiceKind::Https => "https",
            _ => continue,
        };
        if !seeded_origins.insert((scheme, endpoint.port)) {
            continue;
        }
        let key = OriginKey {
            ip: endpoint.ip,
            scheme: scheme.to_owned(),
            hostname: hostname.clone(),
            port: endpoint.port,
        };
        if origins.contains_key(&key) {
            continue;
        }
        let root = Url::parse(&format!(
            "{scheme}://{}:{}/",
            url_host(&hostname),
            endpoint.port
        ))
        .expect("constructed origin URL is valid");
        let seed = supplied_seed
            .filter(|seed| {
                seed.scheme() == scheme
                    && seed.port_or_known_default() == Some(endpoint.port)
                    && seed
                        .host_str()
                        .is_some_and(|host| host.eq_ignore_ascii_case(&hostname))
            })
            .cloned()
            .and_then(|seed| normalize_url(seed).ok())
            .unwrap_or_else(|| normalize_url(root.clone()).unwrap_or(root));
        create_origin(&mut origins, &key, &seed, &session.baseline_path);
        enqueue_origin_baseline(
            &mut origins,
            &mut queue,
            &mut report,
            &key,
            request.crawl_max_urls,
            &mut session,
        );
        enqueue_url(
            &mut origins,
            &mut queue,
            &mut report,
            key.clone(),
            seed.clone(),
            0,
            None,
            JobProvenance::Seed,
            request.crawl_max_urls,
            &mut session,
        );
        if let Ok(robots) = seed.join("/robots.txt") {
            enqueue_url(
                &mut origins,
                &mut queue,
                &mut report,
                key.clone(),
                robots,
                0,
                None,
                JobProvenance::AutomaticProbe,
                request.crawl_max_urls,
                &mut session,
            );
        }
        for path in TECHNOLOGY_ROOT_PROBES {
            if let Ok(probe) = seed.join(&format!("/{path}")) {
                enqueue_url(
                    &mut origins,
                    &mut queue,
                    &mut report,
                    key.clone(),
                    probe,
                    0,
                    Some(seed.to_string()),
                    JobProvenance::AutomaticProbe,
                    request.crawl_max_urls,
                    &mut session,
                );
            }
        }
    }
    send_global_progress(progress, &origins, None, ExposureScanPhaseState::Running);
    let limiter = ConnectionRateLimiter::new(request.crawl_requests_per_second);
    let mut pending = FuturesUnordered::new();
    while (!queue.is_empty() || !pending.is_empty()) && !cancel.is_cancelled() {
        while pending.len() < request.crawl_concurrency {
            let Some(job) = queue.pop_front() else {
                break;
            };
            transition_endpoint(
                &mut session,
                &job.url,
                EndpointState::Queued,
                EndpointState::InFlight,
            );
            pending.push(fetch(
                job,
                request,
                cancel,
                &limiter,
                http_auth,
                client_certificate,
                &hostname,
            ));
        }
        let Some(result) = pending.next().await else {
            break;
        };
        let current_url = safe_url(&result.job.url);
        transition_endpoint(
            &mut session,
            &result.job.url,
            EndpointState::InFlight,
            EndpointState::Completed,
        );
        if let Some(origin) = origins.get_mut(&result.job.origin) {
            origin.report.completed += 1;
            send_origin_progress(progress, &origin.report, result.job.url.as_str());
        }
        if matches!(result.job.provenance, JobProvenance::BaselineCheck) {
            let deferred = complete_origin_baseline(result, &mut origins);
            for result in deferred {
                process_result(
                    result,
                    request,
                    cancel,
                    &mut session,
                    &mut origins,
                    &mut queue,
                    &mut report,
                )
                .await;
            }
        } else if origins
            .get(&result.job.origin)
            .is_some_and(|origin| origin.baseline_complete)
        {
            process_result(
                result,
                request,
                cancel,
                &mut session,
                &mut origins,
                &mut queue,
                &mut report,
            )
            .await;
        } else if let Some(origin) = origins.get_mut(&result.job.origin) {
            origin.deferred.push(result);
        }
        send_global_progress(
            progress,
            &origins,
            Some(&current_url),
            ExposureScanPhaseState::Running,
        );
    }
    if cancel.is_cancelled() {
        pending.clear();
    }
    if !cancel.is_cancelled() {
        send_global_progress(progress, &origins, None, ExposureScanPhaseState::Complete);
    }
    report.origins = origins.into_values().map(|origin| origin.report).collect();
    finish(&mut report, &session.reportable_urls);
    report
}

async fn fetch(
    job: Job,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
    http_auth: Option<&ResolvedAuth>,
    client_certificate: Option<&LoadedClientCertificate>,
    auth_hostname: &str,
) -> FetchResult {
    let hostname = job.origin.hostname.clone();
    let context = ProbeContext {
        ip: job.origin.ip,
        port: job.origin.port,
        scan: ScanContext {
            hostname: &hostname,
            request,
            cancel,
            limiter,
            client_certificate: client_certificate
                .filter(|certificate| certificate.applies_to(&hostname)),
        },
    };
    let path = url_path(&job.url);
    let auth = http_auth.filter(|_| hostname.eq_ignore_ascii_case(auth_hostname));
    let auth_headers = auth
        .map(|auth| vec![(auth.header_name, auth.header_value.as_str())])
        .unwrap_or_default();
    let mut response = single_http_request_with_limit(
        context,
        &job.origin.scheme,
        "GET",
        &path,
        &auth_headers,
        BODY_LIMIT,
    )
    .await;
    if let Ok(response) = &mut response {
        response.url = job.url.to_string();
    }
    FetchResult { job, response }
}

fn enqueue_origin_baseline(
    origins: &mut BTreeMap<OriginKey, OriginState>,
    queue: &mut VecDeque<Job>,
    report: &mut CrawlReport,
    key: &OriginKey,
    max_urls: usize,
    session: &mut CrawlSession,
) -> bool {
    let Some(url) = origins.get(key).map(|origin| origin.baseline_url.clone()) else {
        return false;
    };
    enqueue_url(
        origins,
        queue,
        report,
        key.clone(),
        url,
        0,
        None,
        JobProvenance::BaselineCheck,
        max_urls,
        session,
    )
}

fn transition_endpoint(
    session: &mut CrawlSession,
    url: &Url,
    expected: EndpointState,
    next: EndpointState,
) {
    let state = session
        .endpoint_states
        .get_mut(url.as_str())
        .expect("crawl job must be registered before execution");
    debug_assert_eq!(*state, expected);
    *state = next;
}

fn complete_origin_baseline(
    result: FetchResult,
    origins: &mut BTreeMap<OriginKey, OriginState>,
) -> Vec<FetchResult> {
    let Some(origin) = origins.get_mut(&result.job.origin) else {
        return Vec::new();
    };
    origin.baseline = result.response.ok();
    origin.baseline_complete = true;
    std::mem::take(&mut origin.deferred)
}

async fn process_result(
    result: FetchResult,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    session: &mut CrawlSession,
    origins: &mut BTreeMap<OriginKey, OriginState>,
    queue: &mut VecDeque<Job>,
    report: &mut CrawlReport,
) {
    let FetchResult { job, response } = result;
    let displayed_url = safe_url(&job.url);
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            report.resource_records.push(CrawlResourceRecord {
                resource: CrawledResource {
                    ip: job.origin.ip,
                    port: job.origin.port,
                    url: displayed_url,
                    depth: job.depth,
                    source_url: job.source.map(|source| redact_url_text(&source)),
                    status: None,
                    content_type: None,
                    bytes_inspected: 0,
                    body_truncated: false,
                    detected_file_types: Vec::new(),
                    error: Some(error),
                },
                url: job.url.to_string(),
                provenance: job.provenance,
                probe_reportable: false,
            });
            return;
        }
    };
    let content_type = header_values(&response, "content-type")
        .next()
        .map(str::to_owned);
    report
        .stream_observations
        .extend(super::stream_inventory::observations_for_response(
            &response,
        ));
    let baseline = origins
        .get(&job.origin)
        .and_then(|origin| origin.baseline.clone());
    let probe_reportable = job.provenance.is_automatic_probe()
        && automatic_probe_reportable(&job.url, &response, baseline.as_ref());
    let process_response = !job.provenance.is_automatic_probe() || probe_reportable;
    let detected_file_types = if process_response && (200..300).contains(&response.status) {
        technology::classify_resource(&job.url, content_type.as_deref(), &response.body)
    } else {
        Vec::new()
    };
    report.resource_records.push(CrawlResourceRecord {
        resource: CrawledResource {
            ip: job.origin.ip,
            port: job.origin.port,
            url: displayed_url.clone(),
            depth: job.depth,
            source_url: job.source.as_deref().map(redact_url_text),
            status: Some(response.status),
            content_type: content_type.clone(),
            bytes_inspected: response.body.len(),
            body_truncated: response.body_truncated,
            detected_file_types: detected_file_types.clone(),
            error: None,
        },
        url: job.url.to_string(),
        provenance: job.provenance,
        probe_reportable,
    });
    if !process_response {
        if let Some(location) = response.redirect_location.as_deref() {
            enqueue_reference(
                origins,
                queue,
                report,
                &job,
                &job.url,
                location,
                job.depth,
                job.provenance.redirect(),
                request,
                cancel,
                session,
            )
            .await;
        }
        return;
    }
    let capture_technology = (200..300).contains(&response.status)
        && !response.body.is_empty()
        && technology::should_capture(
            &job.url,
            content_type.as_deref(),
            &response.body,
            &detected_file_types,
        )
        && report.technology_resources.len() < TECHNOLOGY_CAPTURE_LIMIT
        && report.technology_bytes.saturating_add(response.body.len()) <= TECHNOLOGY_CAPTURE_BYTES;
    response_checks(&job, &response, baseline.as_ref(), report);
    if let Some((surface_type, confidence, evidence)) =
        detect_surface(&job.url, &response, baseline.as_ref())
    {
        observe_surface(report, &job, &response, surface_type, confidence, evidence);
    }
    if let Some(location) = response.redirect_location.as_deref() {
        enqueue_reference(
            origins,
            queue,
            report,
            &job,
            &job.url,
            location,
            job.depth,
            job.provenance.redirect(),
            request,
            cancel,
            session,
        )
        .await;
    }
    if is_textual(&job.url, content_type.as_deref()) {
        let text = String::from_utf8_lossy(&response.body);
        collect_personal_information(&text, &job, report);
        let lower_start = text.trim_start().to_ascii_lowercase();
        let html = content_type
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains("html"))
            || lower_start.starts_with("<!doctype html")
            || lower_start.starts_with("<html");
        let javascript = content_type.as_deref().is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("javascript") || value.contains("ecmascript")
        }) || job.url.path().to_ascii_lowercase().ends_with(".js");
        if job.url.path().eq_ignore_ascii_case("/robots.txt") {
            process_robots(
                &job, &text, request, cancel, session, origins, queue, report,
            )
            .await;
        }
        if content_type
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains("xml"))
            || job.url.path().to_ascii_lowercase().contains("sitemap")
        {
            for location in sitemap_locations(&text).into_iter().take(REFERENCE_LIMIT) {
                if enqueue_reference(
                    origins,
                    queue,
                    report,
                    &job,
                    &job.url,
                    &location,
                    job.depth.saturating_add(1),
                    JobProvenance::DiscoveredReference,
                    request,
                    cancel,
                    session,
                )
                .await
                    && let Some(origin) = origins.get_mut(&job.origin)
                {
                    origin.report.sitemap_urls.push(location);
                }
            }
        }
        if html {
            let discovery = parse_html(&text);
            let base_url = html_base_url(&job.url, &discovery.base_hrefs);
            for reference in discovery.references.into_iter().take(REFERENCE_LIMIT) {
                if reference.kind == "script"
                    && report.javascript_candidates.len() < 256
                    && let Ok(url) = base_url.join(&reference.value)
                    && let Ok(url) = normalize_url(url)
                    && url
                        .host_str()
                        .is_some_and(|host| session.scope.allows(host))
                {
                    report.javascript_candidates.push((
                        job.origin.ip,
                        job.origin.port,
                        url.to_string(),
                    ));
                }
                if job.origin.scheme == "https"
                    && reference.active
                    && base_url
                        .join(&reference.value)
                        .is_ok_and(|url| url.scheme() == "http")
                {
                    finding(
                        report,
                        &job,
                        "Mixed active content",
                        "An HTTPS document references active content over cleartext HTTP",
                        format!(
                            "{} references cleartext {} content",
                            job.url, reference.kind
                        ),
                    );
                }
                enqueue_reference(
                    origins,
                    queue,
                    report,
                    &job,
                    &base_url,
                    &reference.value,
                    job.depth.saturating_add(1),
                    JobProvenance::DiscoveredReference,
                    request,
                    cancel,
                    session,
                )
                .await;
            }
            for form in discovery.forms {
                process_form(
                    form, &job, &base_url, request, cancel, session, origins, queue, report,
                )
                .await;
            }
            if !discovery.javascript.is_empty() {
                process_javascript(
                    &discovery.javascript,
                    &job,
                    &base_url,
                    request,
                    cancel,
                    session,
                    origins,
                    queue,
                    report,
                )
                .await;
            }
        }
        if javascript {
            process_javascript(
                &text, &job, &job.url, request, cancel, session, origins, queue, report,
            )
            .await;
        }
    }
    if capture_technology {
        report.technology_bytes += response.body.len();
        report
            .technology_resources
            .push(CapturedTechnologyResource {
                ip: job.origin.ip,
                port: job.origin.port,
                url: displayed_url,
                fetch_url: job.url.to_string(),
                status: response.status,
                headers: response.headers,
                body: response.body,
                truncated: response.body_truncated,
                detected_file_types,
            });
    }
}

async fn process_robots(
    job: &Job,
    text: &str,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    session: &mut CrawlSession,
    origins: &mut BTreeMap<OriginKey, OriginState>,
    queue: &mut VecDeque<Job>,
    report: &mut CrawlReport,
) {
    for line in text.lines().take(10_000) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.split('#').next().unwrap_or_default().trim();
        if name.trim().eq_ignore_ascii_case("disallow") && !value.is_empty() {
            if let Some(origin) = origins.get_mut(&job.origin) {
                origin.report.robots_exclusions.push(value.to_owned());
            }
        } else if name.trim().eq_ignore_ascii_case("sitemap")
            && !value.is_empty()
            && enqueue_reference(
                origins,
                queue,
                report,
                job,
                &job.url,
                value,
                job.depth.saturating_add(1),
                JobProvenance::DiscoveredReference,
                request,
                cancel,
                session,
            )
            .await
            && let Some(origin) = origins.get_mut(&job.origin)
        {
            origin.report.sitemap_urls.push(value.to_owned());
        }
    }
}

async fn process_form(
    form: HtmlForm,
    job: &Job,
    base_url: &Url,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    session: &mut CrawlSession,
    origins: &mut BTreeMap<OriginKey, OriginState>,
    queue: &mut VecDeque<Job>,
    report: &mut CrawlReport,
) {
    let action = if form.action.trim().is_empty() {
        job.url.to_string()
    } else {
        form.action
    };
    let method = if form.method.is_empty() {
        "GET".to_owned()
    } else {
        form.method
    };
    if !method.eq_ignore_ascii_case("GET") {
        match base_url.join(&action) {
            Ok(url) => {
                if let Ok(url) = normalize_url(url.clone())
                    && !url
                        .host_str()
                        .is_some_and(|host| session.scope.allows(host))
                {
                    external(
                        report,
                        job.url.as_str(),
                        "URL",
                        &redact_url(&url),
                        "Off-host form action",
                    );
                }
                skip(
                    report,
                    Some(job.url.as_str()),
                    &safe_url(&url),
                    "Non-GET form action was recorded but not submitted",
                );
            }
            Err(error) => {
                skip(
                    report,
                    Some(job.url.as_str()),
                    &action,
                    &format!("Malformed URL: {error}"),
                );
            }
        }
    }
    let enqueued = method.eq_ignore_ascii_case("GET")
        && enqueue_reference(
            origins,
            queue,
            report,
            job,
            base_url,
            &action,
            job.depth.saturating_add(1),
            JobProvenance::DiscoveredReference,
            request,
            cancel,
            session,
        )
        .await;
    let normalized = base_url
        .join(&action)
        .ok()
        .and_then(|url| normalize_url(url).ok())
        .map(|url| safe_url(&url))
        .unwrap_or_else(|| redact_url_text(&action));
    report.forms.push(CrawlFormAction {
        source_url: safe_url(&job.url),
        action_url: normalized.clone(),
        method: method.clone(),
        encoding: form.encoding,
        has_password: form.password,
        likely_csrf_tokens: form
            .controls
            .iter()
            .filter(|control| likely_csrf_name(&control.name))
            .map(|control| control.name.clone())
            .collect(),
        controls: form.controls,
        enqueued,
    });
    if form.password && job.origin.scheme == "http" {
        finding(
            report,
            job,
            "Password form delivered over cleartext HTTP",
            "A password field is present in a document delivered without transport encryption",
            format!("Password form found at {}", job.url),
        );
    }
    if form.password && method.eq_ignore_ascii_case("GET") {
        finding(
            report,
            job,
            "Password form submits with GET",
            "A password form places submitted fields in a URL query",
            format!("GET password form at {} targets {normalized}", job.url),
        );
    }
}

async fn process_javascript(
    text: &str,
    job: &Job,
    base_url: &Url,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    session: &mut CrawlSession,
    origins: &mut BTreeMap<OriginKey, OriginState>,
    queue: &mut VecDeque<Job>,
    report: &mut CrawlReport,
) {
    for captures in SOURCE_MAP_HINT.captures_iter(text).take(16) {
        if let Some(path) = captures.get(1) {
            enqueue_reference(
                origins,
                queue,
                report,
                job,
                base_url,
                path.as_str().trim_matches(['\'', '"']),
                job.depth.saturating_add(1),
                JobProvenance::DiscoveredReference,
                request,
                cancel,
                session,
            )
            .await;
        }
    }
    for candidate in decoded_candidates(text) {
        collect_personal_information(&candidate, job, report);
        let post_only = super::stream_inventory::post_only_endpoints(base_url.as_str(), &candidate);
        let standalone = candidate.trim();
        if standalone.len() <= 2048
            && standalone.starts_with('/')
            && !standalone.chars().any(char::is_whitespace)
            && !post_only_reference(base_url, standalone, &post_only)
        {
            enqueue_reference(
                origins,
                queue,
                report,
                job,
                base_url,
                standalone,
                job.depth.saturating_add(1),
                JobProvenance::DiscoveredReference,
                request,
                cancel,
                session,
            )
            .await;
        }
        for matched in ABSOLUTE_URL.find_iter(&candidate).take(REFERENCE_LIMIT) {
            if post_only_reference(base_url, matched.as_str(), &post_only) {
                continue;
            }
            enqueue_reference(
                origins,
                queue,
                report,
                job,
                base_url,
                matched.as_str(),
                job.depth.saturating_add(1),
                JobProvenance::DiscoveredReference,
                request,
                cancel,
                session,
            )
            .await;
        }
        for captures in PATH_HINT.captures_iter(&candidate).take(REFERENCE_LIMIT) {
            if let Some(path) = captures.get(1) {
                if post_only_reference(base_url, path.as_str(), &post_only) {
                    continue;
                }
                enqueue_reference(
                    origins,
                    queue,
                    report,
                    job,
                    base_url,
                    path.as_str(),
                    job.depth.saturating_add(1),
                    JobProvenance::DiscoveredReference,
                    request,
                    cancel,
                    session,
                )
                .await;
            }
        }
    }
}

fn post_only_reference(base_url: &Url, reference: &str, post_only: &HashSet<String>) -> bool {
    base_url
        .join(reference)
        .ok()
        .map(|mut url| {
            url.set_fragment(None);
            url.to_string()
        })
        .is_some_and(|url| post_only.contains(&url))
}

fn decoded_candidates(text: &str) -> Vec<String> {
    let mut candidates = text
        .as_bytes()
        .chunks(DECODE_LIMIT)
        .take(CANDIDATE_LIMIT)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>();
    let mut seen = candidates.iter().cloned().collect::<HashSet<_>>();
    let mut frontier = candidates.clone();
    for _ in 0..2 {
        let mut next = Vec::new();
        for candidate in frontier {
            for decoded in [
                decode_entities(&candidate),
                decode_javascript(&candidate),
                percent_decode_str(&candidate)
                    .decode_utf8_lossy()
                    .into_owned(),
            ] {
                push_candidate(decoded, &mut candidates, &mut next, &mut seen);
            }
            for encoded in BASE64_HINT.find_iter(&candidate).take(CANDIDATE_LIMIT) {
                if encoded.as_str().len() % 4 != 0 {
                    continue;
                }
                if let Ok(bytes) =
                    base64::engine::general_purpose::STANDARD.decode(encoded.as_str())
                    && bytes.len() <= DECODE_LIMIT
                    && bytes
                        .iter()
                        .all(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
                    && let Ok(decoded) = String::from_utf8(bytes)
                {
                    push_candidate(decoded, &mut candidates, &mut next, &mut seen);
                }
            }
            if candidates.len() >= CANDIDATE_LIMIT {
                break;
            }
        }
        frontier = next;
        if frontier.is_empty() || candidates.len() >= CANDIDATE_LIMIT {
            break;
        }
    }
    candidates
}

fn push_candidate(
    mut candidate: String,
    all: &mut Vec<String>,
    next: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    if candidate.len() > DECODE_LIMIT {
        candidate.truncate(DECODE_LIMIT);
    }
    if !candidate.is_empty() && all.len() < CANDIDATE_LIMIT && seen.insert(candidate.clone()) {
        all.push(candidate.clone());
        next.push(candidate);
    }
}

fn decode_entities(value: &str) -> String {
    static NUMERIC: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"&#(?:x([0-9A-Fa-f]{1,6})|([0-9]{1,7}));?").expect("valid entity regex")
    });
    let basic = value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    NUMERIC
        .replace_all(&basic, |captures: &regex::Captures<'_>| {
            let number = captures
                .get(1)
                .and_then(|value| u32::from_str_radix(value.as_str(), 16).ok())
                .or_else(|| captures.get(2)?.as_str().parse().ok());
            number
                .and_then(char::from_u32)
                .map(|value| value.to_string())
                .unwrap_or_else(|| captures[0].to_owned())
        })
        .into_owned()
}

fn decode_javascript(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut position = 0;
    while position < bytes.len() {
        if bytes[position] != b'\\' || position + 1 >= bytes.len() {
            let Some(character) = value[position..].chars().next() else {
                break;
            };
            output.push(character);
            position += character.len_utf8();
            continue;
        }
        match bytes[position + 1] {
            b'u' if position + 6 <= bytes.len() => {
                if let Ok(hex) = std::str::from_utf8(&bytes[position + 2..position + 6])
                    && let Ok(number) = u32::from_str_radix(hex, 16)
                    && let Some(character) = char::from_u32(number)
                {
                    output.push(character);
                    position += 6;
                    continue;
                }
            }
            b'x' if position + 4 <= bytes.len() => {
                if let Ok(hex) = std::str::from_utf8(&bytes[position + 2..position + 4])
                    && let Ok(number) = u8::from_str_radix(hex, 16)
                {
                    output.push(char::from(number));
                    position += 4;
                    continue;
                }
            }
            b'/' | b'\\' | b'\'' | b'"' => {
                output.push(char::from(bytes[position + 1]));
                position += 2;
                continue;
            }
            b'n' | b'r' | b't' => {
                output.push(match bytes[position + 1] {
                    b'n' => '\n',
                    b'r' => '\r',
                    _ => '\t',
                });
                position += 2;
                continue;
            }
            _ => {}
        }
        output.push('\\');
        position += 1;
    }
    output
}

fn response_checks(
    job: &Job,
    response: &HttpObservation,
    baseline: Option<&HttpObservation>,
    report: &mut CrawlReport,
) {
    let content_type = header_values(response, "content-type")
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let text = String::from_utf8_lossy(&response.body);
    let lower = text.to_ascii_lowercase();
    let html = content_type.contains("html")
        || lower.trim_start().starts_with("<!doctype html")
        || lower.trim_start().starts_with("<html");
    let soft_404 = baseline.is_some_and(|baseline| {
        Url::parse(&baseline.url).is_ok_and(|baseline_url| {
            looks_like_soft_404(baseline, response, baseline_url.path(), job.url.path())
        })
    });
    if (200..300).contains(&response.status)
        && !soft_404
        && job.url.path().to_ascii_lowercase().ends_with(".map")
    {
        for issue in super::artifact_analysis::source_map_issues(job.url.as_str(), &response.body) {
            finding(report, job, issue.title, issue.description, issue.evidence);
        }
    } else if (200..300).contains(&response.status)
        && !soft_404
        && secret_scannable_path(job.url.path())
    {
        for issue in super::artifact_analysis::text_artifact_secret_issues(
            job.url.as_str(),
            &response.body,
            None,
        ) {
            finding(report, job, issue.title, issue.description, issue.evidence);
        }
    }
    if html {
        for issue in super::browser_policy::response_issues(response, &job.origin.scheme, true) {
            finding(report, job, issue.title, issue.description, issue.evidence);
        }
        for nonce in super::browser_policy::csp_nonces(response) {
            if let Some(previous) = report.csp_nonce_sources.get(&nonce).cloned()
                && previous != job.url.as_str()
            {
                finding(
                    report,
                    job,
                    "Content-Security-Policy nonce is reused",
                    "A script nonce was reused across distinct document responses",
                    format!(
                        "Nonce reused by {} and {}; nonce value withheld",
                        previous,
                        safe_url(&job.url)
                    ),
                );
            } else {
                report.csp_nonce_sources.insert(nonce, safe_url(&job.url));
            }
        }
    }
    for cookie in header_values(response, "set-cookie") {
        let (pair, attributes) = cookie.split_once(';').unwrap_or((cookie, ""));
        let Some((name, _)) = pair.split_once('=') else {
            continue;
        };
        let lower_name = name.trim().to_ascii_lowercase();
        if !["session", "sess", "sid", "auth", "token", "jwt"]
            .iter()
            .any(|value| lower_name.contains(value))
        {
            continue;
        }
        let attributes = attributes.to_ascii_lowercase();
        let mut missing = Vec::new();
        if job.origin.scheme == "https"
            && !attributes.split(';').any(|value| value.trim() == "secure")
        {
            missing.push("Secure");
        }
        if !attributes
            .split(';')
            .any(|value| value.trim() == "httponly")
        {
            missing.push("HttpOnly");
        }
        if !attributes
            .split(';')
            .any(|value| value.trim_start().starts_with("samesite="))
        {
            missing.push("SameSite");
        }
        if !missing.is_empty() {
            finding(
                report,
                job,
                "Session-like cookie attributes are missing",
                "A session-like cookie omits applicable browser protections",
                format!(
                    "{} sets cookie {} without {}",
                    job.url,
                    name.trim().chars().take(80).collect::<String>(),
                    missing.join(", ")
                ),
            );
        }
    }
    for header in ["server", "x-powered-by", "x-generator"] {
        for value in header_values(response, header) {
            if VERSION_HINT.is_match(value)
                && report
                    .technology_version_disclosures
                    .insert(TechnologyVersionDisclosureKey {
                        ip: job.origin.ip,
                        port: job.origin.port,
                        header,
                        value: value.to_owned(),
                    })
            {
                finding(
                    report,
                    job,
                    "Technology version disclosed",
                    "An HTTP response header discloses a technology version",
                    format!(
                        "{}: {} at {}",
                        match header {
                            "server" => "Server",
                            "x-powered-by" => "X-Powered-By",
                            _ => "X-Generator",
                        },
                        value.chars().take(160).collect::<String>(),
                        job.url
                    ),
                );
            }
        }
    }
    check_signature(
        report,
        job,
        &lower,
        "Directory listing exposed",
        "The response appears to expose a browsable directory index",
        &[
            "<title>index of /",
            "directory listing for",
            "parent directory",
        ],
    );
    check_signature(
        report,
        job,
        &lower,
        "Stack trace or debug output exposed",
        "The response contains diagnostic or stack-trace markers",
        &[
            "traceback (most recent call last)",
            "stack trace:",
            "debug toolbar",
            "xdebug error",
            "exception in thread",
        ],
    );
    check_signature(
        report,
        job,
        &lower,
        "Configuration information exposed",
        "The response contains configuration-file or runtime configuration markers",
        &["database_url=", "db_password=", "app_secret=", "phpinfo()"],
    );
    check_signature(
        report,
        job,
        &lower,
        "API specification exposed",
        "The response contains an OpenAPI or Swagger document signature",
        &["\"openapi\"", "\"swagger\"", "swagger-ui"],
    );
}

fn secret_scannable_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.ends_with(".env")
        || path.contains("/.env.")
        || path.ends_with("config.php")
        || path.ends_with("wp-config.php")
        || path.ends_with("web.config")
        || path.ends_with("appsettings.json")
        || path.ends_with("application.properties")
        || path.ends_with("bootstrap.properties")
        || path.ends_with("settings.py")
        || path.ends_with("credentials.yml")
        || path.ends_with("credentials")
        || path.ends_with("jenkinsfile")
        || path.ends_with(".gitlab-ci.yml")
        || path.ends_with("azure-pipelines.yml")
        || path.ends_with("bitbucket-pipelines.yml")
        || path.ends_with(".travis.yml")
        || path.contains("/.github/workflows/")
        || path.contains("/.circleci/")
        || path.ends_with("buildspec.yml")
}

fn check_signature(
    report: &mut CrawlReport,
    job: &Job,
    body: &str,
    title: &str,
    description: &str,
    signatures: &[&str],
) {
    if let Some(signature) = signatures.iter().find(|value| body.contains(**value)) {
        finding(
            report,
            job,
            title,
            description,
            format!("Signature '{signature}' detected at {}", job.url),
        );
    }
}

fn detect_surface(
    url: &Url,
    response: &HttpObservation,
    baseline: Option<&HttpObservation>,
) -> Option<(WebSurfaceType, Confidence, String)> {
    let baseline = baseline?;
    let authentication_redirect = authentication_redirect(url, response);
    if !(200..300).contains(&response.status)
        && !matches!(response.status, 401 | 403)
        && authentication_redirect.is_none()
    {
        return None;
    }
    if is_asset_like_path(url) || is_binary_content(response) {
        return None;
    }
    let baseline_url = Url::parse(&baseline.url).ok()?;
    if looks_like_soft_404(baseline, response, baseline_url.path(), url.path()) {
        return None;
    }

    let checkout_route = route_evidence(url, &["checkout"]);
    let cart_route = route_evidence(url, &["cart"]);
    let admin_route = route_evidence(url, &["admin"]);
    let login_route = route_evidence(url, &["login", "signin"]);
    let api_route = route_evidence(url, &["api"]);

    if matches!(response.status, 401 | 403) {
        let (surface, route) = if let Some(route) = checkout_route {
            (WebSurfaceType::Checkout, route)
        } else if let Some(route) = cart_route {
            (WebSurfaceType::Cart, route)
        } else if let Some(route) = admin_route {
            (WebSurfaceType::Admin, route)
        } else if let Some(route) = login_route {
            (WebSurfaceType::Login, route)
        } else if let Some(route) = api_route {
            (WebSurfaceType::Api, route)
        } else {
            return None;
        };
        return Some((
            surface,
            Confidence::High,
            format!(
                "Exact {route}; access-control response HTTP {} corroborates the application route",
                response.status
            ),
        ));
    }

    if let Some(authentication_redirect) = authentication_redirect {
        let classified = if let Some(route) = checkout_route {
            (WebSurfaceType::Checkout, route)
        } else if let Some(route) = cart_route {
            (WebSurfaceType::Cart, route)
        } else if let Some(route) = admin_route {
            (WebSurfaceType::Admin, route)
        } else if let Some(route) = login_route {
            (WebSurfaceType::Login, route)
        } else if let Some(route) = api_route {
            (WebSurfaceType::Api, route)
        } else {
            return Some((
                WebSurfaceType::Login,
                Confidence::High,
                authentication_redirect,
            ));
        };
        let (surface, route) = classified;
        return Some((
            surface,
            Confidence::High,
            format!("Exact {route}; {authentication_redirect}"),
        ));
    }

    let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    if let Some(route) = api_route
        && let Some(marker) = api_content_evidence(response, &body)
    {
        return Some((
            WebSurfaceType::Api,
            Confidence::High,
            format!("Exact {route}; {marker}"),
        ));
    }
    if !is_html_response(response, &body) {
        return None;
    }

    let cart_marker = cart_evidence(&body);
    if let Some(route) = checkout_route {
        let marker = checkout_evidence(&body).or_else(|| cart_route.as_ref().and(cart_marker));
        if let Some(marker) = marker {
            return Some((
                WebSurfaceType::Checkout,
                Confidence::High,
                format!("Exact {route}; HTML response contains {marker}"),
            ));
        }
    }
    if let (Some(route), Some(marker)) = (cart_route, cart_marker) {
        return Some((
            WebSurfaceType::Cart,
            Confidence::High,
            format!("Exact {route}; HTML response contains {marker}"),
        ));
    }
    if let Some(route) = admin_route
        && let Some(marker) = administration_evidence(&body)
    {
        return Some((
            WebSurfaceType::Admin,
            Confidence::High,
            format!("Exact {route}; HTML response contains {marker}"),
        ));
    }

    let form = body.contains("<form");
    let password = body.contains("type=\"password\"") || body.contains("type='password'");
    let login_marker = content_marker(
        &body,
        &[
            ("sign in", "sign-in text"),
            ("log in", "log-in text"),
            ("login", "login text"),
        ],
    );
    if form && password {
        if let Some(route) = login_route {
            return Some((
                WebSurfaceType::Login,
                Confidence::High,
                format!("Exact {route}; HTML response contains a form with a password control"),
            ));
        }
        if let Some(marker) = login_marker {
            return Some((
                WebSurfaceType::Login,
                Confidence::High,
                format!("HTML response contains a form, a password control, and {marker}"),
            ));
        }
    }
    None
}

fn automatic_probe_reportable(
    url: &Url,
    response: &HttpObservation,
    baseline: Option<&HttpObservation>,
) -> bool {
    (200..300).contains(&response.status)
        && !response.body.is_empty()
        && !baseline.is_some_and(|baseline| {
            Url::parse(&baseline.url).is_ok_and(|baseline_url| {
                looks_like_soft_404(baseline, response, baseline_url.path(), url.path())
            })
        })
}

fn route_evidence(url: &Url, expected: &[&str]) -> Option<String> {
    let path = percent_decode_str(url.path())
        .decode_utf8_lossy()
        .to_ascii_lowercase();
    for component in route_components(&path) {
        if expected.contains(&component) {
            return Some(format!("path route component '{component}'"));
        }
    }
    for (name, value) in url.query_pairs() {
        let name = name.to_ascii_lowercase();
        if !matches!(
            name.as_ref(),
            "route" | "path" | "page" | "action" | "controller" | "view"
        ) {
            continue;
        }
        let value = value.to_ascii_lowercase();
        for component in route_components(&value) {
            if expected.contains(&component) {
                return Some(format!(
                    "query route component '{component}' in parameter '{name}'"
                ));
            }
        }
    }
    None
}

fn route_components(value: &str) -> impl Iterator<Item = &str> {
    value.split(['/', '\\']).filter_map(|component| {
        let component = component.split(';').next().unwrap_or_default().trim();
        let component = [".php", ".asp", ".aspx", ".htm", ".html"]
            .iter()
            .find_map(|extension| component.strip_suffix(extension))
            .unwrap_or(component);
        (!component.is_empty()).then_some(component)
    })
}

fn content_marker<'a>(body: &str, markers: &'a [(&str, &'a str)]) -> Option<&'a str> {
    markers
        .iter()
        .find_map(|(needle, evidence)| body.contains(needle).then_some(*evidence))
}

fn administration_evidence(body: &str) -> Option<&'static str> {
    let identifies_administration = ["administration", "admin", "dashboard", "control panel"]
        .iter()
        .any(|marker| body.contains(marker));
    let has_controls = [
        "<form",
        "navigation",
        "<nav",
        "menu",
        "log out",
        "logout",
        "settings",
        "manage users",
        "user management",
        "roles",
    ]
    .iter()
    .any(|marker| body.contains(marker));
    (identifies_administration && has_controls).then_some("administration controls")
}

fn cart_evidence(body: &str) -> Option<&'static str> {
    if ["shopping cart", "your cart", "cart items", "empty cart"]
        .iter()
        .any(|marker| body.contains(marker))
    {
        return Some("cart content markers");
    }
    let identifies_cart = body.contains("cart") || body.contains("basket");
    let has_controls = [
        "quantity",
        "subtotal",
        "remove item",
        "line-item",
        "item_count",
    ]
    .iter()
    .any(|marker| body.contains(marker));
    (identifies_cart && has_controls).then_some("cart item-management controls")
}

fn checkout_evidence(body: &str) -> Option<&'static str> {
    let identifies_checkout = body.contains("checkout") || body.contains("order summary");
    let has_controls = [
        "proceed to checkout",
        "payment",
        "billing",
        "shipping",
        "place order",
        "order summary",
    ]
    .iter()
    .any(|marker| body.contains(marker));
    (identifies_checkout && has_controls).then_some("checkout order or payment controls")
}

fn authentication_redirect(url: &Url, response: &HttpObservation) -> Option<String> {
    if !(300..400).contains(&response.status) {
        return None;
    }
    let location = response.redirect_location.as_deref()?;
    let target = url.join(location).ok()?;
    let authentication_route = route_evidence(
        &target,
        &[
            "login",
            "signin",
            "sign-in",
            "auth",
            "authenticate",
            "authentication",
            "oauth",
            "authorize",
            "sso",
        ],
    )
    .is_some();
    let authentication_host = target.host_str().is_some_and(|host| {
        host.split('.')
            .any(|component| crate::matches_ascii(component, &["login", "signin", "auth", "sso"]))
    });
    (authentication_route || authentication_host).then(|| {
        format!(
            "authentication redirect to {}",
            redact_url(&target).chars().take(2048).collect::<String>()
        )
    })
}

fn is_html_response(response: &HttpObservation, lower_body: &str) -> bool {
    header_values(response, "content-type").any(|value| value.to_ascii_lowercase().contains("html"))
        || lower_body.trim_start().starts_with("<!doctype html")
        || lower_body.trim_start().starts_with("<html")
}

fn is_binary_content(response: &HttpObservation) -> bool {
    header_values(response, "content-type").any(|value| {
        let value = value.to_ascii_lowercase();
        value.starts_with("image/")
            || value.starts_with("audio/")
            || value.starts_with("video/")
            || value.starts_with("font/")
            || [
                "application/octet-stream",
                "application/pdf",
                "application/zip",
                "application/gzip",
                "application/x-rar",
                "application/x-7z",
                "application/wasm",
            ]
            .iter()
            .any(|binary| value.contains(binary))
    })
}

fn is_asset_like_path(url: &Url) -> bool {
    let path = percent_decode_str(url.path())
        .decode_utf8_lossy()
        .to_ascii_lowercase();
    let path = path.split(';').next().unwrap_or(&path);
    [
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif", ".css", ".js", ".mjs",
        ".map", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".webm", ".wav", ".pdf",
        ".zip", ".gz", ".rar", ".7z", ".wasm",
    ]
    .iter()
    .any(|extension| path.ends_with(extension))
}

fn api_content_evidence(response: &HttpObservation, lower_body: &str) -> Option<&'static str> {
    if let Ok(document) = serde_json::from_slice::<serde_json::Value>(&response.body) {
        if document
            .as_object()
            .is_some_and(|object| object.contains_key("openapi") || object.contains_key("swagger"))
        {
            return Some("validated OpenAPI or Swagger document marker");
        }
        if document
            .as_object()
            .is_some_and(|object| !object.is_empty())
            || document.as_array().is_some()
        {
            return Some("validated structured JSON response body");
        }
    }
    if lower_body.contains("swagger-ui")
        && (lower_body.contains("swagger-ui-bundle")
            || lower_body.contains("openapi")
            || lower_body.contains("swagger"))
    {
        return Some("validated Swagger UI markers");
    }
    None
}

fn observe_surface(
    report: &mut CrawlReport,
    job: &Job,
    response: &HttpObservation,
    surface_type: WebSurfaceType,
    confidence: Confidence,
    evidence: String,
) {
    let url = safe_url(&job.url);
    let access_control = if matches!(response.status, 401 | 403) {
        format!(
            "Access control: anonymous GET was denied with HTTP {}",
            response.status
        )
    } else if let Some(redirect) = authentication_redirect(&job.url, response) {
        format!("Access control: anonymous GET received {redirect}")
    } else {
        format!(
            "Access control: anonymous GET returned HTTP {}; no authorization bypass was tested or demonstrated",
            response.status
        )
    };
    if let Some(existing) = report.observed_web_surfaces.iter_mut().find(|observed| {
        observed.ip == job.origin.ip
            && observed.port == job.origin.port
            && observed.url == url
            && observed.surface_type == surface_type
    }) {
        existing.confidence = existing.confidence.max(confidence);
        existing.evidence.extend([evidence, access_control]);
        existing.evidence.sort();
        existing.evidence.dedup();
        return;
    }
    let candidate_key = (job.origin.ip, job.origin.port, url.as_str(), surface_type);
    if report.observed_web_surfaces.len() >= OBSERVED_SURFACE_LIMIT {
        let Some((largest_index, largest)) = report
            .observed_web_surfaces
            .iter()
            .enumerate()
            .max_by_key(|(_, observed)| {
                (
                    observed.ip,
                    observed.port,
                    observed.url.as_str(),
                    observed.surface_type,
                )
            })
        else {
            return;
        };
        let largest_key = (
            largest.ip,
            largest.port,
            largest.url.as_str(),
            largest.surface_type,
        );
        if candidate_key >= largest_key {
            return;
        }
        report.observed_web_surfaces.swap_remove(largest_index);
    }
    report.observed_web_surfaces.push(CrawlObservedWebSurface {
        ip: job.origin.ip,
        port: job.origin.port,
        url,
        status: response.status,
        surface_type,
        confidence,
        evidence: vec![evidence, access_control],
    });
}

async fn enqueue_reference(
    origins: &mut BTreeMap<OriginKey, OriginState>,
    queue: &mut VecDeque<Job>,
    report: &mut CrawlReport,
    job: &Job,
    base_url: &Url,
    reference: &str,
    depth: usize,
    provenance: JobProvenance,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    session: &mut CrawlSession,
) -> bool {
    let reference = reference.trim();
    if reference.is_empty() {
        return false;
    }
    collect_personal_information(reference, job, report);
    let parsed = match base_url.join(reference) {
        Ok(url) => url,
        Err(error) => {
            skip(
                report,
                Some(job.url.as_str()),
                reference,
                &format!("Malformed URL: {error}"),
            );
            return false;
        }
    };
    let url = match normalize_url(parsed) {
        Ok(url) => url,
        Err(reason) => {
            skip(report, Some(job.url.as_str()), reference, &reason);
            return false;
        }
    };
    let hostname = canonical_hostname(url.host_str().expect("normalized URL has a hostname"));
    if !session.scope.allows(&hostname) {
        let redacted = redact_url(&url);
        external(
            report,
            job.url.as_str(),
            "URL",
            &redacted,
            "Off-host URL reference",
        );
        skip(
            report,
            Some(job.url.as_str()),
            &redacted,
            "Outside crawl domain",
        );
        return false;
    }
    let text = url.to_string();
    let resolution = resolve_crawl_host(&hostname, cancel, session).await;
    for (address, reason) in &resolution.rejected {
        skip(
            report,
            Some(job.url.as_str()),
            &text,
            &format!("Unsafe resolved address {address}: {reason}"),
        );
    }
    if let Some(error) = resolution.error.as_deref() {
        skip(
            report,
            Some(job.url.as_str()),
            &text,
            &format!("DNS resolution failed for {hostname}: {error}"),
        );
        return false;
    }
    let Some(&resolved_ip) = resolution.addresses.first() else {
        skip(
            report,
            Some(job.url.as_str()),
            &text,
            &format!("{hostname} has no publicly routable A or AAAA address"),
        );
        return false;
    };
    let ip = if hostname == job.origin.hostname && resolution.addresses.contains(&job.origin.ip) {
        job.origin.ip
    } else {
        resolved_ip
    };
    let key = OriginKey {
        ip,
        scheme: url.scheme().to_owned(),
        hostname,
        port: url.port_or_known_default().unwrap_or_default(),
    };
    let new_origin = !origins.contains_key(&key);
    if new_origin {
        create_origin(origins, &key, &url, &session.baseline_path);
        enqueue_origin_baseline(
            origins,
            queue,
            report,
            &key,
            request.crawl_max_urls,
            session,
        );
    }
    let enqueued = enqueue_url(
        origins,
        queue,
        report,
        key.clone(),
        url.clone(),
        depth,
        Some(job.url.to_string()),
        provenance,
        request.crawl_max_urls,
        session,
    );
    if new_origin && let Ok(robots) = url.join("/robots.txt") {
        enqueue_url(
            origins,
            queue,
            report,
            key,
            robots,
            0,
            Some(url.to_string()),
            JobProvenance::AutomaticProbe,
            request.crawl_max_urls,
            session,
        );
    }
    enqueued
}

fn enqueue_url(
    origins: &mut BTreeMap<OriginKey, OriginState>,
    queue: &mut VecDeque<Job>,
    report: &mut CrawlReport,
    key: OriginKey,
    url: Url,
    depth: usize,
    source: Option<String>,
    provenance: JobProvenance,
    max_urls: usize,
    session: &mut CrawlSession,
) -> bool {
    let original_text = url.to_string();
    let url = match normalize_url(url) {
        Ok(url) => url,
        Err(reason) => {
            skip(report, source.as_deref(), &original_text, &reason);
            return false;
        }
    };
    let Some(origin) = origins.get_mut(&key) else {
        return false;
    };
    let text = url.to_string();
    if provenance.is_reportable_url() {
        session.reportable_urls.insert(text.clone());
    }
    let budget_reached = session.endpoint_states.len() >= max_urls;
    let endpoint = match session.endpoint_states.entry(text.clone()) {
        Entry::Occupied(_) => return false,
        Entry::Vacant(endpoint) => endpoint,
    };
    if budget_reached {
        skip(
            report,
            source.as_deref(),
            &text,
            "Domain URL budget reached",
        );
        return false;
    }
    if let Some(query) = url.query() {
        let mut base = url.clone();
        base.set_query(None);
        let variants = session.query_variants.entry(base.to_string()).or_default();
        if !variants.contains(query) && variants.len() >= 10 {
            skip(
                report,
                source.as_deref(),
                &text,
                "Query-variant limit reached for path",
            );
            return false;
        }
        variants.insert(query.to_owned());
    }
    endpoint.insert(EndpointState::Queued);
    origin.report.queued += 1;
    queue.push_back(Job {
        origin: key,
        url,
        depth,
        source,
        provenance,
    });
    true
}

async fn resolve_crawl_host(
    hostname: &str,
    cancel: &CancellationToken,
    session: &mut CrawlSession,
) -> HostResolution {
    if let Some(resolution) = session.resolutions.get(hostname) {
        return resolution.clone();
    }
    let mut dns = DnsTrace::default();
    let result = tokio::select! {
        _ = cancel.cancelled() => Err("Crawl cancelled during name resolution".to_owned()),
        result = resolve_host(hostname, &mut dns) => result,
    };
    let mut resolution = HostResolution {
        addresses: Vec::new(),
        rejected: Vec::new(),
        error: result.err(),
    };
    if resolution.error.is_none() {
        let mut seen = HashSet::new();
        for address in dns.addresses {
            if !seen.insert(address) {
                continue;
            }
            if let Some(reason) = non_public_reason(address) {
                resolution.rejected.push((address, reason));
            } else {
                resolution.addresses.push(address);
            }
        }
        resolution.addresses.sort();
        resolution.rejected.sort_by_key(|(address, _)| *address);
        if resolution.addresses.is_empty() && resolution.rejected.is_empty() {
            resolution.error = Some("DNS returned no A or AAAA addresses".to_owned());
        }
    }
    session
        .resolutions
        .insert(hostname.to_owned(), resolution.clone());
    resolution
}

fn create_origin(
    origins: &mut BTreeMap<OriginKey, OriginState>,
    key: &OriginKey,
    seed: &Url,
    baseline_path: &str,
) {
    origins.entry(key.clone()).or_insert_with(|| OriginState {
        report: CrawlOrigin {
            ip: key.ip,
            scheme: key.scheme.clone(),
            hostname: key.hostname.clone(),
            port: key.port,
            seed_url: safe_url(seed),
            queued: 0,
            completed: 0,
            robots_exclusions: Vec::new(),
            sitemap_urls: Vec::new(),
        },
        baseline_url: seed
            .join(baseline_path)
            .expect("constructed baseline URL is valid"),
        baseline: None,
        baseline_complete: false,
        deferred: Vec::new(),
    });
}

pub(super) fn normalize_url(mut url: Url) -> Result<Url, String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err("Non-HTTP scheme".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Embedded credentials".to_owned());
    }
    if url.host_str().is_none() {
        return Err("URL has no hostname".to_owned());
    }
    if url.as_str().len() > 2048 {
        return Err("URL exceeds 2,048 characters".to_owned());
    }
    url.set_fragment(None);
    let mut pairs = url
        .query_pairs()
        .filter(|(name, _)| {
            let name = name.to_ascii_lowercase();
            !name.starts_with("utm_") && !matches!(name.as_ref(), "gclid" | "fbclid" | "msclkid")
        })
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    pairs.sort();
    url.set_query(None);
    if !pairs.is_empty() {
        url.query_pairs_mut().extend_pairs(pairs);
    }
    if (url.scheme() == "http" && url.port() == Some(80))
        || (url.scheme() == "https" && url.port() == Some(443))
    {
        let _ = url.set_port(None);
    }
    (url.as_str().len() <= 2048)
        .then_some(url)
        .ok_or_else(|| "URL exceeds 2,048 characters".to_owned())
}

fn parse_html(text: &str) -> HtmlDiscovery {
    let input = BufferQueue::default();
    input.push_back(StrTendril::from(text));
    let tokenizer = Tokenizer::new(
        HtmlSink(RefCell::new(HtmlState::default())),
        Default::default(),
    );
    let _ = tokenizer.feed(&input);
    tokenizer.end();
    tokenizer.sink.0.into_inner().result
}

fn html_base_url(document_url: &Url, candidates: &[String]) -> Url {
    candidates
        .iter()
        .find_map(|candidate| {
            document_url
                .join(candidate.trim())
                .ok()
                .and_then(|url| normalize_url(url).ok())
        })
        .unwrap_or_else(|| document_url.clone())
}

fn html_ref(result: &mut HtmlDiscovery, value: Option<String>, kind: &str, active: bool) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        result.references.push(HtmlReference {
            value,
            kind: kind.to_owned(),
            active,
        });
    }
}

fn refresh_url(value: &str) -> Option<String> {
    let (_, value) = value.split_once(';')?;
    let (_, value) = value.split_once('=')?;
    Some(value.trim().trim_matches(['\'', '"']).to_owned())
}

fn sitemap_locations(text: &str) -> Vec<String> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut in_location = false;
    let mut locations = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                in_location = element.name().as_ref().eq_ignore_ascii_case(b"loc")
            }
            Ok(Event::Text(value)) if in_location => {
                if let Ok(value) = value.decode() {
                    locations.push(decode_entities(value.trim()));
                }
            }
            Ok(Event::End(element)) if element.name().as_ref().eq_ignore_ascii_case(b"loc") => {
                in_location = false
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    locations
}

fn is_textual(url: &Url, content_type: Option<&str>) -> bool {
    if let Some(content_type) = content_type {
        let content_type = content_type.to_ascii_lowercase();
        return ["text/", "javascript", "ecmascript", "json", "xml"]
            .iter()
            .any(|value| content_type.contains(value));
    }
    let path = url.path().to_ascii_lowercase();
    ![
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".zip", ".pdf",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
}

fn redact_url(url: &Url) -> String {
    let mut redacted = url.clone();
    if redacted.query().is_some() {
        let names = redacted
            .query_pairs()
            .map(|(name, _)| name.into_owned())
            .collect::<Vec<_>>();
        redacted.set_query(None);
        redacted
            .query_pairs_mut()
            .extend_pairs(names.into_iter().map(|name| (name, "<redacted>")));
    }
    redacted.to_string()
}

fn safe_url(url: &Url) -> String {
    let mut safe = url.clone();
    if !safe.username().is_empty() || safe.password().is_some() {
        let _ = safe.set_username("redacted");
        let _ = safe.set_password(None);
    }
    let pairs = safe
        .query_pairs()
        .map(|(name, value)| {
            let value = if sensitive_name(&name) {
                "<redacted>".to_owned()
            } else {
                value.into_owned()
            };
            (name.into_owned(), value)
        })
        .collect::<Vec<_>>();
    safe.set_query(None);
    if !pairs.is_empty() {
        safe.query_pairs_mut().extend_pairs(pairs);
    }
    safe.to_string()
}

fn redact_url_text(value: &str) -> String {
    Url::parse(value)
        .map(|url| safe_url(&url))
        .unwrap_or_else(|_| value.to_owned())
}

fn sensitive_name(name: &str) -> bool {
    let normalized = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "authorization",
        "credential",
        "session",
        "sid",
        "jwt",
    ]
    .iter()
    .any(|value| normalized == *value || normalized.ends_with(value))
}

fn collect_personal_information(text: &str, job: &Job, report: &mut CrawlReport) {
    for captures in EMAIL_HINT.captures_iter(text).take(CANDIDATE_LIMIT) {
        let Some(full) = captures.get(0) else {
            continue;
        };
        let Some(value) = captures.get(1) else {
            continue;
        };
        if contact_boundaries(text, full.start(), full.end()) && valid_email(value.as_str()) {
            record_contact(
                report,
                job,
                CrawlContactType::Email,
                value.as_str(),
                value.as_str().to_ascii_lowercase(),
            );
        }
    }
    for matched in PHONE_HINT.find_iter(text).take(CANDIDATE_LIMIT) {
        if !contact_boundaries(text, matched.start(), matched.end()) {
            continue;
        }
        let candidate = matched.as_str();
        let explicit_tel = candidate
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("tel:"));
        let value = if explicit_tel {
            candidate[4..].trim()
        } else {
            candidate.trim()
        };
        if let Some(normalized_value) = normalize_phone(value, explicit_tel) {
            record_contact(
                report,
                job,
                CrawlContactType::Telephone,
                value,
                normalized_value,
            );
        }
    }
}

fn record_contact(
    report: &mut CrawlReport,
    job: &Job,
    contact_type: CrawlContactType,
    value: &str,
    normalized_value: String,
) {
    let record = report
        .contact_records
        .entry(ContactKey {
            contact_type,
            normalized_value,
        })
        .or_insert_with(|| CrawlContactRecord {
            value: value.to_owned(),
            urls: HashSet::new(),
        });
    record.urls.insert(job.url.as_str().to_owned());
}

fn contact_boundaries(text: &str, start: usize, end: usize) -> bool {
    let mut before = text[..start].chars().rev();
    if let Some(character) = before.next() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '@') {
            return false;
        }
        if matches!(character, '-' | '/' | '.')
            && before
                .next()
                .is_some_and(|character| character.is_ascii_alphanumeric())
        {
            return false;
        }
    }
    let mut after = text[end..].chars();
    if let Some(character) = after.next() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '@') {
            return false;
        }
        if matches!(character, '-' | '/' | '.')
            && after
                .next()
                .is_some_and(|character| character.is_ascii_alphanumeric())
        {
            return false;
        }
    }
    true
}

fn valid_email(value: &str) -> bool {
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    let domain = domain.to_ascii_lowercase();
    !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.len() <= 64
        && value.len() <= 254
        && domain.len() <= 253
        && psl::suffix(domain.as_bytes()).is_some_and(|suffix| suffix.is_known())
}

fn normalize_phone(value: &str, explicit_tel: bool) -> Option<String> {
    if value.bytes().filter(|byte| *byte == b'+').count() > 1
        || (value.contains('+') && !value.trim_start().starts_with('+'))
    {
        return None;
    }
    if !valid_phone_formatting(value) {
        return None;
    }

    let compact = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    if likely_decimal_number(&compact) {
        return None;
    }
    let digits = value
        .chars()
        .filter(|character| character.is_ascii_digit())
        .collect::<String>();
    if explicit_tel {
        return (7..=15)
            .contains(&digits.len())
            .then(|| normalize_nz_phone(&digits, value.starts_with('+')).unwrap_or(digits));
    }

    if value.starts_with('+') {
        if !(8..=15).contains(&digits.len())
            || digits.starts_with('0')
            || (digits.starts_with('1') && digits.len() != 11)
        {
            return None;
        }
        return if digits.starts_with("64") {
            normalize_nz_phone(&digits, true)
        } else {
            Some(digits)
        };
    }

    if compact.parse::<Ipv4Addr>().is_ok()
        || likely_numeric_date(&compact)
        || likely_semantic_version(&compact)
        || !digits.starts_with('0')
    {
        return None;
    }
    normalize_nz_phone(&digits, false)
}

fn normalize_nz_phone(digits: &str, international: bool) -> Option<String> {
    let national = if international {
        digits.strip_prefix("64")?
    } else {
        digits.strip_prefix('0').unwrap_or(digits)
    };
    if national.starts_with('0') || !valid_nz_national_number(national) {
        return None;
    }
    Some(format!("64{national}"))
}

fn valid_nz_national_number(national: &str) -> bool {
    (national.len() == 8
        && matches!(
            national.as_bytes().first(),
            Some(b'3' | b'4' | b'6' | b'7' | b'9')
        ))
        || ((9..=10).contains(&national.len()) && national.starts_with('2'))
        || (national.len() == 9
            && (national.starts_with("70")
                || national.starts_with("508")
                || national.starts_with("800")))
        || ((8..=10).contains(&national.len()) && national.starts_with("900"))
}

fn valid_phone_formatting(value: &str) -> bool {
    let mut inside_parentheses = false;
    let mut parenthetical_digits = 0;
    let mut parenthetical_groups = 0;
    let mut last_punctuation = false;
    for character in value.chars() {
        match character {
            '(' if !inside_parentheses => {
                inside_parentheses = true;
                parenthetical_digits = 0;
                parenthetical_groups += 1;
                last_punctuation = false;
            }
            ')' if inside_parentheses && parenthetical_digits > 0 => {
                inside_parentheses = false;
                last_punctuation = false;
            }
            '0'..='9' => {
                if inside_parentheses {
                    parenthetical_digits += 1;
                }
                last_punctuation = false;
            }
            '-' | '/' | '.' if !inside_parentheses && !last_punctuation => {
                last_punctuation = true;
            }
            '+' | ' ' | '\t' if !inside_parentheses => {}
            _ => return false,
        }
    }
    !inside_parentheses && parenthetical_groups <= 2
}

fn likely_numeric_date(value: &str) -> bool {
    if value.len() == 8 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        let year = value[..4].parse::<u16>().unwrap_or_default();
        let month = value[4..6].parse::<u16>().unwrap_or_default();
        let day = value[6..].parse::<u16>().unwrap_or_default();
        if (1900..=2100).contains(&year) && valid_month_day(month, day) {
            return true;
        }
    }
    for separator in ['-', '/'] {
        let parts = value.split(separator).collect::<Vec<_>>();
        if parts.len() != 3
            || parts
                .iter()
                .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            continue;
        }
        let numbers = parts
            .iter()
            .map(|part| part.parse::<u16>().unwrap_or_default())
            .collect::<Vec<_>>();
        let first_year = parts[0].len() == 4
            && (1900..=2100).contains(&numbers[0])
            && valid_month_day(numbers[1], numbers[2]);
        let last_year = parts[2].len() == 4
            && (1900..=2100).contains(&numbers[2])
            && (valid_month_day(numbers[1], numbers[0]) || valid_month_day(numbers[0], numbers[1]));
        let short_year = parts.iter().all(|part| part.len() <= 2)
            && (valid_month_day(numbers[1], numbers[0]) || valid_month_day(numbers[0], numbers[1]));
        if first_year || last_year || short_year {
            return true;
        }
    }
    false
}

fn valid_month_day(month: u16, day: u16) -> bool {
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

fn likely_semantic_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() >= 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn likely_decimal_number(value: &str) -> bool {
    let value = value.strip_prefix('+').unwrap_or(value);
    let Some((whole, fractional)) = value.split_once('.') else {
        return false;
    };
    !whole.is_empty()
        && !fractional.is_empty()
        && whole.bytes().all(|byte| byte.is_ascii_digit())
        && fractional.bytes().all(|byte| byte.is_ascii_digit())
}

fn finding(report: &mut CrawlReport, job: &Job, title: &str, description: &str, evidence: String) {
    report.findings.push(ExposureFinding {
        title: title.to_owned(),
        description: description.to_owned(),
        ip: job.origin.ip,
        port: job.origin.port,
        transport: super::TransportProtocol::Tcp,
        evidence: vec![evidence.replace(job.url.as_str(), &safe_url(&job.url))],
        component_kind: None,
    });
}

fn likely_csrf_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "csrf",
        "xsrf",
        "requestverificationtoken",
        "authenticity_token",
        "nonce",
    ]
    .iter()
    .any(|marker| name.contains(marker))
}

fn external(report: &mut CrawlReport, source: &str, kind: &str, value: &str, evidence: &str) {
    report.external_indicators.push(CrawlExternalIndicator {
        source_url: redact_url_text(source),
        kind: kind.to_owned(),
        value: value.chars().take(2048).collect(),
        evidence: evidence.chars().take(160).collect(),
    });
}

fn skip(report: &mut CrawlReport, source: Option<&str>, url: &str, reason: &str) {
    if report.skipped_urls.len() < SKIPPED_LIMIT {
        report.skipped_urls.push(CrawlSkippedUrl {
            source_url: source.map(redact_url_text),
            url: redact_url_text(url).chars().take(2048).collect(),
            reason: reason.to_owned(),
        });
    }
}

fn send_origin_progress(
    progress: &Option<Sender<ExposureScanProgress>>,
    origin: &CrawlOrigin,
    current_url: &str,
) {
    if let Some(progress) = progress {
        let _ = progress.send(ExposureScanProgress::CrawlProgress {
            origin: format!(
                "{}://{}:{} ({})",
                origin.scheme, origin.hostname, origin.port, origin.ip
            ),
            queued: origin.queued,
            completed: origin.completed,
            current_url: current_url.to_owned(),
        });
    }
}

fn send_global_progress(
    progress: &Option<Sender<ExposureScanProgress>>,
    origins: &BTreeMap<OriginKey, OriginState>,
    current_url: Option<&str>,
    state: ExposureScanPhaseState,
) {
    let queued = origins
        .values()
        .map(|origin| origin.report.queued)
        .sum::<usize>();
    let completed = origins
        .values()
        .map(|origin| origin.report.completed)
        .sum::<usize>();
    let fraction = if state == ExposureScanPhaseState::Complete {
        1.0
    } else {
        completed as f32 / queued.max(1) as f32
    };
    let text = match current_url {
        Some(url) => format!("{completed} / {queued} URLs — {url}"),
        None if state == ExposureScanPhaseState::Complete => {
            format!("{completed} / {queued} URLs")
        }
        None => format!("{completed} / {queued} URLs queued"),
    };
    send_phase_progress(progress, ExposureScanPhase::Crawl, state, fraction, text);
}

fn finish(report: &mut CrawlReport, reportable_urls: &HashSet<String>) {
    report.contacts = std::mem::take(&mut report.contact_records)
        .into_iter()
        .map(|(key, record)| {
            let mut endpoints = record.urls.into_iter().collect::<Vec<_>>();
            endpoints.sort();
            CrawlContact {
                contact_type: key.contact_type,
                value: record.value,
                endpoints,
            }
        })
        .collect();
    for origin in &mut report.origins {
        origin.robots_exclusions.sort();
        origin.robots_exclusions.dedup();
        origin.sitemap_urls.sort();
        origin.sitemap_urls.dedup();
    }
    report.origins.sort_by(|left, right| {
        left.ip
            .cmp(&right.ip)
            .then(left.scheme.cmp(&right.scheme))
            .then(left.port.cmp(&right.port))
    });
    report.resources.extend(
        report
            .resource_records
            .drain(..)
            .filter(|record| {
                record.provenance.is_reportable_url()
                    || record.probe_reportable
                    || reportable_urls.contains(&record.url)
            })
            .map(|record| record.resource),
    );
    report
        .resources
        .retain(|resource| !matches!(resource.status, Some(400..=499)));
    let mut resources = BTreeMap::<ResourceKey, CrawledResource>::new();
    for resource in report.resources.drain(..) {
        let key = ResourceKey::from(&resource);
        if let Some(existing) = resources.get_mut(&key) {
            retain_smallest_optional_source(&mut existing.source_url, resource.source_url);
        } else {
            resources.insert(key, resource);
        }
    }
    report.resources = resources.into_values().collect();
    report.resources.sort_by(|left, right| {
        left.ip
            .cmp(&right.ip)
            .then(left.port.cmp(&right.port))
            .then(left.url.cmp(&right.url))
    });
    let mut forms = BTreeMap::<FormKey, CrawlFormAction>::new();
    for mut form in report.forms.drain(..) {
        form.method = normalized_form_method(&form.method);
        let key = FormKey {
            method: form.method.clone(),
            action_url: form.action_url.clone(),
        };
        if let Some(existing) = forms.get_mut(&key) {
            retain_smallest_source(&mut existing.source_url, form.source_url);
            existing.has_password |= form.has_password;
            existing.enqueued |= form.enqueued;
            existing.likely_csrf_tokens.extend(form.likely_csrf_tokens);
            existing.controls.extend(form.controls);
            existing.likely_csrf_tokens.sort();
            existing.likely_csrf_tokens.dedup();
            existing.controls.sort_by(|left, right| {
                left.name
                    .cmp(&right.name)
                    .then(left.control_type.cmp(&right.control_type))
            });
            existing.controls.dedup();
        } else {
            forms.insert(key, form);
        }
    }
    report.forms = forms.into_values().collect();
    report.forms.sort_by(|left, right| {
        left.source_url
            .cmp(&right.source_url)
            .then(left.action_url.cmp(&right.action_url))
            .then(left.method.cmp(&right.method))
    });
    let mut external_indicators = BTreeMap::<ExternalIndicatorKey, CrawlExternalIndicator>::new();
    for indicator in report.external_indicators.drain(..) {
        let key = ExternalIndicatorKey {
            value: indicator.value.clone(),
            source_url: indicator.source_url.clone(),
        };
        external_indicators.entry(key).or_insert(indicator);
    }
    report.external_indicators = external_indicators.into_values().collect();
    report.external_indicators.sort_by(|left, right| {
        left.value
            .cmp(&right.value)
            .then(left.source_url.cmp(&right.source_url))
    });
    let mut skipped_urls = BTreeMap::<SkippedUrlKey, CrawlSkippedUrl>::new();
    for skipped in report.skipped_urls.drain(..) {
        let key = SkippedUrlKey {
            url: skipped.url.clone(),
            reason: skipped.reason.clone(),
        };
        if let Some(existing) = skipped_urls.get_mut(&key) {
            retain_smallest_optional_source(&mut existing.source_url, skipped.source_url);
        } else {
            skipped_urls.insert(key, skipped);
        }
    }
    report.skipped_urls = skipped_urls.into_values().collect();
    report.skipped_urls.sort_by(|left, right| {
        left.url
            .cmp(&right.url)
            .then(left.reason.cmp(&right.reason))
            .then(left.source_url.cmp(&right.source_url))
    });
    for observed in &mut report.observed_web_surfaces {
        observed.evidence.sort();
        observed.evidence.dedup();
    }
    report.observed_web_surfaces.sort_by(|left, right| {
        left.ip
            .cmp(&right.ip)
            .then(left.port.cmp(&right.port))
            .then(left.url.cmp(&right.url))
            .then(left.surface_type.cmp(&right.surface_type))
    });
    let mut findings = BTreeMap::<(IpAddr, u16, TransportProtocol, String), ExposureFinding>::new();
    for finding in report.findings.drain(..) {
        let key = (
            finding.ip,
            finding.port,
            finding.transport,
            finding.title.clone(),
        );
        if let Some(existing) = findings.get_mut(&key) {
            existing.evidence.extend(finding.evidence);
        } else {
            findings.insert(key, finding);
        }
    }
    for finding in findings.values_mut() {
        finding.evidence.sort();
        finding.evidence.dedup();
    }
    report.findings = findings.into_values().collect();
}

fn normalized_form_method(method: &str) -> String {
    let method = method.trim();
    if method.is_empty() {
        "GET".to_owned()
    } else {
        method.to_ascii_uppercase()
    }
}

fn retain_smallest_source(current: &mut String, candidate: String) {
    if candidate < *current {
        *current = candidate;
    }
}

fn retain_smallest_optional_source(current: &mut Option<String>, candidate: Option<String>) {
    if let Some(candidate) = candidate
        && current.as_ref().is_none_or(|current| candidate < *current)
    {
        *current = Some(candidate);
    }
}
