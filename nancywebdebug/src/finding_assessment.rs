use super::*;
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::states::RawKind;
use html5ever::tokenizer::{
    BufferQueue, EndTag, StartTag, TagToken, Token, TokenSink, TokenSinkResult, Tokenizer,
};
use regex::Regex;
use std::cell::RefCell;
use std::sync::LazyLock;

static URL_IN_TEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)https?://[^\s<>\"']+"#).unwrap());
static PRIVATE_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie):[^\r\n]*").unwrap()
});
static CSP_SECRET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)'(?:nonce|sha256|sha384|sha512)-[^']*'").unwrap());

pub(super) fn safe_url(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return "URL unavailable".to_owned();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

pub(crate) fn safe_evidence(value: &str) -> String {
    let value = PRIVATE_HEADER.replace_all(value, "$1: [value withheld]");
    let value = CSP_SECRET.replace_all(&value, "'[policy token withheld]'");
    URL_IN_TEXT
        .replace_all(&value, |capture: &regex::Captures<'_>| {
            let raw = capture[0].trim_end_matches([',', ';', ')']);
            let suffix = &capture[0][raw.len()..];
            format!("{}{suffix}", safe_url(raw))
        })
        .into_owned()
}

fn headers<'a>(response: &'a HttpObservation, name: &'a str) -> impl Iterator<Item = &'a str> {
    response
        .headers
        .iter()
        .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[derive(Default)]
struct PolicyMeta {
    policies: Vec<String>,
    referrers: Vec<String>,
    template_depth: usize,
}

struct MetaSink(RefCell<PolicyMeta>);

impl TokenSink for MetaSink {
    type Handle = ();

    fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
        if let TagToken(tag) = token {
            let mut state = self.0.borrow_mut();
            let name = tag.name.as_ref();
            if name == "template" {
                if tag.kind == StartTag {
                    state.template_depth += 1;
                }
                if tag.kind == EndTag {
                    state.template_depth = state.template_depth.saturating_sub(1);
                }
            }
            if tag.kind != StartTag {
                return TokenSinkResult::Continue;
            }
            if name == "meta" && state.template_depth == 0 {
                let attr = |name: &str| {
                    tag.attrs
                        .iter()
                        .find(|attr| attr.name.local.as_ref() == name)
                        .map(|attr| attr.value.as_ref())
                        .unwrap_or("")
                };
                if attr("http-equiv").eq_ignore_ascii_case("content-security-policy")
                    && !attr("content").trim().is_empty()
                {
                    state.policies.push(attr("content").to_owned());
                }
                if attr("name").eq_ignore_ascii_case("referrer") {
                    state.referrers.push(attr("content").to_owned());
                }
            }
            return match name {
                "script" => TokenSinkResult::RawData(RawKind::ScriptData),
                "style" | "xmp" | "iframe" | "noembed" | "noframes" | "noscript" => {
                    TokenSinkResult::RawData(RawKind::Rawtext)
                }
                "title" | "textarea" => TokenSinkResult::RawData(RawKind::Rcdata),
                "plaintext" => TokenSinkResult::Plaintext,
                _ => TokenSinkResult::Continue,
            };
        }
        TokenSinkResult::Continue
    }
}

fn meta_policies(response: &HttpObservation) -> PolicyMeta {
    let input = BufferQueue::default();
    input.push_back(StrTendril::from_slice(&String::from_utf8_lossy(
        &response.body,
    )));
    let tokenizer = Tokenizer::new(
        MetaSink(RefCell::new(PolicyMeta::default())),
        Default::default(),
    );
    let _ = tokenizer.feed(&input);
    tokenizer.end();
    tokenizer.sink.0.into_inner()
}

fn sources<'a>(policy: &'a str, name: &str) -> Option<Vec<&'a str>> {
    policy.split(';').find_map(|directive| {
        let mut parts = directive.split_ascii_whitespace();
        parts
            .next()
            .is_some_and(|part| part.eq_ignore_ascii_case(name))
            .then(|| parts.collect())
    })
}

fn effective_sources<'a>(policy: &'a str, kind: &str) -> Option<Vec<&'a str>> {
    sources(policy, kind)
        .or_else(|| sources(policy, "script-src"))
        .or_else(|| sources(policy, "default-src"))
}

fn permits_inline(policy: &str, kind: &str) -> bool {
    effective_sources(policy, kind).is_none_or(|sources| {
        sources
            .iter()
            .any(|source| source.eq_ignore_ascii_case("'unsafe-inline'"))
            && !sources.iter().any(|source| {
                let source = source.to_ascii_lowercase();
                source == "'strict-dynamic'"
                    || source.starts_with("'nonce-")
                    || source.starts_with("'sha256-")
                    || source.starts_with("'sha384-")
                    || source.starts_with("'sha512-")
            })
    })
}

fn finding(
    ip: IpAddr,
    port: u16,
    title: &str,
    cause: &str,
    url: &str,
    method: &str,
    subject: &str,
) -> ExposureFinding {
    let location = FindingLocation {
        url: Some(safe_url(url)),
        method: Some(method.to_owned()),
        subject: Some(subject.to_owned()),
    };
    ExposureFinding {
        details: vec![FindingDetail {
            cause: cause.to_owned(),
            location,
        }],
        title: title.to_owned(),
        description: cause.to_owned(),
        ip,
        port,
        transport: TransportProtocol::Tcp,
        evidence: vec![format!("{} {} — {}", method, safe_url(url), subject)],
        component_kind: None,
    }
}

pub(super) fn response_findings(
    ip: IpAddr,
    port: u16,
    response: &HttpObservation,
) -> Vec<ExposureFinding> {
    let mut findings = Vec::new();
    let Ok(url) = Url::parse(&response.url) else {
        return findings;
    };
    let mut add = |title: &str, cause: &str, subject: &str| {
        findings.push(finding(
            ip,
            port,
            title,
            cause,
            &response.url,
            &response.method,
            subject,
        ));
    };
    if url.scheme() == "https" && matches!(response.status, 301 | 302 | 303 | 307 | 308) {
        let locations = headers(response, "location").collect::<Vec<_>>();
        let location = if locations.len() == 1 {
            locations.first().copied()
        } else if locations.is_empty() {
            response.redirect_location.as_deref()
        } else {
            None
        };
        if let Some(target) = location
            .and_then(|location| url.join(location).ok())
            .filter(|target| target.scheme() == "http")
        {
            add(
                "HTTPS redirects to cleartext HTTP",
                "An HTTPS response directs the client to an unencrypted HTTP URL",
                &format!(
                    "HTTP {}; Location: {}",
                    response.status,
                    safe_url(target.as_str())
                ),
            );
        }
    }
    if !(200..300).contains(&response.status) {
        return findings;
    }
    let cache = headers(response, "cache-control")
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .collect::<Vec<_>>();
    let directive = |value: &str| {
        value
            .split('=')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    };
    let protected = cache
        .iter()
        .any(|value| matches!(directive(value).as_str(), "private" | "no-store"));
    let public = cache
        .iter()
        .any(|value| value.eq_ignore_ascii_case("public"));
    let shared_ages = cache
        .iter()
        .filter(|value| directive(value) == "s-maxage")
        .collect::<Vec<_>>();
    let shared = shared_ages.len() == 1
        && shared_ages[0]
            .split_once('=')
            .and_then(|(_, value)| value.trim().trim_matches('"').parse::<u64>().ok())
            .is_some_and(|age| age > 0);
    if !protected && (public || shared) {
        let secrets = super::artifact_analysis::text_artifact_secret_issues(
            &response.url,
            &response.body,
            None,
        );
        if !secrets.is_empty() {
            add(
                "Sensitive response permits shared caching",
                "The response contains credential-shaped material and explicitly permits shared caching",
                &format!("Cache-Control: {}", safe_evidence(&cache.join(", "))),
            );
            if let Some(last) = findings.last_mut() {
                last.evidence.extend(
                    secrets
                        .into_iter()
                        .map(|issue| safe_evidence(&issue.evidence)),
                );
            }
        }
    }
    let html = super::browser_policy::is_html(response);
    if !html {
        return findings;
    }
    let meta = meta_policies(response);
    let complete = !response.body_truncated
        && response.framing.completed
        && !response.framing.body_limit_reached
        && !response.framing.read_timed_out;
    let policy_values = headers(response, "content-security-policy")
        .chain(meta.policies.iter().map(String::as_str))
        .collect::<Vec<_>>();
    let policies = policy_values
        .iter()
        .flat_map(|value| value.split(','))
        .collect::<Vec<_>>();
    let enforcing_header = headers(response, "content-security-policy")
        .next()
        .is_some();
    let mut add = |title: &str, cause: &str, subject: &str| {
        findings.push(finding(
            ip,
            port,
            title,
            cause,
            &response.url,
            &response.method,
            subject,
        ));
    };
    if complete
        && !enforcing_header
        && meta.policies.is_empty()
        && headers(response, "content-security-policy-report-only")
            .next()
            .is_some()
    {
        add(
            "Content-Security-Policy is report-only",
            "A reporting policy is present, but no enforcing CSP header or meta policy was found in the complete HTML capture",
            "Content-Security-Policy-Report-Only; enforcing policy absent",
        );
    }
    let referrer = headers(response, "referrer-policy")
        .flat_map(|value| value.split(','))
        .chain(meta.referrers.iter().map(String::as_str))
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| {
            matches!(
                value.as_str(),
                "no-referrer"
                    | "no-referrer-when-downgrade"
                    | "origin"
                    | "origin-when-cross-origin"
                    | "same-origin"
                    | "strict-origin"
                    | "strict-origin-when-cross-origin"
                    | "unsafe-url"
            )
        })
        .last();
    if complete && referrer.as_deref() == Some("unsafe-url") {
        add(
            "Referrer policy permits full cross-origin URL disclosure",
            "The effective document referrer policy permits the path and query to be sent to other origins",
            "Referrer-Policy: unsafe-url",
        );
    }
    let mime = headers(response, "x-content-type-options").collect::<Vec<_>>();
    if !mime.is_empty()
        && !mime[0].split(',').next().is_some_and(|value| {
            value
                .trim()
                .trim_matches('"')
                .eq_ignore_ascii_case("nosniff")
        })
    {
        add(
            "MIME-sniffing protection is ineffective",
            "The first X-Content-Type-Options value is not the recognized nosniff token",
            &format!(
                "X-Content-Type-Options: {}",
                safe_evidence(&mime.join(", "))
            ),
        );
    }
    let scripts_sandboxed = headers(response, "content-security-policy")
        .flat_map(|value| value.split(','))
        .any(|policy| {
            sources(policy, "sandbox").is_some_and(|tokens| {
                !tokens
                    .iter()
                    .any(|token| token.eq_ignore_ascii_case("allow-scripts"))
            })
        });
    if !policies.is_empty() && complete && !scripts_sandboxed {
        if ["script-src-elem", "script-src-attr"]
            .iter()
            .any(|kind| policies.iter().all(|policy| permits_inline(policy, kind)))
        {
            add(
                "Content-Security-Policy permits inline script execution",
                "The combined enforcing policies leave an inline script context unrestricted or permit unsafe-inline without nonce/hash protection",
                "Content-Security-Policy: effective inline-script permission",
            );
        }
        if policies.iter().all(|policy| {
            effective_sources(policy, "script-src").is_none_or(|sources| {
                sources
                    .iter()
                    .any(|source| source.eq_ignore_ascii_case("'unsafe-eval'"))
            })
        }) {
            add(
                "Content-Security-Policy permits eval-style script execution",
                "The combined enforcing policies do not restrict eval-style JavaScript execution",
                "Content-Security-Policy: effective eval permission",
            );
        }
    }
    for finding in &mut findings {
        if finding.title.starts_with("Content-Security-Policy ") {
            finding.evidence.extend(policy_values.iter().map(|policy| {
                format!(
                    "Enforcing CSP header/meta policy: {}",
                    safe_evidence(policy)
                )
            }));
            finding.evidence.extend(
                headers(response, "content-security-policy-report-only")
                    .map(|policy| format!("Report-only CSP: {}", safe_evidence(policy))),
            );
        }
    }
    findings
}

pub(super) fn enrich_finding(finding: &mut ExposureFinding) {
    if !finding.details.is_empty() {
        return;
    }
    let mut locations = std::collections::BTreeSet::new();
    for evidence in &finding.evidence {
        let subject = safe_evidence(evidence);
        let subject = subject.chars().take(600).collect::<String>();
        if !URL_IN_TEXT.is_match(evidence) {
            locations.insert((None, subject.clone()));
        }
        for capture in URL_IN_TEXT.find_iter(evidence) {
            locations.insert((
                Some(safe_url(capture.as_str().trim_end_matches([',', ';', ')']))),
                subject.clone(),
            ));
        }
    }
    if locations.is_empty() {
        locations.insert((None, finding.title.clone()));
    }
    for (url, subject) in locations {
        finding.details.push(FindingDetail {
            cause: safe_evidence(&finding.description),
            location: FindingLocation {
                url,
                method: None,
                subject: Some(subject),
            },
        });
    }
}

pub(super) fn password_form_finding(
    ip: IpAddr,
    port: u16,
    source: &str,
    action: &str,
    method: &str,
) -> Option<ExposureFinding> {
    if method.eq_ignore_ascii_case("DIALOG")
        || !Url::parse(action).is_ok_and(|url| url.scheme() == "http")
    {
        return None;
    }
    Some(finding(
        ip,
        port,
        "Password form targets cleartext HTTP",
        "A password form has an HTTP submission target",
        source,
        method,
        &format!("Password form action: {}", safe_url(action)),
    ))
}

pub(super) fn finalize_findings(report: &mut ExposureScanReport, cancel: &CancellationToken) {
    let mut locations = BTreeMap::<String, std::collections::BTreeSet<(IpAddr, u16)>>::new();
    let mut methods = BTreeMap::<(IpAddr, u16, String), std::collections::BTreeSet<String>>::new();
    for resource in &report.crawled_resources {
        if cancel.is_cancelled() {
            return;
        }
        locations
            .entry(resource.url.clone())
            .or_default()
            .insert((resource.ip, resource.port));
    }
    for endpoint in &report.endpoints {
        if cancel.is_cancelled() {
            return;
        }
        for response in &endpoint.http {
            locations
                .entry(response.url.clone())
                .or_default()
                .insert((endpoint.ip, endpoint.port));
            methods
                .entry((endpoint.ip, endpoint.port, safe_url(&response.url)))
                .or_default()
                .insert(response.method.clone());
        }
    }
    let mut confirmed = BTreeMap::<(IpAddr, u16, &str), Vec<&SecurityCheckResult>>::new();
    for check in &report.security_checks {
        if check.outcome == CheckOutcome::Vulnerable {
            confirmed
                .entry((check.ip, check.port, &check.title))
                .or_default()
                .push(check);
        }
    }
    if report.request.security_operations {
        for form in &report.crawl_forms {
            if cancel.is_cancelled() {
                return;
            }
            if !form.has_password
                || form.method.eq_ignore_ascii_case("DIALOG")
                || !Url::parse(&form.action_url).is_ok_and(|url| url.scheme() == "http")
            {
                continue;
            }
            for &(ip, port) in locations.get(&form.source_url).into_iter().flatten() {
                if let Some(finding) = password_form_finding(
                    ip,
                    port,
                    &form.source_url,
                    &form.action_url,
                    &form.method,
                ) {
                    report.findings.push(finding);
                }
            }
        }
    }
    let mut merged = BTreeMap::new();
    for mut finding in std::mem::take(&mut report.findings) {
        if finding.title == "Potential CORS-trusted DNS takeover" {
            continue;
        }
        enrich_finding(&mut finding);
        let checks = if finding.transport == TransportProtocol::Tcp {
            confirmed
                .get(&(finding.ip, finding.port, finding.title.as_str()))
                .map(Vec::as_slice)
                .unwrap_or_default()
        } else {
            &[]
        };
        if !checks.is_empty() {
            if finding.description.starts_with("The ")
                && finding
                    .description
                    .ends_with("security check confirmed the tested condition")
            {
                finding
                    .details
                    .retain(|detail| detail.cause != finding.description);
            }
            for check in checks {
                finding.details.push(FindingDetail {
                    cause: safe_evidence(check.reason.as_deref().unwrap_or(&check.title)),
                    location: FindingLocation { url: check.probe_url.as_deref().map(safe_url), method: None, subject: Some(format!("{} — {}", check.class, check.check_id)) },
                });
            }
        }
        finding.description = safe_evidence(&finding.description);
        finding.evidence = finding
            .evidence
            .iter()
            .map(|value| safe_evidence(value))
            .collect();
        for detail in &mut finding.details {
            detail.cause = safe_evidence(&detail.cause);
            detail.location.url = detail.location.url.as_deref().map(safe_url);
            detail.location.subject = detail.location.subject.as_deref().map(safe_evidence);
            if detail.location.method.is_none() {
                detail.location.method = detail.location.url.as_ref().and_then(|url| {
                    let observed = methods.get(&(finding.ip, finding.port, url.clone()))?;
                    (observed.len() == 1)
                        .then(|| observed.first().cloned())
                        .flatten()
                });
            }
        }
        super::security_analysis::add_security_summary_finding(&mut merged, finding);
    }
    report.findings = merged.into_values().collect();
    report.findings.sort_by(|left, right| {
        left.title
            .cmp(&right.title)
            .then(left.ip.cmp(&right.ip))
            .then(left.port.cmp(&right.port))
    });
}

