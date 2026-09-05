use super::{HttpObservation, header_values};
use base64::Engine as _;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
pub(super) struct BrowserPolicyIssue {
    pub title: &'static str,
    pub description: &'static str,
    pub evidence: String,
}

pub(super) struct HstsAssessment {
    pub issue: Option<BrowserPolicyIssue>,
    pub max_age: Option<u64>,
    pub include_subdomains: bool,
    pub preload: bool,
}

pub(super) fn response_issues(
    response: &HttpObservation,
    scheme: &str,
    advanced: bool,
) -> Vec<BrowserPolicyIssue> {
    if !(200..300).contains(&response.status) || !is_html(response) {
        return Vec::new();
    }
    let url = safe_url(&response.url);
    let mut issues = Vec::new();
    let csp = enforced_csp(response);
    let frame_ancestors = csp
        .iter()
        .find_map(|policy| directive(policy, "frame-ancestors"));
    let valid_frame_ancestors = frame_ancestors
        .as_ref()
        .is_some_and(|sources| !sources.is_empty());
    let xfo = xfo_values(response);
    let valid_xfo = xfo
        .iter()
        .any(|value| matches!(value.as_str(), "deny" | "sameorigin"));
    let mut missing = Vec::new();
    if let Some(hsts) = hsts_assessment(response, scheme)
        && let Some(issue) = hsts.issue
    {
        issues.push(issue);
    }
    if csp.is_empty() {
        missing.push("Content-Security-Policy");
    }
    if header_values(response, "x-content-type-options")
        .next()
        .is_none()
    {
        missing.push("X-Content-Type-Options");
    }
    if header_values(response, "referrer-policy").next().is_none() {
        missing.push("Referrer-Policy");
    }
    if !valid_xfo && !valid_frame_ancestors {
        missing.push("X-Frame-Options or CSP frame-ancestors");
    }
    if header_values(response, "permissions-policy")
        .next()
        .is_none()
    {
        missing.push("Permissions-Policy");
    }
    if !missing.is_empty() {
        issues.push(issue(
            "Browser security headers are missing",
            "The HTML response omits applicable browser hardening headers",
            format!("{url} missing {}", missing.join(", ")),
        ));
    }
    if !advanced {
        return issues;
    }
    if frame_ancestors.as_ref().is_some_and(Vec::is_empty) {
        issues.push(issue(
            "Content-Security-Policy frame-ancestors is malformed",
            "The frame-ancestors directive contains no source expression",
            format!("Empty frame-ancestors directive at {url}"),
        ));
    }
    if xfo.iter().any(|value| value.starts_with("allow-from")) {
        issues.push(issue(
            "X-Frame-Options uses obsolete ALLOW-FROM",
            "ALLOW-FROM is obsolete and does not provide consistent clickjacking protection",
            format!("Obsolete X-Frame-Options at {url}"),
        ));
    }
    let invalid_xfo = xfo
        .iter()
        .filter(|value| {
            !matches!(value.as_str(), "deny" | "sameorigin") && !value.starts_with("allow-from")
        })
        .count();
    if invalid_xfo > 0 {
        issues.push(issue(
            "X-Frame-Options is malformed",
            "The response contains an unrecognized X-Frame-Options value",
            format!("{invalid_xfo} malformed X-Frame-Options value(s) at {url}"),
        ));
    }
    let distinct_xfo = xfo.iter().collect::<BTreeSet<_>>();
    if distinct_xfo.len() > 1 {
        issues.push(issue(
            "X-Frame-Options values conflict",
            "The response supplies conflicting X-Frame-Options policies",
            format!("Conflicting X-Frame-Options values at {url}"),
        ));
    }
    if let Some(sources) = frame_ancestors.as_ref()
        && permissive_frame_ancestors(sources)
    {
        issues.push(issue(
            "Content-Security-Policy frame-ancestors is permissive",
            "The frame-ancestors directive permits broad or external framing",
            format!("Permissive frame-ancestors directive at {url}"),
        ));
    }
    if let Some(sources) = frame_ancestors.as_ref()
        && xfo_conflicts(&xfo, sources)
    {
        issues.push(issue(
            "CSP and X-Frame-Options framing policies conflict",
            "The response supplies materially different framing policies",
            format!("Conflicting framing policies at {url}"),
        ));
    }
    for policy in header_values(response, "permissions-policy") {
        let wildcard = wildcard_permissions(policy);
        if !wildcard.is_empty() {
            issues.push(issue(
                "Permissions-Policy grants powerful capabilities broadly",
                "The policy grants powerful browser capabilities to every origin",
                format!("{} granted with wildcard at {url}", wildcard.join(", ")),
            ));
        }
    }
    validate_cross_origin_tokens(response, &url, &mut issues);
    let coop = first_token(response, "cross-origin-opener-policy");
    let coep = first_token(response, "cross-origin-embedder-policy");
    let coop_isolating = coop.as_deref() == Some("same-origin");
    let coep_isolating = matches!(coep.as_deref(), Some("require-corp" | "credentialless"));
    if coop_isolating != coep_isolating {
        issues.push(issue(
            "Cross-origin isolation policy is incomplete",
            "COOP same-origin and an isolating COEP policy must be paired",
            format!("Incomplete COOP/COEP isolation pair at {url}"),
        ));
    }
    for policy in csp {
        let invalid = invalid_script_tokens(policy);
        if !invalid.is_empty() {
            issues.push(issue(
                "Content-Security-Policy contains malformed script tokens",
                "A script nonce or hash is malformed or below the required strength",
                format!("{} malformed script token(s) at {url}", invalid.len()),
            ));
        }
    }
    issues
}

pub(super) fn hsts_assessment(response: &HttpObservation, scheme: &str) -> Option<HstsAssessment> {
    if !scheme.eq_ignore_ascii_case("https")
        || !(200..300).contains(&response.status)
        || !is_html(response)
    {
        return None;
    }
    let url = safe_url(&response.url);
    let values = header_values(response, "strict-transport-security").collect::<Vec<_>>();
    if values.is_empty() {
        return Some(HstsAssessment {
            issue: Some(issue(
                "HSTS is missing",
                "The final HTTPS HTML response does not require future HTTPS connections",
                format!("Strict-Transport-Security is absent at {url}"),
            )),
            max_age: None,
            include_subdomains: false,
            preload: false,
        });
    }
    let directives = values
        .iter()
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let max_ages = directives
        .iter()
        .filter_map(|directive| {
            let (name, value) = directive.split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("max-age")
                .then_some(value.trim())
        })
        .collect::<Vec<_>>();
    let max_age = (max_ages.len() == 1)
        .then(|| max_ages[0].parse::<u64>().ok())
        .flatten();
    let include_subdomains = directives
        .iter()
        .any(|value| value.eq_ignore_ascii_case("includeSubDomains"));
    let preload = directives
        .iter()
        .any(|value| value.eq_ignore_ascii_case("preload"));
    let issue = if values.len() != 1 || max_ages.len() != 1 || max_age.is_none() {
        Some(issue(
            "Malformed or conflicting HSTS policy",
            "The Strict-Transport-Security policy is malformed, duplicated, or conflicting",
            format!(
                "{url} returned {} HSTS header(s) and {} max-age directive(s)",
                values.len(),
                max_ages.len()
            ),
        ))
    } else if max_age.is_some_and(|value| value < 15_552_000) {
        Some(issue(
            "Weak HSTS max-age",
            "The HSTS lifetime is shorter than the 180-day assessment threshold",
            format!("{url} returned max-age={}", max_age.unwrap_or_default()),
        ))
    } else {
        None
    };
    Some(HstsAssessment {
        issue,
        max_age,
        include_subdomains,
        preload,
    })
}

pub(super) fn csp_nonces(response: &HttpObservation) -> Vec<Vec<u8>> {
    enforced_csp(response)
        .into_iter()
        .flat_map(|policy| script_sources(policy))
        .filter_map(|source| {
            let source = source.trim_matches('\'');
            let encoded = source.strip_prefix("nonce-")?;
            decode_base64(encoded)
        })
        .filter(|nonce| nonce.len() >= 16)
        .collect()
}

fn is_html(response: &HttpObservation) -> bool {
    if header_values(response, "content-type")
        .any(|value| value.to_ascii_lowercase().contains("html"))
    {
        return true;
    }
    let start = String::from_utf8_lossy(&response.body[..response.body.len().min(256)])
        .trim_start()
        .to_ascii_lowercase();
    start.starts_with("<!doctype html") || start.starts_with("<html")
}

fn enforced_csp(response: &HttpObservation) -> Vec<&str> {
    header_values(response, "content-security-policy").collect()
}

fn directive<'a>(policy: &'a str, expected: &str) -> Option<Vec<&'a str>> {
    policy.split(';').find_map(|part| {
        let mut values = part.split_ascii_whitespace();
        values
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case(expected))
            .then(|| values.collect())
    })
}

fn xfo_values(response: &HttpObservation) -> Vec<String> {
    header_values(response, "x-frame-options")
        .flat_map(|value| value.split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn permissive_frame_ancestors(sources: &[&str]) -> bool {
    sources.iter().any(|source| {
        let value = source.trim_matches('\'').to_ascii_lowercase();
        value == "*"
            || matches!(value.as_str(), "http:" | "https:" | "data:" | "blob:")
            || value.contains("*.")
            || value.starts_with("http://")
            || value.starts_with("https://")
    })
}

fn xfo_conflicts(xfo: &[String], frame_ancestors: &[&str]) -> bool {
    let none = frame_ancestors.len() == 1
        && frame_ancestors[0]
            .trim_matches('\'')
            .eq_ignore_ascii_case("none");
    let only_self = frame_ancestors.len() == 1
        && frame_ancestors[0]
            .trim_matches('\'')
            .eq_ignore_ascii_case("self");
    xfo.iter().any(|value| match value.as_str() {
        "deny" => !none,
        "sameorigin" => !only_self,
        _ => false,
    })
}

fn wildcard_permissions(policy: &str) -> Vec<&'static str> {
    const POWERFUL: &[&str] = &[
        "camera",
        "microphone",
        "geolocation",
        "display-capture",
        "payment",
        "usb",
        "serial",
        "hid",
    ];
    let mut grants = Vec::new();
    for part in policy.split(',') {
        let Some((name, allowlist)) = part.split_once('=') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if POWERFUL.contains(&name.as_str())
            && allowlist
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .split_ascii_whitespace()
                .any(|value| value.trim_matches('"') == "*")
            && let Some(capability) = POWERFUL.iter().find(|value| **value == name)
        {
            grants.push(*capability);
        }
    }
    grants
}

fn validate_cross_origin_tokens(
    response: &HttpObservation,
    url: &str,
    issues: &mut Vec<BrowserPolicyIssue>,
) {
    let policies = [
        (
            "cross-origin-opener-policy",
            "Cross-Origin-Opener-Policy",
            &[
                "unsafe-none",
                "same-origin-allow-popups",
                "same-origin",
                "noopener-allow-popups",
            ][..],
        ),
        (
            "cross-origin-embedder-policy",
            "Cross-Origin-Embedder-Policy",
            &["unsafe-none", "require-corp", "credentialless"][..],
        ),
        (
            "cross-origin-resource-policy",
            "Cross-Origin-Resource-Policy",
            &["same-origin", "same-site", "cross-origin"][..],
        ),
    ];
    for (header, label, valid) in policies {
        let values = header_values(response, header)
            .map(|value| value.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        if values.iter().any(|value| !valid.contains(&value.as_str())) {
            issues.push(issue(
                "Cross-origin policy header is malformed",
                "A COOP, COEP, or CORP header contains an invalid token",
                format!("Malformed {label} value at {url}"),
            ));
        }
        if values.iter().collect::<BTreeSet<_>>().len() > 1 {
            issues.push(issue(
                "Cross-origin policy header values conflict",
                "A COOP, COEP, or CORP header contains conflicting values",
                format!("Conflicting {label} values at {url}"),
            ));
        }
    }
}

fn first_token(response: &HttpObservation, name: &str) -> Option<String> {
    header_values(response, name)
        .next()
        .map(|value| value.trim().to_ascii_lowercase())
}

fn script_sources(policy: &str) -> Vec<&str> {
    let mut sources = Vec::new();
    for name in ["script-src", "script-src-elem", "script-src-attr"] {
        if let Some(values) = directive(policy, name) {
            sources.extend(values);
        }
    }
    if sources.is_empty()
        && let Some(values) = directive(policy, "default-src")
    {
        sources.extend(values);
    }
    sources
}

fn invalid_script_tokens(policy: &str) -> Vec<String> {
    let mut invalid = Vec::new();
    for source in script_sources(policy) {
        let token = source.trim_matches('\'');
        if let Some(encoded) = token.strip_prefix("nonce-") {
            if decode_base64(encoded).is_none_or(|value| value.len() < 16) {
                invalid.push("nonce".to_owned());
            }
            continue;
        }
        for (prefix, length) in [("sha256-", 32), ("sha384-", 48), ("sha512-", 64)] {
            if let Some(encoded) = token.strip_prefix(prefix)
                && decode_base64(encoded).is_none_or(|value| value.len() != length)
            {
                invalid.push(prefix.trim_end_matches('-').to_owned());
            }
        }
        if token.starts_with("nonce") && !token.starts_with("nonce-") {
            invalid.push("nonce".to_owned());
        }
        if ["sha256", "sha384", "sha512"]
            .iter()
            .any(|prefix| token.starts_with(prefix) && !token.starts_with(&format!("{prefix}-")))
        {
            invalid.push("hash".to_owned());
        }
    }
    invalid
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value))
        .ok()
}

fn safe_url(value: &str) -> String {
    let Ok(mut url) = url::Url::parse(value) else {
        return value.to_owned();
    };
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn issue(title: &'static str, description: &'static str, evidence: String) -> BrowserPolicyIssue {
    BrowserPolicyIssue {
        title,
        description,
        evidence,
    }
}

pub(super) fn nonce_reuse_issues<'a>(
    responses: impl Iterator<Item = &'a HttpObservation>,
) -> Vec<BrowserPolicyIssue> {
    let mut first = BTreeMap::<Vec<u8>, String>::new();
    let mut issues = Vec::new();
    for response in responses {
        let url = safe_url(&response.url);
        for nonce in csp_nonces(response) {
            if let Some(previous) = first.get(&nonce)
                && previous != &url
            {
                issues.push(issue(
                    "Content-Security-Policy nonce is reused",
                    "A script nonce was reused across distinct document responses",
                    format!("Nonce reused by {previous} and {url}; nonce value withheld"),
                ));
            } else {
                first.insert(nonce, url.clone());
            }
        }
    }
    issues
}
