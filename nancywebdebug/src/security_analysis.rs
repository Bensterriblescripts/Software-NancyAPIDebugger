use super::*;

pub(super) fn build_security_summary(
    endpoints: &[EndpointScan],
    include_csp_warnings: bool,
) -> Vec<ExposureFinding> {
    let mut findings = BTreeMap::new();
    for endpoint in endpoints {
        for finding in &endpoint.findings {
            add_security_summary_finding(&mut findings, finding.clone());
        }
        if include_csp_warnings {
            for response in &endpoint.http {
                for policy in header_values(response, "content-security-policy") {
                    add_csp_findings(&mut findings, endpoint.ip, endpoint.port, policy);
                }
            }
            add_cookie_findings(&mut findings, endpoint);
            add_url_credential_findings(&mut findings, endpoint);
            add_web_storage_findings(&mut findings, endpoint);
            for issue in super::browser_policy::nonce_reuse_issues(endpoint.http.iter()) {
                add_security_summary_finding(
                    &mut findings,
                    ExposureFinding {
                        ip: endpoint.ip,
                        port: endpoint.port,
                        transport: endpoint.transport,
                        title: issue.title.to_owned(),
                        description: issue.description.to_owned(),
                        evidence: vec![issue.evidence],
                        component_kind: None,
                    },
                );
            }
        }
    }
    findings.into_values().collect()
}

#[derive(Clone, PartialEq, Eq)]
struct CookieSecurityAttributes {
    secure: bool,
    http_only: bool,
    same_site: Option<SameSite>,
}

fn add_cookie_findings(findings: &mut SecuritySummaryFindings, endpoint: &EndpointScan) {
    let mut jar = EndpointCookieJar::default();
    let mut records = Vec::new();
    let mut continuity = HashMap::<CookieKey, usize>::new();
    for response in &endpoint.http {
        let Ok(url) = Url::parse(&response.url) else {
            continue;
        };
        let sent = if matches!(response.method.as_str(), "GET" | "HEAD") {
            jar.eligible(&url)
                .into_iter()
                .map(|cookie| cookie.key.clone())
                .collect::<HashSet<_>>()
        } else {
            HashSet::new()
        };
        let mut continued = HashSet::new();
        for header in header_values(response, "set-cookie") {
            let Some(cookie) = parse_set_cookie(&url, header) else {
                continue;
            };
            if !cookie.deletion
                && sent.contains(&cookie.key)
                && continued.insert(cookie.key.clone())
            {
                *continuity.entry(cookie.key.clone()).or_default() += 1;
            }
            jar.store(cookie.clone());
            records.push((cookie, safe_source_url(&url)));
        }
    }

    let sensitive_keys = records
        .iter()
        .filter(|(cookie, _)| {
            recognized_sensitive_cookie(&cookie.key.name)
                || is_structured_credential(&cookie.value)
                || continuity.get(&cookie.key).copied().unwrap_or_default() >= 2
        })
        .map(|(cookie, _)| cookie.key.clone())
        .collect::<HashSet<_>>();
    let mut previous = HashMap::<CookieKey, CookieSecurityAttributes>::new();
    for (cookie, source) in records {
        if cookie.deletion {
            continue;
        }
        let name = safe_evidence_name(&cookie.key.name);
        let sensitive = sensitive_keys.contains(&cookie.key);
        if sensitive && !cookie.secure {
            add_operations_finding(
                findings,
                endpoint,
                "Security-sensitive cookie lacks Secure",
                "A security-sensitive cookie can be sent without requiring encrypted transport",
                format!("Cookie '{name}' issued by {source} omits Secure"),
            );
        }
        if sensitive && http_only_applies(&cookie.key.name) && !cookie.http_only {
            add_operations_finding(
                findings,
                endpoint,
                "Security-sensitive cookie lacks HttpOnly",
                "A security-sensitive cookie is accessible to client-side scripts",
                format!("Cookie '{name}' issued by {source} omits HttpOnly"),
            );
        }
        if sensitive && cookie.same_site.is_none() {
            add_operations_finding(
                findings,
                endpoint,
                "Security-sensitive cookie lacks SameSite",
                "A security-sensitive cookie has no explicit SameSite restriction",
                format!("Cookie '{name}' issued by {source} omits SameSite"),
            );
        }
        if cookie.same_site == Some(SameSite::None) && !cookie.secure {
            add_operations_finding(
                findings,
                endpoint,
                "SameSite=None cookie lacks Secure",
                "A cookie declares SameSite=None without the required Secure attribute",
                format!("Cookie '{name}' issued by {source}; value withheld"),
            );
        }
        if cookie.key.name.starts_with("__Secure-")
            && (!cookie.secure || cookie.source_scheme != "https")
        {
            add_operations_finding(
                findings,
                endpoint,
                "Invalid __Secure- cookie prefix requirements",
                "A __Secure- cookie was not issued over HTTPS with the Secure attribute",
                format!("Cookie '{name}' issued by {source}"),
            );
        }
        if cookie.key.name.starts_with("__Host-")
            && (!cookie.secure
                || cookie.source_scheme != "https"
                || cookie.domain_attribute
                || cookie.key.path != "/")
        {
            add_operations_finding(
                findings,
                endpoint,
                "Invalid __Host- cookie prefix requirements",
                "A __Host- cookie did not meet HTTPS, Secure, host-only, and Path=/ requirements",
                format!("Cookie '{name}' issued by {source}"),
            );
        }
        if sensitive && cookie.source_scheme == "http" {
            add_operations_finding(
                findings,
                endpoint,
                "Security-sensitive cookie issued over cleartext HTTP",
                "A security-sensitive cookie was issued without transport encryption",
                format!("Cookie '{name}' issued by {source}; value withheld"),
            );
        }
        let attributes = CookieSecurityAttributes {
            secure: cookie.secure,
            http_only: cookie.http_only,
            same_site: cookie.same_site,
        };
        if sensitive
            && let Some(prior) = previous.insert(cookie.key.clone(), attributes.clone())
            && prior != attributes
        {
            let mut changed = Vec::new();
            if prior.secure != attributes.secure {
                changed.push("Secure");
            }
            if prior.http_only != attributes.http_only {
                changed.push("HttpOnly");
            }
            if prior.same_site != attributes.same_site {
                changed.push("SameSite");
            }
            add_operations_finding(
                findings,
                endpoint,
                "Cookie security attributes conflict across reissues",
                "The same security-sensitive cookie was reissued with different security attributes",
                format!(
                    "Cookie '{name}' changed {} at {source}; values withheld",
                    changed.join(", ")
                ),
            );
        }
    }
}

fn add_url_credential_findings(findings: &mut SecuritySummaryFindings, endpoint: &EndpointScan) {
    let mut seen = HashSet::new();
    for response in &endpoint.http {
        let Ok(url) = Url::parse(&response.url) else {
            continue;
        };
        inspect_credential_url(findings, endpoint, &url, &mut seen);
        if let Some(location) = response.redirect_location.as_deref()
            && let Ok(location) = url.join(location)
        {
            inspect_credential_url(findings, endpoint, &location, &mut seen);
        }
    }
}

fn inspect_credential_url(
    findings: &mut SecuritySummaryFindings,
    endpoint: &EndpointScan,
    url: &Url,
    seen: &mut HashSet<(String, String)>,
) {
    for (name, value) in url.query_pairs() {
        if session_parameter_name(&name) && is_credential_shaped(&value) {
            let source = safe_source_url(url);
            let name = safe_evidence_name(&name);
            if seen.insert((source.clone(), name.clone())) {
                add_operations_finding(
                    findings,
                    endpoint,
                    "Session or token identifier exposed in a URL",
                    "A credential-shaped session or token identifier appears in a URL query parameter",
                    format!("Parameter '{name}' appears in {source}; value withheld"),
                );
            }
        }
    }
}

fn add_web_storage_findings(findings: &mut SecuritySummaryFindings, endpoint: &EndpointScan) {
    let documents = endpoint
        .http
        .iter()
        .filter(|response| response_is_html(response))
        .filter_map(|response| Url::parse(&response.url).ok().map(|url| (response, url)))
        .collect::<Vec<_>>();
    let mut reported = HashSet::new();
    for (response, url) in &documents {
        let source = safe_source_url(url);
        let text = String::from_utf8_lossy(&response.body);
        for script in inline_script_blocks(&text) {
            report_storage_writes(findings, endpoint, &source, script, &mut reported);
        }
    }
    for response in endpoint
        .http
        .iter()
        .filter(|response| response_is_javascript(response))
    {
        let Ok(url) = Url::parse(&response.url) else {
            continue;
        };
        if !documents
            .iter()
            .any(|(_, document_url)| same_origin(document_url, &url))
        {
            continue;
        }
        let source = safe_source_url(&url);
        let text = String::from_utf8_lossy(&response.body);
        report_storage_writes(findings, endpoint, &source, &text, &mut reported);
    }
}

fn report_storage_writes(
    findings: &mut SecuritySummaryFindings,
    endpoint: &EndpointScan,
    source: &str,
    script: &str,
    reported: &mut HashSet<(String, String, String)>,
) {
    for write in storage_writes(script) {
        let key = safe_evidence_name(&write.key);
        if !reported.insert((write.storage.to_owned(), key.clone(), source.to_owned())) {
            continue;
        }
        add_operations_finding(
            findings,
            endpoint,
            &format!("Authentication data written to {}", write.storage),
            &format!(
                "Client-side code directly writes authentication or session data to {}",
                write.storage
            ),
            format!("Key '{key}' written by {source}; stored value withheld"),
        );
    }
}

fn add_operations_finding(
    findings: &mut SecuritySummaryFindings,
    endpoint: &EndpointScan,
    title: &str,
    description: &str,
    evidence: String,
) {
    add_security_summary_finding(
        findings,
        ExposureFinding {
            title: title.to_owned(),
            description: description.to_owned(),
            ip: endpoint.ip,
            port: endpoint.port,
            transport: endpoint.transport,
            evidence: vec![evidence],
            component_kind: None,
        },
    );
}

fn recognized_sensitive_cookie(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "session"
            | "sessionid"
            | "session_id"
            | "sid"
            | "jsessionid"
            | "phpsessid"
            | "asp.net_sessionid"
            | ".aspnetcore.cookies"
            | "connect.sid"
            | "laravel_session"
            | "ci_session"
            | "rack.session"
            | "auth"
            | "auth_token"
            | "authorization"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "jwt"
            | "jwt_token"
            | "remember_token"
            | "csrftoken"
            | "csrf_token"
            | "xsrf-token"
            | "next-auth.session-token"
            | "authjs.session-token"
    ) || lower.starts_with("aspsessionid")
        || lower.starts_with("wordpress_logged_in_")
        || lower.starts_with("wordpress_sec_")
        || lower.starts_with("wp_woocommerce_session_")
        || lower.starts_with("__secure-next-auth.session-token")
        || lower.starts_with("__secure-authjs.session-token")
}

fn http_only_applies(name: &str) -> bool {
    !crate::matches_ascii(name, &["csrftoken", "csrf_token", "xsrf-token"])
}

fn session_parameter_name(name: &str) -> bool {
    crate::matches_ascii(
        name,
        &[
            "sid",
            "session",
            "sessionid",
            "session_id",
            "jsessionid",
            "phpsessid",
            "token",
            "access_token",
            "auth_token",
            "id_token",
            "jwt",
            "ticket",
            "sso_token",
        ],
    )
}

fn is_structured_credential(value: &str) -> bool {
    let value = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value);
    let segments = value.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return false;
    }
    let decode = |segment: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(segment))
            .ok()
    };
    let Some(header) = decode(segments[0]) else {
        return false;
    };
    let Some(payload) = decode(segments[1]) else {
        return false;
    };
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header) else {
        return false;
    };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        return false;
    };
    header.get("alg").and_then(|value| value.as_str()).is_some()
        && payload.as_object().is_some_and(|payload| {
            ["sub", "iss", "aud", "exp", "iat", "nbf", "jti"]
                .iter()
                .any(|claim| payload.contains_key(*claim))
        })
}

fn is_credential_shaped(value: &str) -> bool {
    let value = value.trim();
    if is_structured_credential(value) {
        return true;
    }
    let value = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value);
    if !(24..=2048).contains(&value.len())
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=' | b'%')
        })
    {
        return false;
    }
    let unique = value.bytes().collect::<HashSet<_>>().len();
    let has_letter = value.bytes().any(|byte| byte.is_ascii_alphabetic());
    let has_digit = value.bytes().any(|byte| byte.is_ascii_digit());
    unique >= 10 && has_letter && has_digit
}

fn safe_source_url(url: &Url) -> String {
    let Some(host) = url.host_str() else {
        return "URL withheld".to_owned();
    };
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    format!("{}://{}{port}{}", url.scheme(), url_host(host), url.path())
}

fn safe_evidence_name(value: &str) -> String {
    let mut output = value
        .chars()
        .filter(|character| !character.is_control())
        .take(80)
        .collect::<String>();
    if value.chars().count() > 80 {
        output.push('…');
    }
    output
}

pub(super) fn response_is_html(response: &HttpObservation) -> bool {
    header_values(response, "content-type")
        .any(|value| value.to_ascii_lowercase().contains("text/html"))
}

fn response_is_javascript(response: &HttpObservation) -> bool {
    header_values(response, "content-type").any(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("javascript") || value.contains("ecmascript")
    }) || Url::parse(&response.url)
        .ok()
        .is_some_and(|url| url.path().to_ascii_lowercase().ends_with(".js"))
}

fn inline_script_blocks(document: &str) -> Vec<&str> {
    let lower = document.to_ascii_lowercase();
    let mut scripts = Vec::new();
    let mut position = 0usize;
    while let Some(relative_start) = lower[position..].find("<script") {
        let start = position + relative_start;
        let Some(relative_open_end) = lower[start..].find('>') else {
            break;
        };
        let open_end = start + relative_open_end + 1;
        let Some(relative_close) = lower[open_end..].find("</script") else {
            break;
        };
        let close = open_end + relative_close;
        if html_attribute(&document[start..open_end], "src").is_none() {
            scripts.push(&document[open_end..close]);
        }
        position = close + "</script".len();
    }
    scripts
}

#[derive(Clone)]
enum ScriptToken {
    Identifier(String),
    Text(String),
    Punctuation(char),
}

struct StorageWrite {
    storage: &'static str,
    key: String,
}

fn storage_writes(script: &str) -> Vec<StorageWrite> {
    let tokens = tokenize_script(script);
    let mut writes = Vec::new();
    for index in 0..tokens.len() {
        let storage = match tokens.get(index) {
            Some(ScriptToken::Identifier(name)) if name == "localStorage" => "localStorage",
            Some(ScriptToken::Identifier(name)) if name == "sessionStorage" => "sessionStorage",
            _ => continue,
        };
        if token_punctuation(&tokens, index + 1, '.')
            && token_identifier(&tokens, index + 2) == Some("setItem")
            && token_punctuation(&tokens, index + 3, '(')
            && let Some(key) = token_text(&tokens, index + 4)
            && token_punctuation(&tokens, index + 5, ',')
        {
            let sensitive_value = token_text(&tokens, index + 6).is_some_and(is_credential_shaped);
            if storage_key_sensitive(key) || sensitive_value {
                writes.push(StorageWrite {
                    storage,
                    key: key.to_owned(),
                });
            }
            continue;
        }
        let property_key = if token_punctuation(&tokens, index + 1, '.') {
            token_identifier(&tokens, index + 2).map(str::to_owned)
        } else if token_punctuation(&tokens, index + 1, '[')
            && token_punctuation(&tokens, index + 3, ']')
        {
            token_text(&tokens, index + 2).map(str::to_owned)
        } else {
            None
        };
        let assignment_index = if token_punctuation(&tokens, index + 1, '.') {
            index + 3
        } else {
            index + 4
        };
        let Some(key) = property_key else {
            continue;
        };
        if token_punctuation(&tokens, assignment_index, '=')
            && !token_punctuation(&tokens, assignment_index + 1, '=')
        {
            let sensitive_value =
                token_text(&tokens, assignment_index + 1).is_some_and(is_credential_shaped);
            if storage_key_sensitive(&key) || sensitive_value {
                writes.push(StorageWrite { storage, key });
            }
        }
    }
    writes
}

fn tokenize_script(script: &str) -> Vec<ScriptToken> {
    let bytes = script.as_bytes();
    let mut tokens = Vec::new();
    let mut position = 0usize;
    while position < bytes.len() {
        if bytes[position].is_ascii_whitespace() {
            position += 1;
            continue;
        }
        if bytes[position..].starts_with(b"//") {
            position += 2;
            while position < bytes.len() && !matches!(bytes[position], b'\r' | b'\n') {
                position += 1;
            }
            continue;
        }
        if bytes[position..].starts_with(b"/*") {
            position += 2;
            while position + 1 < bytes.len() && !bytes[position..].starts_with(b"*/") {
                position += 1;
            }
            position = (position + 2).min(bytes.len());
            continue;
        }
        let byte = bytes[position];
        if matches!(byte, b'\'' | b'"' | b'`') {
            let quote = byte;
            position += 1;
            let mut value = String::new();
            let mut complete = false;
            while position < bytes.len() {
                let byte = bytes[position];
                if byte == b'\\' && position + 1 < bytes.len() {
                    value.push(bytes[position + 1] as char);
                    position += 2;
                } else if byte == quote {
                    position += 1;
                    complete = true;
                    break;
                } else {
                    value.push(byte as char);
                    position += 1;
                }
            }
            if complete {
                tokens.push(ScriptToken::Text(value));
            }
            continue;
        }
        if byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$') {
            let start = position;
            position += 1;
            while position < bytes.len()
                && (bytes[position].is_ascii_alphanumeric()
                    || matches!(bytes[position], b'_' | b'$'))
            {
                position += 1;
            }
            tokens.push(ScriptToken::Identifier(
                String::from_utf8_lossy(&bytes[start..position]).into_owned(),
            ));
            continue;
        }
        tokens.push(ScriptToken::Punctuation(byte as char));
        position += 1;
    }
    tokens
}

fn token_punctuation(tokens: &[ScriptToken], index: usize, expected: char) -> bool {
    matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
}

fn token_identifier(tokens: &[ScriptToken], index: usize) -> Option<&str> {
    match tokens.get(index) {
        Some(ScriptToken::Identifier(value)) => Some(value),
        _ => None,
    }
}

fn token_text(tokens: &[ScriptToken], index: usize) -> Option<&str> {
    match tokens.get(index) {
        Some(ScriptToken::Text(value)) => Some(value),
        _ => None,
    }
}

fn storage_key_sensitive(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "auth"
            | "authentication"
            | "authorization"
            | "credential"
            | "credentials"
            | "jwt"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "authtoken"
            | "bearertoken"
            | "session"
            | "sessionid"
            | "sessiontoken"
    ) || normalized.ends_with("authtoken")
        || normalized.ends_with("accesstoken")
        || normalized.ends_with("refreshtoken")
        || normalized.ends_with("sessiontoken")
        || normalized.ends_with("sessionid")
}

type SecuritySummaryFindings = BTreeMap<(IpAddr, u16, TransportProtocol, String), ExposureFinding>;

pub(super) fn security_summary_finding_key(
    finding: &ExposureFinding,
) -> (IpAddr, u16, TransportProtocol, String) {
    (
        finding.ip,
        finding.port,
        finding.transport,
        finding.title.clone(),
    )
}

pub(super) fn add_security_summary_finding(
    findings: &mut SecuritySummaryFindings,
    finding: ExposureFinding,
) {
    let key = security_summary_finding_key(&finding);
    if let Some(existing) = findings.get_mut(&key) {
        existing.evidence.extend(finding.evidence);
        existing.evidence.sort();
        existing.evidence.dedup();
    } else {
        findings.insert(key, finding);
    }
}

fn add_csp_findings(findings: &mut SecuritySummaryFindings, ip: IpAddr, port: u16, policy: &str) {
    let mut default_sources = None;
    let mut script_sources = None;
    let mut script_element_sources = None;
    let mut script_attribute_sources = None;
    for directive in policy.split(';') {
        let mut parts = directive.split_ascii_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let sources = parts.collect::<Vec<_>>();
        match name.to_ascii_lowercase().as_str() {
            "default-src" if default_sources.is_none() => default_sources = Some(sources),
            "script-src" if script_sources.is_none() => script_sources = Some(sources),
            "script-src-elem" if script_element_sources.is_none() => {
                script_element_sources = Some(sources)
            }
            "script-src-attr" if script_attribute_sources.is_none() => {
                script_attribute_sources = Some(sources)
            }
            _ => {}
        }
    }
    let base_sources = script_sources.as_deref().or(default_sources.as_deref());
    let element_sources = script_element_sources.as_deref().or(base_sources);
    let attribute_sources = script_attribute_sources.as_deref().or(base_sources);
    if element_sources
        .is_some_and(|sources| sources.iter().any(|source| is_remote_script_source(source)))
    {
        add_security_summary_finding(
            findings,
            ExposureFinding {
                ip,
                port,
                transport: TransportProtocol::Tcp,
                title: "Content-Security-Policy permits remote script sources".to_owned(),
                description: "The policy allows scripts to load from remote sources".to_owned(),
                evidence: vec![format!("Content-Security-Policy: {policy}")],
                component_kind: None,
            },
        );
    }
    if element_sources
        .into_iter()
        .chain(attribute_sources)
        .flatten()
        .any(|source| source.eq_ignore_ascii_case("'unsafe-inline'"))
    {
        add_security_summary_finding(
            findings,
            ExposureFinding {
                ip,
                port,
                transport: TransportProtocol::Tcp,
                title: "Content-Security-Policy permits inline script execution".to_owned(),
                description: "The policy allows inline script execution".to_owned(),
                evidence: vec![format!("Content-Security-Policy: {policy}")],
                component_kind: None,
            },
        );
    }
    if base_sources.is_some_and(|sources| {
        sources
            .iter()
            .any(|source| source.eq_ignore_ascii_case("'unsafe-eval'"))
    }) {
        add_security_summary_finding(
            findings,
            ExposureFinding {
                ip,
                port,
                transport: TransportProtocol::Tcp,
                title: "Content-Security-Policy permits eval-style script execution".to_owned(),
                description: "The policy allows eval-style script execution".to_owned(),
                evidence: vec![format!("Content-Security-Policy: {policy}")],
                component_kind: None,
            },
        );
    }
}

fn is_remote_script_source(source: &str) -> bool {
    let source = source.trim_end_matches(',').to_ascii_lowercase();
    !source.is_empty()
        && !source.starts_with('\'')
        && !matches!(
            source.as_str(),
            "none" | "self" | "data:" | "blob:" | "filesystem:"
        )
}
