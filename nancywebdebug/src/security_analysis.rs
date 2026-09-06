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
                for policy in {
                    let (response, name): (&crate::HttpObservation, &str) =
                        (response, "content-security-policy");
                    response
                        .headers
                        .iter()
                        .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.as_str())
                } {
                    ({
                        let (findings, ip, port, policy): (
                            &mut SecuritySummaryFindings,
                            IpAddr,
                            u16,
                            &str,
                        ) = (&mut findings, endpoint.ip, endpoint.port, policy);

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
                                "default-src" if default_sources.is_none() => {
                                    default_sources = Some(sources)
                                }
                                "script-src" if script_sources.is_none() => {
                                    script_sources = Some(sources)
                                }
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
                        let attribute_sources =
                            script_attribute_sources.as_deref().or(base_sources);
                        if element_sources.is_some_and(|sources| {
                            sources.iter().any(|source| {
                                let (source,): (&str,) = (source,);
                                {
                                    let source = source.trim_end_matches(',').to_ascii_lowercase();
                                    !source.is_empty()
                                        && !source.starts_with('\'')
                                        && !matches!(
                                            source.as_str(),
                                            "none" | "self" | "data:" | "blob:" | "filesystem:"
                                        )
                                }
                            })
                        }) {
                            add_security_summary_finding(
                                findings,
                                ExposureFinding {
                                    ip,
                                    port,
                                    transport: TransportProtocol::Tcp,
                                    title: "Content-Security-Policy permits remote script sources"
                                        .to_owned(),
                                    description:
                                        "The policy allows scripts to load from remote sources"
                                            .to_owned(),
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
                                    title:
                                        "Content-Security-Policy permits inline script execution"
                                            .to_owned(),
                                    description: "The policy allows inline script execution"
                                        .to_owned(),
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
                    });
                }
            }
            ({
                let (findings, endpoint): (&mut SecuritySummaryFindings, &EndpointScan) =
                    (&mut findings, endpoint);

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
                    for header in {
                        let (response, name): (&crate::HttpObservation, &str) =
                            (response, "set-cookie");
                        response
                            .headers
                            .iter()
                            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                            .map(|(_, value)| value.as_str())
                    } {
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
                        records.push((
                            cookie,
                            ({
                                let (url,): (&Url,) = (&url,);
                                {
                                    'inlined_safe_source_url: {
                                        let Some(host) = url.host_str() else {
                                            break 'inlined_safe_source_url "URL withheld"
                                                .to_owned();
                                        };
                                        let port = url
                                            .port()
                                            .map(|port| format!(":{port}"))
                                            .unwrap_or_default();
                                        format!(
                                            "{}://{}{port}{}",
                                            url.scheme(),
                                            ({
                                                let hostname: &str = host;
                                                if hostname.parse::<std::net::Ipv6Addr>().is_ok() {
                                                    format!("[{hostname}]")
                                                } else {
                                                    hostname.to_owned()
                                                }
                                            }),
                                            url.path()
                                        )
                                    }
                                }
                            }),
                        ));
                    }
                }

                let sensitive_keys = records
                    .iter()
                    .filter(|(cookie, _)| {
                        ({
                            let (name,): (&str,) = (&cookie.key.name,);
                            {
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
                        }) || ({
                            let (value,): (&str,) = (&cookie.value,);
                            {
                                'inlined_is_structured_credential: {
                                    let value = value
                                        .strip_prefix("Bearer ")
                                        .or_else(|| value.strip_prefix("bearer "))
                                        .unwrap_or(value);
                                    let segments = value.split('.').collect::<Vec<_>>();
                                    if segments.len() != 3
                                        || segments.iter().any(|segment| segment.is_empty())
                                    {
                                        break 'inlined_is_structured_credential false;
                                    }
                                    let decode = |segment: &str| {
                                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                                            .decode(segment)
                                            .or_else(|_| {
                                                base64::engine::general_purpose::URL_SAFE
                                                    .decode(segment)
                                            })
                                            .ok()
                                    };
                                    let Some(header) = decode(segments[0]) else {
                                        break 'inlined_is_structured_credential false;
                                    };
                                    let Some(payload) = decode(segments[1]) else {
                                        break 'inlined_is_structured_credential false;
                                    };
                                    let Ok(header) =
                                        serde_json::from_slice::<serde_json::Value>(&header)
                                    else {
                                        break 'inlined_is_structured_credential false;
                                    };
                                    let Ok(payload) =
                                        serde_json::from_slice::<serde_json::Value>(&payload)
                                    else {
                                        break 'inlined_is_structured_credential false;
                                    };
                                    header.get("alg").and_then(|value| value.as_str()).is_some()
                                        && payload.as_object().is_some_and(|payload| {
                                            ["sub", "iss", "aud", "exp", "iat", "nbf", "jti"]
                                                .iter()
                                                .any(|claim| payload.contains_key(*claim))
                                        })
                                }
                            }
                        }) || continuity.get(&cookie.key).copied().unwrap_or_default() >= 2
                    })
                    .map(|(cookie, _)| cookie.key.clone())
                    .collect::<HashSet<_>>();
                let mut previous = HashMap::<CookieKey, CookieSecurityAttributes>::new();
                for (cookie, source) in records {
                    if cookie.deletion {
                        continue;
                    }
                    let name = {
                        let (value,): (&str,) = (&cookie.key.name,);
                        let inlined_result: String = {
                            let mut output = value
                                .chars()
                                .filter(|character| !character.is_control())
                                .take(80)
                                .collect::<String>();
                            if value.chars().count() > 80 {
                                output.push('…');
                            }
                            output
                        };
                        inlined_result
                    };
                    let sensitive = sensitive_keys.contains(&cookie.key);
                    if sensitive && !cookie.secure {
                        ({
                            let (findings, endpoint, title, description, evidence): (
                                &mut SecuritySummaryFindings,
                                &EndpointScan,
                                &str,
                                &str,
                                String,
                            ) = (
                                findings,
                                endpoint,
                                "Security-sensitive cookie lacks Secure",
                                "A security-sensitive cookie can be sent without requiring encrypted transport",
                                format!("Cookie '{name}' issued by {source} omits Secure"),
                            );

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
                        });
                    }
                    if sensitive
                        && ({
                            let (name,): (&str,) = (&cookie.key.name,);
                            {
                                !({
                                    let (value, candidates): (&str, &[&str]) =
                                        (name, &["csrftoken", "csrf_token", "xsrf-token"]);
                                    candidates
                                        .iter()
                                        .any(|candidate| value.eq_ignore_ascii_case(candidate))
                                })
                            }
                        })
                        && !cookie.http_only
                    {
                        ({
                            let (findings, endpoint, title, description, evidence): (
                                &mut SecuritySummaryFindings,
                                &EndpointScan,
                                &str,
                                &str,
                                String,
                            ) = (
                                findings,
                                endpoint,
                                "Security-sensitive cookie lacks HttpOnly",
                                "A security-sensitive cookie is accessible to client-side scripts",
                                format!("Cookie '{name}' issued by {source} omits HttpOnly"),
                            );

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
                        });
                    }
                    if sensitive && cookie.same_site.is_none() {
                        ({
                            let (findings, endpoint, title, description, evidence): (
                                &mut SecuritySummaryFindings,
                                &EndpointScan,
                                &str,
                                &str,
                                String,
                            ) = (
                                findings,
                                endpoint,
                                "Security-sensitive cookie lacks SameSite",
                                "A security-sensitive cookie has no explicit SameSite restriction",
                                format!("Cookie '{name}' issued by {source} omits SameSite"),
                            );

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
                        });
                    }
                    if cookie.same_site == Some(SameSite::None) && !cookie.secure {
                        ({
                            let (findings, endpoint, title, description, evidence): (
                                &mut SecuritySummaryFindings,
                                &EndpointScan,
                                &str,
                                &str,
                                String,
                            ) = (
                                findings,
                                endpoint,
                                "SameSite=None cookie lacks Secure",
                                "A cookie declares SameSite=None without the required Secure attribute",
                                format!("Cookie '{name}' issued by {source}; value withheld"),
                            );

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
                        });
                    }
                    if cookie.key.name.starts_with("__Secure-")
                        && (!cookie.secure || cookie.source_scheme != "https")
                    {
                        ({
                            let (findings, endpoint, title, description, evidence): (
                                &mut SecuritySummaryFindings,
                                &EndpointScan,
                                &str,
                                &str,
                                String,
                            ) = (
                                findings,
                                endpoint,
                                "Invalid __Secure- cookie prefix requirements",
                                "A __Secure- cookie was not issued over HTTPS with the Secure attribute",
                                format!("Cookie '{name}' issued by {source}"),
                            );

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
                        });
                    }
                    if cookie.key.name.starts_with("__Host-")
                        && (!cookie.secure
                            || cookie.source_scheme != "https"
                            || cookie.domain_attribute
                            || cookie.key.path != "/")
                    {
                        ({
                            let (findings, endpoint, title, description, evidence): (
                                &mut SecuritySummaryFindings,
                                &EndpointScan,
                                &str,
                                &str,
                                String,
                            ) = (
                                findings,
                                endpoint,
                                "Invalid __Host- cookie prefix requirements",
                                "A __Host- cookie did not meet HTTPS, Secure, host-only, and Path=/ requirements",
                                format!("Cookie '{name}' issued by {source}"),
                            );

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
                        });
                    }
                    if sensitive && cookie.source_scheme == "http" {
                        ({
                            let (findings, endpoint, title, description, evidence): (
                                &mut SecuritySummaryFindings,
                                &EndpointScan,
                                &str,
                                &str,
                                String,
                            ) = (
                                findings,
                                endpoint,
                                "Security-sensitive cookie issued over cleartext HTTP",
                                "A security-sensitive cookie was issued without transport encryption",
                                format!("Cookie '{name}' issued by {source}; value withheld"),
                            );

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
                        });
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
                        ({
                            let (findings, endpoint, title, description, evidence): (
                                &mut SecuritySummaryFindings,
                                &EndpointScan,
                                &str,
                                &str,
                                String,
                            ) = (
                                findings,
                                endpoint,
                                "Cookie security attributes conflict across reissues",
                                "The same security-sensitive cookie was reissued with different security attributes",
                                format!(
                                    "Cookie '{name}' changed {} at {source}; values withheld",
                                    changed.join(", ")
                                ),
                            );

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
                        });
                    }
                }
            });
            ({
                let (findings, endpoint): (&mut SecuritySummaryFindings, &EndpointScan) =
                    (&mut findings, endpoint);

                let mut seen = HashSet::new();
                for response in &endpoint.http {
                    let Ok(url) = Url::parse(&response.url) else {
                        continue;
                    };
                    ({
                        let (findings, endpoint, url, seen): (
                            &mut SecuritySummaryFindings,
                            &EndpointScan,
                            &Url,
                            &mut HashSet<(String, String)>,
                        ) = (findings, endpoint, &url, &mut seen);

                        for (name, value) in url.query_pairs() {
                            if ({
                                let (name,): (&str,) = (&name,);
                                {
                                    {
                                        let (value, candidates): (&str, &[&str]) = (
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
                                        );
                                        candidates
                                            .iter()
                                            .any(|candidate| value.eq_ignore_ascii_case(candidate))
                                    }
                                }
                            }) && ({
                                let (value,): (&str,) = (&value,);
                                {
                                    'inlined_is_credential_shaped: {
                                        let value = value.trim();
                                        if {
                                            let (value,): (&str,) = (value,);
                                            {
                                                'inlined_is_structured_credential: {
                                                    let value = value
                                                        .strip_prefix("Bearer ")
                                                        .or_else(|| value.strip_prefix("bearer "))
                                                        .unwrap_or(value);
                                                    let segments =
                                                        value.split('.').collect::<Vec<_>>();
                                                    if segments.len() != 3
                                                        || segments
                                                            .iter()
                                                            .any(|segment| segment.is_empty())
                                                    {
                                                        break 'inlined_is_structured_credential false;
                                                    }
                                                    let decode = |segment: &str| {
                                                        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(segment))
            .ok()
                                                    };
                                                    let Some(header) = decode(segments[0]) else {
                                                        break 'inlined_is_structured_credential false;
                                                    };
                                                    let Some(payload) = decode(segments[1]) else {
                                                        break 'inlined_is_structured_credential false;
                                                    };
                                                    let Ok(header) = serde_json::from_slice::<
                                                        serde_json::Value,
                                                    >(
                                                        &header
                                                    ) else {
                                                        break 'inlined_is_structured_credential false;
                                                    };
                                                    let Ok(payload) = serde_json::from_slice::<
                                                        serde_json::Value,
                                                    >(
                                                        &payload
                                                    ) else {
                                                        break 'inlined_is_structured_credential false;
                                                    };
                                                    header
                                                        .get("alg")
                                                        .and_then(|value| value.as_str())
                                                        .is_some()
                                                        && payload.as_object().is_some_and(
                                                            |payload| {
                                                                [
                                                                    "sub", "iss", "aud", "exp",
                                                                    "iat", "nbf", "jti",
                                                                ]
                                                                .iter()
                                                                .any(|claim| {
                                                                    payload.contains_key(*claim)
                                                                })
                                                            },
                                                        )
                                                }
                                            }
                                        } {
                                            break 'inlined_is_credential_shaped true;
                                        }
                                        let value = value
                                            .strip_prefix("Bearer ")
                                            .or_else(|| value.strip_prefix("bearer "))
                                            .unwrap_or(value);
                                        if !(24..=2048).contains(&value.len())
                                            || !value.bytes().all(|byte| {
                                                byte.is_ascii_alphanumeric()
                                                    || matches!(
                                                        byte,
                                                        b'-' | b'_'
                                                            | b'.'
                                                            | b'~'
                                                            | b'+'
                                                            | b'/'
                                                            | b'='
                                                            | b'%'
                                                    )
                                            })
                                        {
                                            break 'inlined_is_credential_shaped false;
                                        }
                                        let unique = value.bytes().collect::<HashSet<_>>().len();
                                        let has_letter =
                                            value.bytes().any(|byte| byte.is_ascii_alphabetic());
                                        let has_digit =
                                            value.bytes().any(|byte| byte.is_ascii_digit());
                                        unique >= 10 && has_letter && has_digit
                                    }
                                }
                            }) {
                                let source = {
                                    let (url,): (&Url,) = (url,);
                                    {
                                        'inlined_safe_source_url: {
                                            let Some(host) = url.host_str() else {
                                                break 'inlined_safe_source_url "URL withheld"
                                                    .to_owned();
                                            };
                                            let port = url
                                                .port()
                                                .map(|port| format!(":{port}"))
                                                .unwrap_or_default();
                                            format!(
                                                "{}://{}{port}{}",
                                                url.scheme(),
                                                ({
                                                    let hostname: &str = host;
                                                    if hostname
                                                        .parse::<std::net::Ipv6Addr>()
                                                        .is_ok()
                                                    {
                                                        format!("[{hostname}]")
                                                    } else {
                                                        hostname.to_owned()
                                                    }
                                                }),
                                                url.path()
                                            )
                                        }
                                    }
                                };
                                let name = {
                                    let (value,): (&str,) = (&name,);
                                    let inlined_result: String = {
                                        let mut output = value
                                            .chars()
                                            .filter(|character| !character.is_control())
                                            .take(80)
                                            .collect::<String>();
                                        if value.chars().count() > 80 {
                                            output.push('…');
                                        }
                                        output
                                    };
                                    inlined_result
                                };
                                if seen.insert((source.clone(), name.clone())) {
                                    ({
                                        let (findings, endpoint, title, description, evidence): (
                                            &mut SecuritySummaryFindings,
                                            &EndpointScan,
                                            &str,
                                            &str,
                                            String,
                                        ) = (
                                            findings,
                                            endpoint,
                                            "Session or token identifier exposed in a URL",
                                            "A credential-shaped session or token identifier appears in a URL query parameter",
                                            format!(
                                                "Parameter '{name}' appears in {source}; value withheld"
                                            ),
                                        );

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
                                    });
                                }
                            }
                        }
                    });
                    if let Some(location) = response.redirect_location.as_deref()
                        && let Ok(location) = url.join(location)
                    {
                        ({
                            let (findings, endpoint, url, seen): (
                                &mut SecuritySummaryFindings,
                                &EndpointScan,
                                &Url,
                                &mut HashSet<(String, String)>,
                            ) = (findings, endpoint, &location, &mut seen);

                            for (name, value) in url.query_pairs() {
                                if ({
                                    let (name,): (&str,) = (&name,);
                                    {
                                        {
                                            let (value, candidates): (&str, &[&str]) = (
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
                                            );
                                            candidates.iter().any(|candidate| {
                                                value.eq_ignore_ascii_case(candidate)
                                            })
                                        }
                                    }
                                }) && ({
                                    let (value,): (&str,) = (&value,);
                                    {
                                        'inlined_is_credential_shaped: {
                                            let value = value.trim();
                                            if {
                                                let (value,): (&str,) = (value,);
                                                {
                                                    'inlined_is_structured_credential: {
                                                        let value = value
                                                            .strip_prefix("Bearer ")
                                                            .or_else(|| {
                                                                value.strip_prefix("bearer ")
                                                            })
                                                            .unwrap_or(value);
                                                        let segments =
                                                            value.split('.').collect::<Vec<_>>();
                                                        if segments.len() != 3
                                                            || segments
                                                                .iter()
                                                                .any(|segment| segment.is_empty())
                                                        {
                                                            break 'inlined_is_structured_credential false;
                                                        }
                                                        let decode = |segment: &str| {
                                                            base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(segment))
            .ok()
                                                        };
                                                        let Some(header) = decode(segments[0])
                                                        else {
                                                            break 'inlined_is_structured_credential false;
                                                        };
                                                        let Some(payload) = decode(segments[1])
                                                        else {
                                                            break 'inlined_is_structured_credential false;
                                                        };
                                                        let Ok(header) = serde_json::from_slice::<
                                                            serde_json::Value,
                                                        >(
                                                            &header
                                                        ) else {
                                                            break 'inlined_is_structured_credential false;
                                                        };
                                                        let Ok(payload) = serde_json::from_slice::<
                                                            serde_json::Value,
                                                        >(
                                                            &payload
                                                        ) else {
                                                            break 'inlined_is_structured_credential false;
                                                        };
                                                        header
                                                            .get("alg")
                                                            .and_then(|value| value.as_str())
                                                            .is_some()
                                                            && payload.as_object().is_some_and(
                                                                |payload| {
                                                                    [
                                                                        "sub", "iss", "aud", "exp",
                                                                        "iat", "nbf", "jti",
                                                                    ]
                                                                    .iter()
                                                                    .any(|claim| {
                                                                        payload.contains_key(*claim)
                                                                    })
                                                                },
                                                            )
                                                    }
                                                }
                                            } {
                                                break 'inlined_is_credential_shaped true;
                                            }
                                            let value = value
                                                .strip_prefix("Bearer ")
                                                .or_else(|| value.strip_prefix("bearer "))
                                                .unwrap_or(value);
                                            if !(24..=2048).contains(&value.len())
                                                || !value.bytes().all(|byte| {
                                                    byte.is_ascii_alphanumeric()
                                                        || matches!(
                                                            byte,
                                                            b'-' | b'_'
                                                                | b'.'
                                                                | b'~'
                                                                | b'+'
                                                                | b'/'
                                                                | b'='
                                                                | b'%'
                                                        )
                                                })
                                            {
                                                break 'inlined_is_credential_shaped false;
                                            }
                                            let unique =
                                                value.bytes().collect::<HashSet<_>>().len();
                                            let has_letter = value
                                                .bytes()
                                                .any(|byte| byte.is_ascii_alphabetic());
                                            let has_digit =
                                                value.bytes().any(|byte| byte.is_ascii_digit());
                                            unique >= 10 && has_letter && has_digit
                                        }
                                    }
                                }) {
                                    let source = {
                                        let (url,): (&Url,) = (url,);
                                        {
                                            'inlined_safe_source_url: {
                                                let Some(host) = url.host_str() else {
                                                    break 'inlined_safe_source_url "URL withheld"
                                                        .to_owned();
                                                };
                                                let port = url
                                                    .port()
                                                    .map(|port| format!(":{port}"))
                                                    .unwrap_or_default();
                                                format!(
                                                    "{}://{}{port}{}",
                                                    url.scheme(),
                                                    ({
                                                        let hostname: &str = host;
                                                        if hostname
                                                            .parse::<std::net::Ipv6Addr>()
                                                            .is_ok()
                                                        {
                                                            format!("[{hostname}]")
                                                        } else {
                                                            hostname.to_owned()
                                                        }
                                                    }),
                                                    url.path()
                                                )
                                            }
                                        }
                                    };
                                    let name = {
                                        let (value,): (&str,) = (&name,);
                                        let inlined_result: String = {
                                            let mut output = value
                                                .chars()
                                                .filter(|character| !character.is_control())
                                                .take(80)
                                                .collect::<String>();
                                            if value.chars().count() > 80 {
                                                output.push('…');
                                            }
                                            output
                                        };
                                        inlined_result
                                    };
                                    if seen.insert((source.clone(), name.clone())) {
                                        ({
                                            let (findings, endpoint, title, description, evidence,): (& mut SecuritySummaryFindings, & EndpointScan, & str, & str, String,) = (findings, endpoint, "Session or token identifier exposed in a URL", "A credential-shaped session or token identifier appears in a URL query parameter", format!("Parameter '{name}' appears in {source}; value withheld"),);

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
                                        });
                                    }
                                }
                            }
                        });
                    }
                }
            });
            ({
                let (findings, endpoint): (&mut SecuritySummaryFindings, &EndpointScan) =
                    (&mut findings, endpoint);

                let documents = endpoint
                    .http
                    .iter()
                    .filter(|response| {
                        (response)
                            .headers
                            .iter()
                            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                            .any(|(_, value)| value.to_ascii_lowercase().contains("text/html"))
                    })
                    .filter_map(|response| {
                        Url::parse(&response.url).ok().map(|url| (response, url))
                    })
                    .collect::<Vec<_>>();
                let mut reported = HashSet::new();
                for (response, url) in &documents {
                    let source = {
                        let (url,): (&Url,) = (url,);
                        {
                            'inlined_safe_source_url: {
                                let Some(host) = url.host_str() else {
                                    break 'inlined_safe_source_url "URL withheld".to_owned();
                                };
                                let port = url
                                    .port()
                                    .map(|port| format!(":{port}"))
                                    .unwrap_or_default();
                                format!(
                                    "{}://{}{port}{}",
                                    url.scheme(),
                                    ({
                                        let hostname: &str = host;
                                        if hostname.parse::<std::net::Ipv6Addr>().is_ok() {
                                            format!("[{hostname}]")
                                        } else {
                                            hostname.to_owned()
                                        }
                                    }),
                                    url.path()
                                )
                            }
                        }
                    };
                    let text = String::from_utf8_lossy(&response.body);
                    for script in {
                        let (document,): (&str,) = (&text,);
                        let inlined_result: Vec<&str> = {
                            let lower = document.to_ascii_lowercase();
                            let mut scripts = Vec::new();
                            let mut position = 0usize;
                            while let Some(relative_start) = lower[position..].find("<script") {
                                let start = position + relative_start;
                                let Some(relative_open_end) = lower[start..].find('>') else {
                                    break;
                                };
                                let open_end = start + relative_open_end + 1;
                                let Some(relative_close) = lower[open_end..].find("</script")
                                else {
                                    break;
                                };
                                let close = open_end + relative_close;
                                if html_attribute(&document[start..open_end], "src").is_none() {
                                    scripts.push(&document[open_end..close]);
                                }
                                position = close + "</script".len();
                            }
                            scripts
                        };
                        inlined_result
                    } {
                        ({
                            let (findings, endpoint, source, script, reported): (
                                &mut SecuritySummaryFindings,
                                &EndpointScan,
                                &str,
                                &str,
                                &mut HashSet<(String, String, String)>,
                            ) = (findings, endpoint, &source, script, &mut reported);

                            for write in {
                                let (script,): (&str,) = (script,);
                                let inlined_result: Vec<StorageWrite> = {
                                    let tokens = {
                                        let (script,): (&str,) = (script,);
                                        let inlined_result: Vec<ScriptToken> = {
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
                                                    while position < bytes.len()
                                                        && !matches!(bytes[position], b'\r' | b'\n')
                                                    {
                                                        position += 1;
                                                    }
                                                    continue;
                                                }
                                                if bytes[position..].starts_with(b"/*") {
                                                    position += 2;
                                                    while position + 1 < bytes.len()
                                                        && !bytes[position..].starts_with(b"*/")
                                                    {
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
                                                        if byte == b'\\'
                                                            && position + 1 < bytes.len()
                                                        {
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
                                                if byte.is_ascii_alphabetic()
                                                    || matches!(byte, b'_' | b'$')
                                                {
                                                    let start = position;
                                                    position += 1;
                                                    while position < bytes.len()
                                                        && (bytes[position].is_ascii_alphanumeric()
                                                            || matches!(
                                                                bytes[position],
                                                                b'_' | b'$'
                                                            ))
                                                    {
                                                        position += 1;
                                                    }
                                                    tokens.push(ScriptToken::Identifier(
                                                        String::from_utf8_lossy(
                                                            &bytes[start..position],
                                                        )
                                                        .into_owned(),
                                                    ));
                                                    continue;
                                                }
                                                tokens.push(ScriptToken::Punctuation(byte as char));
                                                position += 1;
                                            }
                                            tokens
                                        };
                                        inlined_result
                                    };
                                    let mut writes = Vec::new();
                                    for index in 0..tokens.len() {
                                        let storage = match tokens.get(index) {
                                            Some(ScriptToken::Identifier(name))
                                                if name == "localStorage" =>
                                            {
                                                "localStorage"
                                            }
                                            Some(ScriptToken::Identifier(name))
                                                if name == "sessionStorage" =>
                                            {
                                                "sessionStorage"
                                            }
                                            _ => continue,
                                        };
                                        if ({
                                            let (tokens, index, expected): (
                                                &[ScriptToken],
                                                usize,
                                                char,
                                            ) = (&tokens, index + 1, '.');
                                            {
                                                matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                            }
                                        }) && ({
                                            let (tokens, index): (&[ScriptToken], usize) =
                                                (&tokens, index + 2);
                                            {
                                                match tokens.get(index) {
                                                    Some(ScriptToken::Identifier(value)) => {
                                                        Some(value.as_str())
                                                    }
                                                    _ => None,
                                                }
                                            }
                                        }) == Some("setItem")
                                            && ({
                                                let (tokens, index, expected): (
                                                    &[ScriptToken],
                                                    usize,
                                                    char,
                                                ) = (&tokens, index + 3, '(');
                                                {
                                                    matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                                }
                                            })
                                            && let Some(key) = ({
                                                let (tokens, index): (&[ScriptToken], usize) =
                                                    (&tokens, index + 4);
                                                {
                                                    match tokens.get(index) {
                                                        Some(ScriptToken::Text(value)) => {
                                                            Some(value.as_str())
                                                        }
                                                        _ => None,
                                                    }
                                                }
                                            })
                                            && ({
                                                let (tokens, index, expected): (
                                                    &[ScriptToken],
                                                    usize,
                                                    char,
                                                ) = (&tokens, index + 5, ',');
                                                {
                                                    matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                                }
                                            })
                                        {
                                            let sensitive_value = ({
let (tokens, index,): (& [ScriptToken], usize,) = (&tokens, index + 6,);
{

    match tokens.get(index) {
        Some(ScriptToken::Text(value)) => Some(value.as_str()),
        _ => None,
    }

}

}).is_some_and(|value: & str| {
    let value = value.trim();
    if {
let (value,): (& str,) = (value,);
{
'inlined_is_structured_credential: {

    let value = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value);
    let segments = value.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        break 'inlined_is_structured_credential false;
    }
    let decode = |segment: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(segment))
            .ok()
    };
    let Some(header) = decode(segments[0]) else {
        break 'inlined_is_structured_credential false;
    };
    let Some(payload) = decode(segments[1]) else {
        break 'inlined_is_structured_credential false;
    };
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header) else {
        break 'inlined_is_structured_credential false;
    };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        break 'inlined_is_structured_credential false;
    };
    header.get("alg").and_then(|value| value.as_str()).is_some()
        && payload.as_object().is_some_and(|payload| {
            ["sub", "iss", "aud", "exp", "iat", "nbf", "jti"]
                .iter()
                .any(|claim| payload.contains_key(*claim))
        })

}
}

} {
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
});
                                            if ({
                                                let (key,): (&str,) = (key,);
                                                {
                                                    let normalized = key
                                                        .chars()
                                                        .filter(|character| {
                                                            character.is_ascii_alphanumeric()
                                                        })
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
                                            }) || sensitive_value
                                            {
                                                writes.push(StorageWrite {
                                                    storage,
                                                    key: key.to_owned(),
                                                });
                                            }
                                            continue;
                                        }
                                        let property_key = if {
                                            let (tokens, index, expected): (
                                                &[ScriptToken],
                                                usize,
                                                char,
                                            ) = (&tokens, index + 1, '.');
                                            {
                                                matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                            }
                                        } {
                                            ({
                                                let (tokens, index): (&[ScriptToken], usize) =
                                                    (&tokens, index + 2);
                                                {
                                                    match tokens.get(index) {
                                                        Some(ScriptToken::Identifier(value)) => {
                                                            Some(value.as_str())
                                                        }
                                                        _ => None,
                                                    }
                                                }
                                            })
                                            .map(str::to_owned)
                                        } else if ({
                                            let (tokens, index, expected): (
                                                &[ScriptToken],
                                                usize,
                                                char,
                                            ) = (&tokens, index + 1, '[');
                                            {
                                                matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                            }
                                        }) && ({
                                            let (tokens, index, expected): (
                                                &[ScriptToken],
                                                usize,
                                                char,
                                            ) = (&tokens, index + 3, ']');
                                            {
                                                matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                            }
                                        }) {
                                            ({
                                                let (tokens, index): (&[ScriptToken], usize) =
                                                    (&tokens, index + 2);
                                                {
                                                    match tokens.get(index) {
                                                        Some(ScriptToken::Text(value)) => {
                                                            Some(value.as_str())
                                                        }
                                                        _ => None,
                                                    }
                                                }
                                            })
                                            .map(str::to_owned)
                                        } else {
                                            None
                                        };
                                        let assignment_index = if {
                                            let (tokens, index, expected): (
                                                &[ScriptToken],
                                                usize,
                                                char,
                                            ) = (&tokens, index + 1, '.');
                                            {
                                                matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                            }
                                        } {
                                            index + 3
                                        } else {
                                            index + 4
                                        };
                                        let Some(key) = property_key else {
                                            continue;
                                        };
                                        if ({
                                            let (tokens, index, expected): (
                                                &[ScriptToken],
                                                usize,
                                                char,
                                            ) = (&tokens, assignment_index, '=');
                                            {
                                                matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                            }
                                        }) && !({
                                            let (tokens, index, expected): (
                                                &[ScriptToken],
                                                usize,
                                                char,
                                            ) = (&tokens, assignment_index + 1, '=');
                                            {
                                                matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                            }
                                        }) {
                                            let sensitive_value =
                ({
let (tokens, index,): (& [ScriptToken], usize,) = (&tokens, assignment_index + 1,);
{

    match tokens.get(index) {
        Some(ScriptToken::Text(value)) => Some(value.as_str()),
        _ => None,
    }

}

}).is_some_and(|value: & str| {
    let value = value.trim();
    if {
let (value,): (& str,) = (value,);
{
'inlined_is_structured_credential: {

    let value = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value);
    let segments = value.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        break 'inlined_is_structured_credential false;
    }
    let decode = |segment: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(segment))
            .ok()
    };
    let Some(header) = decode(segments[0]) else {
        break 'inlined_is_structured_credential false;
    };
    let Some(payload) = decode(segments[1]) else {
        break 'inlined_is_structured_credential false;
    };
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header) else {
        break 'inlined_is_structured_credential false;
    };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        break 'inlined_is_structured_credential false;
    };
    header.get("alg").and_then(|value| value.as_str()).is_some()
        && payload.as_object().is_some_and(|payload| {
            ["sub", "iss", "aud", "exp", "iat", "nbf", "jti"]
                .iter()
                .any(|claim| payload.contains_key(*claim))
        })

}
}

} {
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
});
                                            if ({
                                                let (key,): (&str,) = (&key,);
                                                {
                                                    let normalized = key
                                                        .chars()
                                                        .filter(|character| {
                                                            character.is_ascii_alphanumeric()
                                                        })
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
                                            }) || sensitive_value
                                            {
                                                writes.push(StorageWrite { storage, key });
                                            }
                                        }
                                    }
                                    writes
                                };
                                inlined_result
                            } {
                                let key = {
                                    let (value,): (&str,) = (&write.key,);
                                    let inlined_result: String = {
                                        let mut output = value
                                            .chars()
                                            .filter(|character| !character.is_control())
                                            .take(80)
                                            .collect::<String>();
                                        if value.chars().count() > 80 {
                                            output.push('…');
                                        }
                                        output
                                    };
                                    inlined_result
                                };
                                if !reported.insert((
                                    write.storage.to_owned(),
                                    key.clone(),
                                    source.to_owned(),
                                )) {
                                    continue;
                                }
                                ({
                                    let (findings, endpoint, title, description, evidence): (
                                        &mut SecuritySummaryFindings,
                                        &EndpointScan,
                                        &str,
                                        &str,
                                        String,
                                    ) = (
                                        findings,
                                        endpoint,
                                        &format!(
                                            "Authentication data written to {}",
                                            write.storage
                                        ),
                                        &format!(
                                            "Client-side code directly writes authentication or session data to {}",
                                            write.storage
                                        ),
                                        format!(
                                            "Key '{key}' written by {source}; stored value withheld"
                                        ),
                                    );

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
                                });
                            }
                        });
                    }
                }
                for response in endpoint.http.iter().filter(|response| {
                    let (response,): (&HttpObservation,) = (response,);
                    {
                        ({
                            let (response, name): (&crate::HttpObservation, &str) =
                                (response, "content-type");
                            response
                                .headers
                                .iter()
                                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                                .map(|(_, value)| value.as_str())
                        })
                        .any(|value| {
                            let value = value.to_ascii_lowercase();
                            value.contains("javascript") || value.contains("ecmascript")
                        }) || Url::parse(&response.url)
                            .ok()
                            .is_some_and(|url| url.path().to_ascii_lowercase().ends_with(".js"))
                    }
                }) {
                    let Ok(url) = Url::parse(&response.url) else {
                        continue;
                    };
                    if !documents
                        .iter()
                        .any(|(_, document_url)| same_origin(document_url, &url))
                    {
                        continue;
                    }
                    let source = {
                        let (url,): (&Url,) = (&url,);
                        {
                            'inlined_safe_source_url: {
                                let Some(host) = url.host_str() else {
                                    break 'inlined_safe_source_url "URL withheld".to_owned();
                                };
                                let port = url
                                    .port()
                                    .map(|port| format!(":{port}"))
                                    .unwrap_or_default();
                                format!(
                                    "{}://{}{port}{}",
                                    url.scheme(),
                                    ({
                                        let hostname: &str = host;
                                        if hostname.parse::<std::net::Ipv6Addr>().is_ok() {
                                            format!("[{hostname}]")
                                        } else {
                                            hostname.to_owned()
                                        }
                                    }),
                                    url.path()
                                )
                            }
                        }
                    };
                    let text = String::from_utf8_lossy(&response.body);
                    ({
                        let (findings, endpoint, source, script, reported): (
                            &mut SecuritySummaryFindings,
                            &EndpointScan,
                            &str,
                            &str,
                            &mut HashSet<(String, String, String)>,
                        ) = (findings, endpoint, &source, &text, &mut reported);

                        for write in {
                            let (script,): (&str,) = (script,);
                            let inlined_result: Vec<StorageWrite> = {
                                let tokens = {
                                    let (script,): (&str,) = (script,);
                                    let inlined_result: Vec<ScriptToken> = {
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
                                                while position < bytes.len()
                                                    && !matches!(bytes[position], b'\r' | b'\n')
                                                {
                                                    position += 1;
                                                }
                                                continue;
                                            }
                                            if bytes[position..].starts_with(b"/*") {
                                                position += 2;
                                                while position + 1 < bytes.len()
                                                    && !bytes[position..].starts_with(b"*/")
                                                {
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
                                            if byte.is_ascii_alphabetic()
                                                || matches!(byte, b'_' | b'$')
                                            {
                                                let start = position;
                                                position += 1;
                                                while position < bytes.len()
                                                    && (bytes[position].is_ascii_alphanumeric()
                                                        || matches!(bytes[position], b'_' | b'$'))
                                                {
                                                    position += 1;
                                                }
                                                tokens.push(ScriptToken::Identifier(
                                                    String::from_utf8_lossy(
                                                        &bytes[start..position],
                                                    )
                                                    .into_owned(),
                                                ));
                                                continue;
                                            }
                                            tokens.push(ScriptToken::Punctuation(byte as char));
                                            position += 1;
                                        }
                                        tokens
                                    };
                                    inlined_result
                                };
                                let mut writes = Vec::new();
                                for index in 0..tokens.len() {
                                    let storage = match tokens.get(index) {
                                        Some(ScriptToken::Identifier(name))
                                            if name == "localStorage" =>
                                        {
                                            "localStorage"
                                        }
                                        Some(ScriptToken::Identifier(name))
                                            if name == "sessionStorage" =>
                                        {
                                            "sessionStorage"
                                        }
                                        _ => continue,
                                    };
                                    if ({
                                        let (tokens, index, expected): (
                                            &[ScriptToken],
                                            usize,
                                            char,
                                        ) = (&tokens, index + 1, '.');
                                        {
                                            matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                        }
                                    }) && ({
                                        let (tokens, index): (&[ScriptToken], usize) =
                                            (&tokens, index + 2);
                                        {
                                            match tokens.get(index) {
                                                Some(ScriptToken::Identifier(value)) => {
                                                    Some(value.as_str())
                                                }
                                                _ => None,
                                            }
                                        }
                                    }) == Some("setItem")
                                        && ({
                                            let (tokens, index, expected): (
                                                &[ScriptToken],
                                                usize,
                                                char,
                                            ) = (&tokens, index + 3, '(');
                                            {
                                                matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                            }
                                        })
                                        && let Some(key) = ({
                                            let (tokens, index): (&[ScriptToken], usize) =
                                                (&tokens, index + 4);
                                            {
                                                match tokens.get(index) {
                                                    Some(ScriptToken::Text(value)) => {
                                                        Some(value.as_str())
                                                    }
                                                    _ => None,
                                                }
                                            }
                                        })
                                        && ({
                                            let (tokens, index, expected): (
                                                &[ScriptToken],
                                                usize,
                                                char,
                                            ) = (&tokens, index + 5, ',');
                                            {
                                                matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                            }
                                        })
                                    {
                                        let sensitive_value = ({
let (tokens, index,): (& [ScriptToken], usize,) = (&tokens, index + 6,);
{

    match tokens.get(index) {
        Some(ScriptToken::Text(value)) => Some(value.as_str()),
        _ => None,
    }

}

}).is_some_and(|value: & str| {
    let value = value.trim();
    if {
let (value,): (& str,) = (value,);
{
'inlined_is_structured_credential: {

    let value = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value);
    let segments = value.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        break 'inlined_is_structured_credential false;
    }
    let decode = |segment: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(segment))
            .ok()
    };
    let Some(header) = decode(segments[0]) else {
        break 'inlined_is_structured_credential false;
    };
    let Some(payload) = decode(segments[1]) else {
        break 'inlined_is_structured_credential false;
    };
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header) else {
        break 'inlined_is_structured_credential false;
    };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        break 'inlined_is_structured_credential false;
    };
    header.get("alg").and_then(|value| value.as_str()).is_some()
        && payload.as_object().is_some_and(|payload| {
            ["sub", "iss", "aud", "exp", "iat", "nbf", "jti"]
                .iter()
                .any(|claim| payload.contains_key(*claim))
        })

}
}

} {
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
});
                                        if ({
                                            let (key,): (&str,) = (key,);
                                            {
                                                let normalized = key
                                                    .chars()
                                                    .filter(|character| {
                                                        character.is_ascii_alphanumeric()
                                                    })
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
                                        }) || sensitive_value
                                        {
                                            writes.push(StorageWrite {
                                                storage,
                                                key: key.to_owned(),
                                            });
                                        }
                                        continue;
                                    }
                                    let property_key = if {
                                        let (tokens, index, expected): (
                                            &[ScriptToken],
                                            usize,
                                            char,
                                        ) = (&tokens, index + 1, '.');
                                        {
                                            matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                        }
                                    } {
                                        ({
                                            let (tokens, index): (&[ScriptToken], usize) =
                                                (&tokens, index + 2);
                                            {
                                                match tokens.get(index) {
                                                    Some(ScriptToken::Identifier(value)) => {
                                                        Some(value.as_str())
                                                    }
                                                    _ => None,
                                                }
                                            }
                                        })
                                        .map(str::to_owned)
                                    } else if ({
                                        let (tokens, index, expected): (
                                            &[ScriptToken],
                                            usize,
                                            char,
                                        ) = (&tokens, index + 1, '[');
                                        {
                                            matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                        }
                                    }) && ({
                                        let (tokens, index, expected): (
                                            &[ScriptToken],
                                            usize,
                                            char,
                                        ) = (&tokens, index + 3, ']');
                                        {
                                            matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                        }
                                    }) {
                                        ({
                                            let (tokens, index): (&[ScriptToken], usize) =
                                                (&tokens, index + 2);
                                            {
                                                match tokens.get(index) {
                                                    Some(ScriptToken::Text(value)) => {
                                                        Some(value.as_str())
                                                    }
                                                    _ => None,
                                                }
                                            }
                                        })
                                        .map(str::to_owned)
                                    } else {
                                        None
                                    };
                                    let assignment_index = if {
                                        let (tokens, index, expected): (
                                            &[ScriptToken],
                                            usize,
                                            char,
                                        ) = (&tokens, index + 1, '.');
                                        {
                                            matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                        }
                                    } {
                                        index + 3
                                    } else {
                                        index + 4
                                    };
                                    let Some(key) = property_key else {
                                        continue;
                                    };
                                    if ({
                                        let (tokens, index, expected): (
                                            &[ScriptToken],
                                            usize,
                                            char,
                                        ) = (&tokens, assignment_index, '=');
                                        {
                                            matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                        }
                                    }) && !({
                                        let (tokens, index, expected): (
                                            &[ScriptToken],
                                            usize,
                                            char,
                                        ) = (&tokens, assignment_index + 1, '=');
                                        {
                                            matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
                                        }
                                    }) {
                                        let sensitive_value =
                ({
let (tokens, index,): (& [ScriptToken], usize,) = (&tokens, assignment_index + 1,);
{

    match tokens.get(index) {
        Some(ScriptToken::Text(value)) => Some(value.as_str()),
        _ => None,
    }

}

}).is_some_and(|value: & str| {
    let value = value.trim();
    if {
let (value,): (& str,) = (value,);
{
'inlined_is_structured_credential: {

    let value = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value);
    let segments = value.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        break 'inlined_is_structured_credential false;
    }
    let decode = |segment: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(segment))
            .ok()
    };
    let Some(header) = decode(segments[0]) else {
        break 'inlined_is_structured_credential false;
    };
    let Some(payload) = decode(segments[1]) else {
        break 'inlined_is_structured_credential false;
    };
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header) else {
        break 'inlined_is_structured_credential false;
    };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        break 'inlined_is_structured_credential false;
    };
    header.get("alg").and_then(|value| value.as_str()).is_some()
        && payload.as_object().is_some_and(|payload| {
            ["sub", "iss", "aud", "exp", "iat", "nbf", "jti"]
                .iter()
                .any(|claim| payload.contains_key(*claim))
        })

}
}

} {
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
});
                                        if ({
                                            let (key,): (&str,) = (&key,);
                                            {
                                                let normalized = key
                                                    .chars()
                                                    .filter(|character| {
                                                        character.is_ascii_alphanumeric()
                                                    })
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
                                        }) || sensitive_value
                                        {
                                            writes.push(StorageWrite { storage, key });
                                        }
                                    }
                                }
                                writes
                            };
                            inlined_result
                        } {
                            let key = {
                                let (value,): (&str,) = (&write.key,);
                                let inlined_result: String = {
                                    let mut output = value
                                        .chars()
                                        .filter(|character| !character.is_control())
                                        .take(80)
                                        .collect::<String>();
                                    if value.chars().count() > 80 {
                                        output.push('…');
                                    }
                                    output
                                };
                                inlined_result
                            };
                            if !reported.insert((
                                write.storage.to_owned(),
                                key.clone(),
                                source.to_owned(),
                            )) {
                                continue;
                            }
                            ({
                                let (findings, endpoint, title, description, evidence): (
                                    &mut SecuritySummaryFindings,
                                    &EndpointScan,
                                    &str,
                                    &str,
                                    String,
                                ) = (
                                    findings,
                                    endpoint,
                                    &format!("Authentication data written to {}", write.storage),
                                    &format!(
                                        "Client-side code directly writes authentication or session data to {}",
                                        write.storage
                                    ),
                                    format!(
                                        "Key '{key}' written by {source}; stored value withheld"
                                    ),
                                );

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
                            });
                        }
                    });
                }
            });
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

type SecuritySummaryFindings = BTreeMap<(IpAddr, u16, TransportProtocol, String), ExposureFinding>;

pub(super) fn add_security_summary_finding(
    findings: &mut SecuritySummaryFindings,
    finding: ExposureFinding,
) {
    let key = {
        let finding = &finding;
        (
            finding.ip,
            finding.port,
            finding.transport,
            finding.title.clone(),
        )
    };
    if let Some(existing) = findings.get_mut(&key) {
        existing.evidence.extend(finding.evidence);
        existing.evidence.sort();
        existing.evidence.dedup();
    } else {
        findings.insert(key, finding);
    }
}
