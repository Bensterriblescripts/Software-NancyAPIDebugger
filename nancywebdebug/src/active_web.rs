use super::*;
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, PartialEq, Eq, Hash)]
struct OriginKey {
    ip: IpAddr,
    port: u16,
    scheme: String,
}

struct RequestBudget {
    per_origin_limit: usize,
    total_limit: usize,
    used: usize,
    per_origin: HashMap<OriginKey, usize>,
}

impl RequestBudget {
    fn new(request: &ExposureScanRequest) -> Self {
        Self {
            per_origin_limit: request.active_requests_per_origin,
            total_limit: request.active_requests_total,
            used: 0,
            per_origin: HashMap::new(),
        }
    }

    fn consume(&mut self, origin: &OriginKey) -> Result<(), String> {
        if self.used >= self.total_limit {
            return Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= self.per_origin_limit {
            return Err("Per-origin active-request budget exhausted".to_owned());
        }
        self.used += 1;
        *origin_used += 1;
        Ok(())
    }
}

pub(super) async fn run(
    endpoints: &mut [EndpointScan],
    resources: &[CrawledResource],
    forms: &[CrawlFormAction],
    scan: ScanContext<'_>,
    progress: &Option<Sender<ExposureScanProgress>>,
) {
    let mut budget = RequestBudget::new(scan.request);
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        0.0,
        "Preparing bounded active probes",
    );
    let mut assessed = 0usize;
    for endpoint in endpoints.iter_mut() {
        if scan.cancel.is_cancelled() || budget.used >= budget.total_limit {
            break;
        }
        let Some(root) = endpoint_root(endpoint, scan.hostname) else {
            continue;
        };
        let origin = OriginKey {
            ip: endpoint.ip,
            port: endpoint.port,
            scheme: root.scheme().to_owned(),
        };
        let context = ProbeContext {
            ip: endpoint.ip,
            port: endpoint.port,
            scan,
        };
        let candidates = query_candidates(endpoint, resources, &root);
        let protected = protected_candidates(endpoint, resources, &root);
        let endpoint_forms = form_candidates(forms, endpoint, &root);
        let root_response = send_http(
            context,
            &origin,
            "GET",
            &root,
            &[],
            &[],
            None,
            None,
            &mut budget,
            progress,
        )
        .await;
        let mut checks = Vec::new();
        checks.push(
            probe_host_header(
                context,
                &origin,
                &root,
                root_response.as_ref().ok(),
                &mut budget,
                progress,
            )
            .await,
        );
        checks.extend(
            probe_input_handling(
                context,
                &origin,
                &candidates,
                &root,
                root_response.as_ref().ok(),
                &mut budget,
                progress,
            )
            .await,
        );
        checks
            .push(probe_open_redirect(context, &origin, &candidates, &mut budget, progress).await);
        checks.push(probe_ssrf(context, &origin, &candidates, &mut budget, progress).await);
        checks.push(
            probe_access_control(
                context,
                &origin,
                &root,
                root_response.as_ref().ok(),
                &protected,
                &mut budget,
                progress,
            )
            .await,
        );
        checks.push(probe_message_framing(context, &origin, &root, &mut budget, progress).await);
        checks.push(
            probe_session_fixation(
                context,
                &origin,
                &root,
                root_response.as_ref().ok(),
                &mut budget,
                progress,
            )
            .await,
        );
        checks.push(
            probe_csrf(
                context,
                &origin,
                &root,
                root_response.as_ref().ok(),
                &endpoint_forms,
                &mut budget,
                progress,
            )
            .await,
        );
        endpoint.security_checks.extend(checks);
        assessed += 1;
    }
    if !scan.cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::ActiveWebAssessment,
            ExposureScanPhaseState::Complete,
            1.0,
            format!(
                "{assessed} web origins assessed with {} active requests",
                budget.used
            ),
        );
    }
}

async fn send_http(
    context: ProbeContext<'_>,
    origin: &OriginKey,
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    body: &[u8],
    cookie_header: Option<&str>,
    host_override: Option<&str>,
    budget: &mut RequestBudget,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> Result<HttpObservation, String> {
    budget.consume(origin)?;
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("{method} {}", display_target(url)),
    );
    let mut response = active_http_request(
        context,
        &origin.scheme,
        method,
        &url_path(url),
        headers,
        body,
        cookie_header,
        host_override,
    )
    .await?;
    response.url = url.to_string();
    Ok(response)
}

fn endpoint_root(endpoint: &EndpointScan, hostname: &str) -> Option<Url> {
    let mut selected = endpoint
        .http
        .iter()
        .filter_map(|response| Url::parse(&response.url).ok())
        .filter(|url| {
            matches!(url.scheme(), "http" | "https")
                && url
                    .host_str()
                    .is_some_and(|host| host.eq_ignore_ascii_case(hostname))
                && url.port_or_known_default() == Some(endpoint.port)
        })
        .max_by_key(|url| url.scheme() == "https")?;
    selected.set_path("/");
    selected.set_query(None);
    selected.set_fragment(None);
    Some(selected)
}

fn query_candidates(
    endpoint: &EndpointScan,
    resources: &[CrawledResource],
    root: &Url,
) -> Vec<Url> {
    let mut values = BTreeSet::new();
    for value in endpoint
        .http
        .iter()
        .map(|response| response.url.as_str())
        .chain(
            resources
                .iter()
                .filter(|resource| resource.ip == endpoint.ip && resource.port == endpoint.port)
                .map(|resource| resource.url.as_str()),
        )
    {
        let Ok(mut url) = Url::parse(value) else {
            continue;
        };
        url.set_fragment(None);
        if same_origin(root, &url) && url.query().is_some() {
            values.insert(url.to_string());
        }
        if values.len() >= 12 {
            break;
        }
    }
    if values.is_empty() {
        let mut url = root.clone();
        url.query_pairs_mut().append_pair("nancy_probe", "baseline");
        values.insert(url.to_string());
    }
    values
        .into_iter()
        .filter_map(|value| Url::parse(&value).ok())
        .collect()
}

fn protected_candidates(
    endpoint: &EndpointScan,
    resources: &[CrawledResource],
    root: &Url,
) -> Vec<(Url, u16)> {
    let mut values = BTreeSet::new();
    for response in endpoint
        .http
        .iter()
        .filter(|response| matches!(response.status, 401 | 403))
    {
        values.insert((response.url.clone(), response.status));
    }
    for resource in resources.iter().filter(|resource| {
        resource.ip == endpoint.ip
            && resource.port == endpoint.port
            && matches!(resource.status, Some(401 | 403))
    }) {
        values.insert((resource.url.clone(), resource.status.unwrap_or_default()));
    }
    values
        .into_iter()
        .filter_map(|(value, status)| {
            let url = Url::parse(&value).ok()?;
            same_origin(root, &url).then_some((url, status))
        })
        .take(3)
        .collect()
}

fn form_candidates<'a>(
    forms: &'a [CrawlFormAction],
    endpoint: &EndpointScan,
    root: &Url,
) -> Vec<&'a CrawlFormAction> {
    forms
        .iter()
        .filter(|form| {
            let Ok(url) = Url::parse(&form.action_url) else {
                return false;
            };
            same_origin(root, &url)
                && url.port_or_known_default() == Some(endpoint.port)
                && !["GET", "HEAD", "OPTIONS", "TRACE"]
                    .iter()
                    .any(|method| form.method.eq_ignore_ascii_case(method))
        })
        .take(12)
        .collect()
}

async fn probe_host_header(
    context: ProbeContext<'_>,
    origin: &OriginKey,
    root: &Url,
    baseline: Option<&HttpObservation>,
    budget: &mut RequestBudget,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> SecurityCheckResult {
    let token = probe_token(context);
    let host = format!("nancy-{token}.invalid");
    let forwarded_headers = vec![("X-Forwarded-Host".to_owned(), host.clone())];
    let direct = send_http(
        context,
        origin,
        "GET",
        root,
        &[],
        &[],
        None,
        Some(&host),
        budget,
        progress,
    )
    .await;
    let forwarded = send_http(
        context,
        origin,
        "GET",
        root,
        &forwarded_headers,
        &[],
        None,
        None,
        budget,
        progress,
    )
    .await;
    let finding = [
        ("Host", direct.as_ref().ok()),
        ("X-Forwarded-Host", forwarded.as_ref().ok()),
    ]
    .into_iter()
    .find(|(_, response)| {
        response.is_some_and(|response| response_references_host(response, &host))
    });
    if let Some((header, response)) = finding {
        let response = response.unwrap();
        return check(
            context,
            "http.host-header",
            VulnerabilityClass::HttpInfrastructure,
            "Host header injection",
            FindingSeverity::Medium,
            Confidence::High,
            CheckOutcome::Vulnerable,
            Some(root.to_string()),
            Some(format!("GET / with {header}: {host}")),
            vec![format!(
                "HTTP {} response incorporated the supplied host into an absolute URL or redirect",
                response.status
            )],
            None,
        );
    }
    let errors = [direct.err(), forwarded.err()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if baseline.is_none() && errors.len() == 2 {
        return inconclusive(
            context,
            "http.host-header",
            VulnerabilityClass::HttpInfrastructure,
            "Host header injection",
            Some(root.to_string()),
            errors.join("; "),
        );
    }
    check(
        context,
        "http.host-header",
        VulnerabilityClass::HttpInfrastructure,
        "Host header injection",
        FindingSeverity::Medium,
        Confidence::Medium,
        CheckOutcome::NotObserved,
        Some(root.to_string()),
        Some("GET / with alternate Host and X-Forwarded-Host values".to_owned()),
        Vec::new(),
        errors.first().cloned(),
    )
}

async fn probe_input_handling(
    context: ProbeContext<'_>,
    origin: &OriginKey,
    candidates: &[Url],
    root: &Url,
    root_response: Option<&HttpObservation>,
    budget: &mut RequestBudget,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> Vec<SecurityCheckResult> {
    let mut xss = None;
    let mut sql = None;
    let mut checked = 0usize;
    let mut errors = Vec::new();
    for (index, candidate) in candidates.iter().take(6).enumerate() {
        if context.scan.cancel.is_cancelled() {
            break;
        }
        let baseline = if same_request_url(candidate, root) {
            root_response
                .cloned()
                .ok_or_else(|| "Root baseline unavailable".to_owned())
        } else {
            send_http(
                context,
                origin,
                "GET",
                candidate,
                &[],
                &[],
                None,
                None,
                budget,
                progress,
            )
            .await
        };
        let Ok(baseline) = baseline else {
            errors.push(baseline.err().unwrap_or_default());
            continue;
        };
        let token = format!("{}-{index}", probe_token(context));
        let element = format!("<nancy-probe data-nancy=\"{token}\">");
        let payload = format!("nancy-{token}'\">{element}");
        let (mutated, parameter) = mutate_first_parameter(candidate, &payload);
        let response = send_http(
            context,
            origin,
            "GET",
            &mutated,
            &[],
            &[],
            None,
            None,
            budget,
            progress,
        )
        .await;
        let Ok(response) = response else {
            errors.push(response.err().unwrap_or_default());
            continue;
        };
        checked += 1;
        let baseline_text = String::from_utf8_lossy(&baseline.body);
        let response_text = String::from_utf8_lossy(&response.body);
        if xss.is_none()
            && is_html(&response)
            && response_text.contains(&element)
            && !baseline_text.contains(&element)
        {
            xss = Some((mutated.clone(), parameter.clone(), response.status));
        }
        if sql.is_none()
            && let Some(marker) = new_sql_error(&baseline_text, &response_text)
        {
            sql = Some((mutated, parameter, response.status, marker.to_owned()));
        }
        if xss.is_some() && sql.is_some() {
            break;
        }
    }
    let xss_check = if let Some((url, parameter, status)) = xss {
        check(
            context,
            "client.reflected-markup",
            VulnerabilityClass::ClientSide,
            "Unencoded reflected markup",
            FindingSeverity::Medium,
            Confidence::Medium,
            CheckOutcome::Potential,
            Some(url.to_string()),
            Some(format!("GET with a benign markup probe in '{parameter}'")),
            vec![format!(
                "HTTP {status} reflected the exact custom-element probe without HTML encoding"
            )],
            Some("Browser execution context was not established, so this is not a confirmed XSS finding".to_owned()),
        )
    } else {
        observed_or_inconclusive(
            context,
            "client.reflected-markup",
            VulnerabilityClass::ClientSide,
            "Unencoded reflected markup",
            FindingSeverity::Medium,
            checked,
            errors.first().cloned(),
        )
    };
    let sql_check = if let Some((url, parameter, status, marker)) = sql {
        check(
            context,
            "injection.sql-error",
            VulnerabilityClass::Injection,
            "SQL error disclosure after input mutation",
            FindingSeverity::High,
            Confidence::Medium,
            CheckOutcome::Potential,
            Some(url.to_string()),
            Some(format!("GET with a quote-bearing marker in '{parameter}'")),
            vec![format!(
                "HTTP {status} introduced the database error signature '{marker}'"
            )],
            Some("An error differential indicates unsafe input handling but does not prove query control".to_owned()),
        )
    } else {
        observed_or_inconclusive(
            context,
            "injection.sql-error",
            VulnerabilityClass::Injection,
            "SQL error disclosure after input mutation",
            FindingSeverity::High,
            checked,
            errors.first().cloned(),
        )
    };
    vec![xss_check, sql_check]
}

async fn probe_open_redirect(
    context: ProbeContext<'_>,
    origin: &OriginKey,
    candidates: &[Url],
    budget: &mut RequestBudget,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> SecurityCheckResult {
    let names = [
        "url",
        "uri",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "return",
        "return_url",
        "next",
        "continue",
        "destination",
        "dest",
        "callback",
    ];
    let mut attempted = 0usize;
    let mut last_error = None;
    for candidate in candidates {
        for (index, (name, _)) in candidate.query_pairs().enumerate() {
            if !names.iter().any(|item| name.eq_ignore_ascii_case(item)) {
                continue;
            }
            let token = probe_token(context);
            let external = format!("https://nancy-{token}.invalid/redirect-check");
            let mutated = mutate_parameter(candidate, index, &external);
            let response = send_http(
                context,
                origin,
                "GET",
                &mutated,
                &[],
                &[],
                None,
                None,
                budget,
                progress,
            )
            .await;
            match response {
                Ok(response) if redirects_to_host(&response, &format!("nancy-{token}.invalid")) => {
                    return check(
                        context,
                        "client.open-redirect",
                        VulnerabilityClass::ClientSide,
                        "Open redirect",
                        FindingSeverity::Medium,
                        Confidence::High,
                        CheckOutcome::Vulnerable,
                        Some(mutated.to_string()),
                        Some(format!("GET with an external URL in '{name}'")),
                        vec![format!(
                            "HTTP {} redirected to the supplied external .invalid host",
                            response.status
                        )],
                        None,
                    );
                }
                Err(error) => last_error = Some(error),
                Ok(_) => attempted += 1,
            }
            if attempted >= 6 {
                break;
            }
        }
        if attempted >= 6 {
            break;
        }
    }
    if attempted == 0 {
        return skipped(
            context,
            "client.open-redirect",
            VulnerabilityClass::ClientSide,
            "Open redirect",
            "No redirect-like query parameter was discovered",
        );
    }
    observed_or_inconclusive(
        context,
        "client.open-redirect",
        VulnerabilityClass::ClientSide,
        "Open redirect",
        FindingSeverity::Medium,
        attempted,
        last_error,
    )
}

async fn probe_ssrf(
    context: ProbeContext<'_>,
    origin: &OriginKey,
    candidates: &[Url],
    budget: &mut RequestBudget,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> SecurityCheckResult {
    let names = [
        "url", "uri", "endpoint", "feed", "proxy", "fetch", "callback", "webhook", "source",
        "image", "host", "domain",
    ];
    let mut attempted = 0usize;
    let mut last_error = None;
    for candidate in candidates {
        for (index, (name, _)) in candidate.query_pairs().enumerate() {
            if !names.iter().any(|item| name.eq_ignore_ascii_case(item)) {
                continue;
            }
            let baseline = send_http(
                context,
                origin,
                "GET",
                candidate,
                &[],
                &[],
                None,
                None,
                budget,
                progress,
            )
            .await;
            let token = probe_token(context);
            let payload = format!("http://127.0.0.1:1/nancy-{token}");
            let mutated = mutate_parameter(candidate, index, &payload);
            let response = send_http(
                context,
                origin,
                "GET",
                &mutated,
                &[],
                &[],
                None,
                None,
                budget,
                progress,
            )
            .await;
            match (baseline, response) {
                (Ok(baseline), Ok(response))
                    if has_new_ssrf_error(&baseline, &response, &token) =>
                {
                    return check(
                        context,
                        "server-side.ssrf-loopback",
                        VulnerabilityClass::ServerSideRequestHandling,
                        "Possible server-side URL fetch",
                        FindingSeverity::High,
                        Confidence::Medium,
                        CheckOutcome::Potential,
                        Some(mutated.to_string()),
                        Some(format!("GET with a loopback URL in '{name}'")),
                        vec![format!(
                            "HTTP {} introduced a loopback connection-error signature",
                            response.status
                        )],
                        Some("The bounded loopback probe did not access a listening internal service; confirm with an authorized callback endpoint".to_owned()),
                    );
                }
                (_, Err(error)) | (Err(error), _) => last_error = Some(error),
                (Ok(_), Ok(_)) => attempted += 1,
            }
            if attempted >= 3 {
                break;
            }
        }
        if attempted >= 3 {
            break;
        }
    }
    if attempted == 0 {
        return skipped(
            context,
            "server-side.ssrf-loopback",
            VulnerabilityClass::ServerSideRequestHandling,
            "Possible server-side URL fetch",
            "No server-side URL input candidate was discovered",
        );
    }
    observed_or_inconclusive(
        context,
        "server-side.ssrf-loopback",
        VulnerabilityClass::ServerSideRequestHandling,
        "Possible server-side URL fetch",
        FindingSeverity::High,
        attempted,
        last_error,
    )
}

async fn probe_access_control(
    context: ProbeContext<'_>,
    origin: &OriginKey,
    root: &Url,
    root_response: Option<&HttpObservation>,
    candidates: &[(Url, u16)],
    budget: &mut RequestBudget,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> SecurityCheckResult {
    let Some((protected, status)) = candidates.first() else {
        return skipped(
            context,
            "access-control.route-bypass",
            VulnerabilityClass::AccessControl,
            "Protected-route method or rewrite bypass",
            "No HTTP 401 or 403 resource was discovered",
        );
    };
    let mut attempted = 0usize;
    let mut last_error = None;
    let head = send_http(
        context,
        origin,
        "HEAD",
        protected,
        &[],
        &[],
        None,
        None,
        budget,
        progress,
    )
    .await;
    match head {
        Ok(response) if (200..300).contains(&response.status) => {
            return check(
                context,
                "access-control.route-bypass",
                VulnerabilityClass::AccessControl,
                "Protected-route method or rewrite bypass",
                FindingSeverity::High,
                Confidence::Medium,
                CheckOutcome::Potential,
                Some(protected.to_string()),
                Some(format!("HEAD {}", url_path(protected))),
                vec![format!(
                    "GET was recorded as HTTP {status}, while HEAD returned HTTP {}",
                    response.status
                )],
                Some(
                    "Confirm that the HEAD response traversed the same authorization path as GET"
                        .to_owned(),
                ),
            );
        }
        Err(error) => last_error = Some(error),
        Ok(_) => attempted += 1,
    }
    for header in ["X-Original-URL", "X-Rewrite-URL"] {
        let headers = vec![(header.to_owned(), url_path(protected))];
        let response = send_http(
            context,
            origin,
            "GET",
            root,
            &headers,
            &[],
            None,
            None,
            budget,
            progress,
        )
        .await;
        match response {
            Ok(response)
                if (200..300).contains(&response.status)
                    && root_response
                        .is_none_or(|baseline| materially_different(baseline, &response)) =>
            {
                return check(
                    context,
                    "access-control.route-bypass",
                    VulnerabilityClass::AccessControl,
                    "Protected-route method or rewrite bypass",
                    FindingSeverity::High,
                    Confidence::Medium,
                    CheckOutcome::Potential,
                    Some(protected.to_string()),
                    Some(format!("GET / with {header}: {}", url_path(protected))),
                    vec![format!(
                        "Direct access returned HTTP {status}; the rewrite-header probe returned HTTP {} with content distinct from the root baseline",
                        response.status
                    )],
                    Some("Verify the returned representation before treating this as an authorization bypass".to_owned()),
                );
            }
            Err(error) => last_error = Some(error),
            Ok(_) => attempted += 1,
        }
    }
    observed_or_inconclusive(
        context,
        "access-control.route-bypass",
        VulnerabilityClass::AccessControl,
        "Protected-route method or rewrite bypass",
        FindingSeverity::High,
        attempted,
        last_error,
    )
}

async fn probe_message_framing(
    context: ProbeContext<'_>,
    origin: &OriginKey,
    root: &Url,
    budget: &mut RequestBudget,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> SecurityCheckResult {
    if let Err(error) = budget.consume(origin) {
        return inconclusive(
            context,
            "http.ambiguous-framing",
            VulnerabilityClass::HttpInfrastructure,
            "Ambiguous HTTP/1.1 framing handling",
            Some(root.to_string()),
            error,
        );
    }
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("OPTIONS {} framing check", display_target(root)),
    );
    let host = request_host(root);
    let raw = format!(
        "OPTIONS / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nancywebdebug-active/{}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    match active_raw_http_exchange(context, &origin.scheme, raw.as_bytes()).await {
        Ok((bytes, duration_ms, false))
            if http_status(&bytes).is_some() && !raw_response_closes(&bytes) =>
        {
            check(
            context,
            "http.ambiguous-framing",
            VulnerabilityClass::HttpInfrastructure,
            "Ambiguous HTTP/1.1 framing handling",
            FindingSeverity::Medium,
            Confidence::Medium,
            CheckOutcome::Potential,
            Some(root.to_string()),
            Some("OPTIONS / with aligned Content-Length and Transfer-Encoding framing".to_owned()),
            vec![format!(
                "The server responded in {duration_ms:.1} ms but did not close the connection after receiving both framing headers"
            )],
            Some("No second request was sent; confirm parser behavior across every intermediary before concluding request smuggling is possible".to_owned()),
        )
        }
        Ok((bytes, _, peer_closed))
            if http_status(&bytes).is_some() && (peer_closed || raw_response_closes(&bytes)) =>
        {
            check(
            context,
            "http.ambiguous-framing",
            VulnerabilityClass::HttpInfrastructure,
            "Ambiguous HTTP/1.1 framing handling",
            FindingSeverity::Medium,
            Confidence::High,
            CheckOutcome::NotObserved,
            Some(root.to_string()),
            Some("OPTIONS / with aligned Content-Length and Transfer-Encoding framing".to_owned()),
            vec![
                "The peer closed the connection or declared Connection: close after the ambiguous request"
                    .to_owned(),
            ],
            None,
        )
        }
        Ok((bytes, _, _)) => inconclusive(
            context,
            "http.ambiguous-framing",
            VulnerabilityClass::HttpInfrastructure,
            "Ambiguous HTTP/1.1 framing handling",
            Some(root.to_string()),
            format!(
                "The peer returned {} bytes without a complete HTTP status line",
                bytes.len()
            ),
        ),
        Err(error) => inconclusive(
            context,
            "http.ambiguous-framing",
            VulnerabilityClass::HttpInfrastructure,
            "Ambiguous HTTP/1.1 framing handling",
            Some(root.to_string()),
            error,
        ),
    }
}

async fn probe_session_fixation(
    context: ProbeContext<'_>,
    origin: &OriginKey,
    root: &Url,
    baseline: Option<&HttpObservation>,
    budget: &mut RequestBudget,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> SecurityCheckResult {
    let Some(baseline) = baseline else {
        return inconclusive(
            context,
            "session.fixation",
            VulnerabilityClass::SessionAuthentication,
            "Session fixation",
            Some(root.to_string()),
            "Root response was unavailable".to_owned(),
        );
    };
    let names = set_cookie_values(baseline)
        .into_iter()
        .filter(|(name, _, _)| likely_session_cookie(name))
        .map(|(name, _, _)| name)
        .take(2)
        .collect::<Vec<_>>();
    if names.is_empty() {
        return skipped(
            context,
            "session.fixation",
            VulnerabilityClass::SessionAuthentication,
            "Session fixation",
            "No session-like response cookie was observed",
        );
    }
    let mut attempted = 0usize;
    let mut last_error = None;
    for name in names {
        let marker = format!("nancyfix{}", probe_token(context));
        let cookie = format!("{name}={marker}");
        match send_http(
            context,
            origin,
            "GET",
            root,
            &[],
            &[],
            Some(&cookie),
            None,
            budget,
            progress,
        )
        .await
        {
            Ok(response)
                if set_cookie_values(&response)
                    .iter()
                    .any(|(response_name, value, _)| {
                        response_name.eq_ignore_ascii_case(&name) && value == &marker
                    }) =>
            {
                return check(
                    context,
                    "session.fixation",
                    VulnerabilityClass::SessionAuthentication,
                    "Session fixation",
                    FindingSeverity::High,
                    Confidence::Medium,
                    CheckOutcome::Potential,
                    Some(root.to_string()),
                    Some(format!("GET / with a caller-selected {name} cookie")),
                    vec![format!(
                        "The response reissued the supplied marker as the value of '{name}'"
                    )],
                    Some("Confirm that the cookie controls an authenticated session before treating fixation as exploitable".to_owned()),
                );
            }
            Err(error) => last_error = Some(error),
            Ok(_) => attempted += 1,
        }
    }
    observed_or_inconclusive(
        context,
        "session.fixation",
        VulnerabilityClass::SessionAuthentication,
        "Session fixation",
        FindingSeverity::High,
        attempted,
        last_error,
    )
}

async fn probe_csrf(
    context: ProbeContext<'_>,
    origin: &OriginKey,
    root: &Url,
    baseline: Option<&HttpObservation>,
    forms: &[&CrawlFormAction],
    budget: &mut RequestBudget,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> SecurityCheckResult {
    let unprotected = forms
        .iter()
        .copied()
        .filter(|form| form.likely_csrf_tokens.is_empty())
        .collect::<Vec<_>>();
    if forms.is_empty() {
        return skipped(
            context,
            "session.csrf-form",
            VulnerabilityClass::SessionAuthentication,
            "Cross-site request forgery protection",
            "No state-changing forms were discovered",
        );
    }
    if unprotected.is_empty() {
        return check(
            context,
            "session.csrf-form",
            VulnerabilityClass::SessionAuthentication,
            "Cross-site request forgery protection",
            FindingSeverity::Medium,
            Confidence::Low,
            CheckOutcome::NotObserved,
            None,
            None,
            vec!["All discovered state-changing forms contained a token-like control".to_owned()],
            None,
        );
    }
    if !context.scan.request.web_probe_level.state_changing() {
        return check(
            context,
            "session.csrf-form",
            VulnerabilityClass::SessionAuthentication,
            "Cross-site request forgery protection",
            FindingSeverity::Medium,
            Confidence::Low,
            CheckOutcome::Potential,
            Some(unprotected[0].action_url.clone()),
            None,
            vec![format!(
                "{} state-changing form(s) had no token-like control",
                unprotected.len()
            )],
            Some("No form was submitted at the non-state-changing probe level; SameSite, Origin, or Referer enforcement may still prevent CSRF".to_owned()),
        );
    }
    let Some(baseline) = baseline else {
        return inconclusive(
            context,
            "session.csrf-form",
            VulnerabilityClass::SessionAuthentication,
            "Cross-site request forgery protection",
            Some(root.to_string()),
            "Root response was unavailable".to_owned(),
        );
    };
    let cookie = cross_site_cookie_header(baseline, root.scheme());
    let Some(cookie) = cookie else {
        return check(
            context,
            "session.csrf-form",
            VulnerabilityClass::SessionAuthentication,
            "Cross-site request forgery protection",
            FindingSeverity::Medium,
            Confidence::Low,
            CheckOutcome::Deferred,
            Some(unprotected[0].action_url.clone()),
            None,
            Vec::new(),
            Some("No cookie eligible for a cross-site form POST was observed in the anonymous session".to_owned()),
        );
    };
    let mut attempted = 0usize;
    let mut last_error = None;
    for form in unprotected
        .into_iter()
        .filter(|form| safe_form_probe(form))
        .take(2)
    {
        let Ok(action) = Url::parse(&form.action_url) else {
            continue;
        };
        let body = form_body(form, &probe_token(context));
        let headers = vec![
            (
                "Content-Type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            ),
            (
                "Origin".to_owned(),
                "https://nancy-exposure.invalid".to_owned(),
            ),
            (
                "Referer".to_owned(),
                "https://nancy-exposure.invalid/".to_owned(),
            ),
        ];
        match send_http(
            context,
            origin,
            &form.method,
            &action,
            &headers,
            body.as_bytes(),
            Some(&cookie),
            None,
            budget,
            progress,
        )
        .await
        {
            Ok(response) if cross_site_submission_accepted(&response) => {
                return check(
                    context,
                    "session.csrf-form",
                    VulnerabilityClass::SessionAuthentication,
                    "Cross-site request forgery protection",
                    FindingSeverity::Medium,
                    Confidence::Medium,
                    CheckOutcome::Potential,
                    Some(action.to_string()),
                    Some(format!(
                        "{} with a foreign Origin and Referer using a cross-site-eligible cookie",
                        form.method
                    )),
                    vec![format!(
                        "The tokenless cross-site submission returned HTTP {} without a recognizable CSRF rejection",
                        response.status
                    )],
                    Some("The application response did not prove that a durable state change occurred".to_owned()),
                );
            }
            Err(error) => last_error = Some(error),
            Ok(_) => attempted += 1,
        }
    }
    if attempted == 0 {
        return check(
            context,
            "session.csrf-form",
            VulnerabilityClass::SessionAuthentication,
            "Cross-site request forgery protection",
            FindingSeverity::Medium,
            Confidence::Low,
            CheckOutcome::Deferred,
            Some(root.to_string()),
            None,
            Vec::new(),
            Some("Discovered forms were excluded from automated submission because they involved credentials, files, or destructive-looking actions".to_owned()),
        );
    }
    observed_or_inconclusive(
        context,
        "session.csrf-form",
        VulnerabilityClass::SessionAuthentication,
        "Cross-site request forgery protection",
        FindingSeverity::Medium,
        attempted,
        last_error,
    )
}

fn check(
    context: ProbeContext<'_>,
    check_id: &str,
    class: VulnerabilityClass,
    title: &str,
    severity: FindingSeverity,
    confidence: Confidence,
    outcome: CheckOutcome,
    probe_url: Option<String>,
    request_evidence: Option<String>,
    evidence: Vec<String>,
    reason: Option<String>,
) -> SecurityCheckResult {
    SecurityCheckResult {
        ip: context.ip,
        port: context.port,
        check_id: check_id.to_owned(),
        class,
        title: title.to_owned(),
        severity,
        confidence,
        outcome,
        probe_url,
        request_evidence,
        evidence,
        reason,
    }
}

fn observed_or_inconclusive(
    context: ProbeContext<'_>,
    check_id: &str,
    class: VulnerabilityClass,
    title: &str,
    severity: FindingSeverity,
    attempted: usize,
    error: Option<String>,
) -> SecurityCheckResult {
    if attempted == 0 {
        return inconclusive(
            context,
            check_id,
            class,
            title,
            None,
            error.unwrap_or_else(|| "No probe could be completed".to_owned()),
        );
    }
    check(
        context,
        check_id,
        class,
        title,
        severity,
        Confidence::Medium,
        CheckOutcome::NotObserved,
        None,
        None,
        vec![format!("{attempted} bounded probe(s) completed")],
        error,
    )
}

fn inconclusive(
    context: ProbeContext<'_>,
    check_id: &str,
    class: VulnerabilityClass,
    title: &str,
    probe_url: Option<String>,
    reason: String,
) -> SecurityCheckResult {
    check(
        context,
        check_id,
        class,
        title,
        FindingSeverity::Informational,
        Confidence::Low,
        CheckOutcome::Inconclusive,
        probe_url,
        None,
        Vec::new(),
        Some(reason),
    )
}

fn skipped(
    context: ProbeContext<'_>,
    check_id: &str,
    class: VulnerabilityClass,
    title: &str,
    reason: &str,
) -> SecurityCheckResult {
    check(
        context,
        check_id,
        class,
        title,
        FindingSeverity::Informational,
        Confidence::Low,
        CheckOutcome::Skipped,
        None,
        None,
        Vec::new(),
        Some(reason.to_owned()),
    )
}

fn mutate_first_parameter(url: &Url, value: &str) -> (Url, String) {
    let pairs = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        let mut mutated = url.clone();
        mutated.query_pairs_mut().append_pair("nancy_probe", value);
        return (mutated, "nancy_probe".to_owned());
    }
    let name = pairs[0].0.clone();
    (mutate_parameter(url, 0, value), name)
}

fn mutate_parameter(url: &Url, index: usize, value: &str) -> Url {
    let mut pairs = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if let Some(pair) = pairs.get_mut(index) {
        pair.1 = value.to_owned();
    }
    let mut mutated = url.clone();
    mutated.query_pairs_mut().clear().extend_pairs(pairs);
    mutated
}

fn same_request_url(left: &Url, right: &Url) -> bool {
    left.path() == right.path() && left.query() == right.query() && same_origin(left, right)
}

fn probe_token(context: ProbeContext<'_>) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{now:x}{:x}{}", context.port, context.ip)
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(28)
        .collect()
}

fn display_target(url: &Url) -> String {
    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )
}

fn is_html(response: &HttpObservation) -> bool {
    header_values(response, "content-type").any(|value| value.to_ascii_lowercase().contains("html"))
        || String::from_utf8_lossy(&response.body)
            .to_ascii_lowercase()
            .contains("<html")
}

fn new_sql_error(baseline: &str, response: &str) -> Option<&'static str> {
    let baseline = baseline.to_ascii_lowercase();
    let response = response.to_ascii_lowercase();
    [
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql_fetch",
        "sqlstate[",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "syntax error at or near",
        "org.postgresql.util.psqlexception",
        "microsoft ole db provider for sql server",
        "system.data.sqlclient.sqlexception",
        "sqlite error",
        "sqliteexception",
        "ora-01756",
        "jdbc exception",
    ]
    .into_iter()
    .find(|marker| response.contains(marker) && !baseline.contains(marker))
}

fn response_references_host(response: &HttpObservation, host: &str) -> bool {
    let needle_http = format!("http://{host}");
    let needle_https = format!("https://{host}");
    response
        .redirect_location
        .as_deref()
        .is_some_and(|location| location.contains(&needle_http) || location.contains(&needle_https))
        || ((200..400).contains(&response.status) && {
            let body = String::from_utf8_lossy(&response.body);
            body.contains(&needle_http) || body.contains(&needle_https)
        })
}

fn redirects_to_host(response: &HttpObservation, host: &str) -> bool {
    let Some(location) = response.redirect_location.as_deref() else {
        return false;
    };
    Url::parse(&response.url)
        .ok()
        .and_then(|base| base.join(location).ok())
        .and_then(|url| url.host_str().map(str::to_owned))
        .is_some_and(|location_host| location_host.eq_ignore_ascii_case(host))
}

fn has_new_ssrf_error(baseline: &HttpObservation, response: &HttpObservation, token: &str) -> bool {
    let baseline = String::from_utf8_lossy(&baseline.body).to_ascii_lowercase();
    let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    let input_reference = body.contains("127.0.0.1") || body.contains(&token.to_ascii_lowercase());
    input_reference
        && [
            "connection refused",
            "failed to connect",
            "could not connect",
            "connection failure",
            "econnrefused",
            "urlopen error",
            "socket error",
        ]
        .into_iter()
        .any(|marker| body.contains(marker) && !baseline.contains(marker))
}

fn materially_different(left: &HttpObservation, right: &HttpObservation) -> bool {
    if left.status != right.status {
        return true;
    }
    let left = &left.body[..left.body.len().min(16_384)];
    let right = &right.body[..right.body.len().min(16_384)];
    left != right && left.len().abs_diff(right.len()) > left.len().max(right.len()) / 10
}

fn request_host(url: &Url) -> String {
    let hostname = url_host(url.host_str().unwrap_or_default());
    let port = url.port_or_known_default().unwrap_or_default();
    if (url.scheme() == "http" && port == 80) || (url.scheme() == "https" && port == 443) {
        hostname
    } else {
        format!("{hostname}:{port}")
    }
}

fn http_status(bytes: &[u8]) -> Option<u16> {
    let line_end = bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(bytes.len());
    let line = std::str::from_utf8(&bytes[..line_end]).ok()?;
    let mut parts = line.split_whitespace();
    parts.next()?.starts_with("HTTP/").then_some(())?;
    parts.next()?.parse().ok()
}

fn raw_response_closes(bytes: &[u8]) -> bool {
    let end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
        .lines()
        .filter_map(|line| line.split_once(':'))
        .any(|(name, value)| {
            name.eq_ignore_ascii_case("connection")
                && value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("close"))
        })
}

fn set_cookie_values(response: &HttpObservation) -> Vec<(String, String, String)> {
    header_values(response, "set-cookie")
        .filter_map(|raw| {
            let pair = raw.split(';').next()?;
            let (name, value) = pair.split_once('=')?;
            Some((
                name.trim().to_owned(),
                value.trim().to_owned(),
                raw.to_owned(),
            ))
        })
        .collect()
}

fn likely_session_cookie(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ["session", "sess", "sid", "auth", "token", "jwt"]
        .iter()
        .any(|marker| name.contains(marker))
}

fn cross_site_cookie_header(response: &HttpObservation, scheme: &str) -> Option<String> {
    let cookies = set_cookie_values(response)
        .into_iter()
        .filter(|(_, _, raw)| {
            let lower = raw.to_ascii_lowercase();
            lower.contains("samesite=none")
                && lower.contains("secure")
                && scheme.eq_ignore_ascii_case("https")
        })
        .map(|(name, value, _)| format!("{name}={value}"))
        .collect::<Vec<_>>();
    (!cookies.is_empty()).then(|| cookies.join("; "))
}

fn safe_form_probe(form: &CrawlFormAction) -> bool {
    if !form.method.eq_ignore_ascii_case("POST")
        || form.has_password
        || !form
            .encoding
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        || form.controls.iter().any(|control| {
            control.control_type.eq_ignore_ascii_case("file") || destructive_term(&control.name)
        })
    {
        return false;
    }
    Url::parse(&form.action_url)
        .ok()
        .is_some_and(|url| !destructive_term(url.path()))
}

fn destructive_term(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "delete", "remove", "destroy", "logout", "password", "reset", "checkout", "payment",
        "purchase", "order", "transfer", "withdraw", "upload", "admin", "amount", "card",
    ]
    .iter()
    .any(|term| value.contains(term))
}

fn form_body(form: &CrawlFormAction, token: &str) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for control in form
        .controls
        .iter()
        .filter(|control| !control.name.is_empty() && !control.submit_control)
    {
        let value = control.default_value.as_deref().unwrap_or_else(|| {
            if control.name.to_ascii_lowercase().contains("email") {
                "nancy-probe@example.invalid"
            } else {
                token
            }
        });
        serializer.append_pair(&control.name, value);
    }
    serializer.finish()
}

fn cross_site_submission_accepted(response: &HttpObservation) -> bool {
    if !(200..400).contains(&response.status) {
        return false;
    }
    let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    ![
        "csrf token",
        "xsrf token",
        "invalid origin",
        "origin is not allowed",
        "referer is not allowed",
        "cross-site request forgery",
    ]
    .iter()
    .any(|marker| body.contains(marker))
}
