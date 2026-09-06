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

pub(super) async fn run(
    endpoints: &mut [EndpointScan],
    resources: &[CrawledResource],
    forms: &[CrawlFormAction],
    scan: ScanContext<'_>,
    progress: &Option<Sender<ExposureScanProgress>>,
) {
    let mut budget = {
        let (request,): (&ExposureScanRequest,) = (scan.request,);
        {
            RequestBudget {
                per_origin_limit: request.active_requests_per_origin,
                total_limit: request.active_requests_total,
                used: 0,
                per_origin: HashMap::new(),
            }
        }
    };
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
        if endpoint_health::stopped(endpoint.ip, endpoint.port) {
            continue;
        }
        let Some(root) = ({
            let (endpoint, hostname): (&EndpointScan, &str) = (endpoint, scan.hostname);
            'inlined_endpoint_root: {
                let mut selected = match endpoint
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
                    .max_by_key(|url| url.scheme() == "https")
                {
                    Some(value) => value,
                    None => break 'inlined_endpoint_root None,
                };
                selected.set_path("/");
                selected.set_query(None);
                selected.set_fragment(None);
                Some(selected)
            }
        }) else {
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
        let candidates: Vec<Url> = {
            let (endpoint, resources, root): (&EndpointScan, &[CrawledResource], &Url) =
                (endpoint, resources, &root);

            let mut values = BTreeSet::new();
            for value in endpoint
                .http
                .iter()
                .map(|response| response.url.as_str())
                .chain(
                    resources
                        .iter()
                        .filter(|resource| {
                            resource.ip == endpoint.ip && resource.port == endpoint.port
                        })
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
        };
        let protected: Vec<(Url, u16)> = {
            let (endpoint, resources, root): (&EndpointScan, &[CrawledResource], &Url) =
                (endpoint, resources, &root);

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
        };
        let endpoint_forms: Vec<&CrawlFormAction> = {
            let (forms, endpoint, root): (&'_ [CrawlFormAction], &EndpointScan, &Url) =
                (forms, endpoint, &root);

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
        };
        let root_response: Result<HttpObservation, String> = ({
            let (
                context,
                origin,
                method,
                url,
                headers,
                body,
                cookie_header,
                host_override,
                budget,
                progress,
            ): (
                ProbeContext<'_>,
                &OriginKey,
                &str,
                &Url,
                &[(String, String)],
                &[u8],
                Option<&str>,
                Option<&str>,
                &mut RequestBudget,
                &Option<Sender<ExposureScanProgress>>,
            ) = (
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
            );
            async move {
                ({
                    let (inlined_self, origin): (&mut RequestBudget, &OriginKey) =
                        (&mut *budget, origin);
                    let inlined_result: Result<(), String> = {
                        'inlined_consume: {
                            if endpoint_health::stopped(origin.ip, origin.port) {
                                break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
                            }
                            if inlined_self.used >= inlined_self.total_limit {
                                break 'inlined_consume Err(
                                    "Total active-request budget exhausted".to_owned(),
                                );
                            }
                            let origin_used =
                                inlined_self.per_origin.entry(origin.clone()).or_default();
                            if *origin_used >= inlined_self.per_origin_limit {
                                break 'inlined_consume Err(
                                    "Per-origin active-request budget exhausted".to_owned(),
                                );
                            }
                            inlined_self.used += 1;
                            *origin_used += 1;
                            Ok(())
                        }
                    };
                    inlined_result
                })?;
                send_phase_progress(
                    progress,
                    ExposureScanPhase::ActiveWebAssessment,
                    ExposureScanPhaseState::Running,
                    budget.used as f32 / budget.total_limit.max(1) as f32,
                    format!("{method} {}", {
                        let (url,): (&Url,) = (url,);

                        format!(
                            "{}://{}:{}{}",
                            url.scheme(),
                            url.host_str().unwrap_or_default(),
                            url.port_or_known_default().unwrap_or_default(),
                            url.path()
                        )
                    }),
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
        })
        .await;
        let mut checks = Vec::new();
        checks.push(
            ({
let (context, origin, root, baseline, budget, progress,): (ProbeContext < '_ >, & OriginKey, & Url, Option < & HttpObservation >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, &origin, &root, root_response.as_ref().ok(), &mut budget, progress,);
async move {

    let token = {

let inlined_result: String = {

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{now:x}{:x}{}", context.port, context.ip)
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(28)
        .collect()

};
inlined_result
};
    let host = format!("nancy-{token}.invalid");
    let forwarded_headers = [("X-Forwarded-Host".to_owned(), host.clone())];
    let direct = ({
let (context, origin, method, url, headers, body, cookie_header, host_override, budget, progress,): (ProbeContext < '_ >, & OriginKey, & str, & Url, & [(String , String)], & [u8], Option < & str >, Option < & str >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, origin, "GET", root, &[], &[], None, Some(&host), budget, progress,);
async move {

    ({
let (inlined_self, origin,): (& mut RequestBudget, & OriginKey,) = (&mut *budget, origin,);
let inlined_result: Result < () , String > = {
'inlined_consume: {

        if endpoint_health::stopped(origin.ip, origin.port) {
            break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
        }
        if inlined_self.used >= inlined_self.total_limit {
            break 'inlined_consume Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = inlined_self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= inlined_self.per_origin_limit {
            break 'inlined_consume Err("Per-origin active-request budget exhausted".to_owned());
        }
        inlined_self.used += 1;
        *origin_used += 1;
        Ok(())

}
};
inlined_result
})?;
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("{method} {}", {
let (url,): (& Url,) = (url,);

    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )

}),
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
})
    .await;
    let forwarded = ({
let (context, origin, method, url, headers, body, cookie_header, host_override, budget, progress,): (ProbeContext < '_ >, & OriginKey, & str, & Url, & [(String , String)], & [u8], Option < & str >, Option < & str >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, origin, "GET", root, &forwarded_headers, &[], None, None, budget, progress,);
async move {

    ({
let (inlined_self, origin,): (& mut RequestBudget, & OriginKey,) = (&mut *budget, origin,);
let inlined_result: Result < () , String > = {
'inlined_consume: {

        if endpoint_health::stopped(origin.ip, origin.port) {
            break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
        }
        if inlined_self.used >= inlined_self.total_limit {
            break 'inlined_consume Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = inlined_self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= inlined_self.per_origin_limit {
            break 'inlined_consume Err("Per-origin active-request budget exhausted".to_owned());
        }
        inlined_self.used += 1;
        *origin_used += 1;
        Ok(())

}
};
inlined_result
})?;
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("{method} {}", {
let (url,): (& Url,) = (url,);

    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )

}),
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
})
    .await;
    let finding = [
        ("Host", direct.as_ref().ok()),
        ("X-Forwarded-Host", forwarded.as_ref().ok()),
    ]
    .into_iter()
    .find(|(_, response)| {
        response.is_some_and(|response| {
let (response, host,): (& HttpObservation, & str,) = (response, &host,);

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

})
    });
    if let Some((header, response)) = finding {
        let response = response.unwrap();
        return {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "http.host-header", VulnerabilityClass::HttpInfrastructure, "Host header injection", FindingSeverity::Medium, Confidence::High, CheckOutcome::Vulnerable, Some(root.to_string()), Some(format!("GET / with {header}: {host}")), vec![format!(
                "HTTP {} response incorporated the supplied host into an absolute URL or redirect",
                response.status
            )], None,);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

};
    }
    let errors = [direct.err(), forwarded.err()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if baseline.is_none() && errors.len() == 2 {
        return {
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, "http.host-header", VulnerabilityClass::HttpInfrastructure, "Host header injection", Some(root.to_string()), errors.join("; "),);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

};
    }
    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "http.host-header", VulnerabilityClass::HttpInfrastructure, "Host header injection", FindingSeverity::Medium, Confidence::Medium, CheckOutcome::NotObserved, Some(root.to_string()), Some("GET / with alternate Host and X-Forwarded-Host values".to_owned()), Vec::new(), errors.first().cloned(),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

}
})
            .await,
        );
        checks.extend(
            ({
let (context, origin, candidates, root, root_response, budget, progress,): (ProbeContext < '_ >, & OriginKey, & [Url], & Url, Option < & HttpObservation >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, &origin, &candidates, &root, root_response.as_ref().ok(), &mut budget, progress,);
async move {

    let mut xss = None;
    let mut sql = None;
    let mut checked = 0usize;
    let mut errors = Vec::new();
    for (index, candidate) in candidates.iter().take(6).enumerate() {
        if context.scan.cancel.is_cancelled() {
            break;
        }
        let baseline = if {
let (left, right,): (& Url, & Url,) = (candidate, root,);

    left.path() == right.path() && left.query() == right.query() && same_origin(left, right)

} {
            root_response
                .cloned()
                .ok_or_else(|| "Root baseline unavailable".to_owned())
        } else {
            ({
let (context, origin, method, url, headers, body, cookie_header, host_override, budget, progress,): (ProbeContext < '_ >, & OriginKey, & str, & Url, & [(String , String)], & [u8], Option < & str >, Option < & str >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, origin, "GET", candidate, &[], &[], None, None, budget, progress,);
async move {

    ({
let (inlined_self, origin,): (& mut RequestBudget, & OriginKey,) = (&mut *budget, origin,);
let inlined_result: Result < () , String > = {
'inlined_consume: {

        if endpoint_health::stopped(origin.ip, origin.port) {
            break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
        }
        if inlined_self.used >= inlined_self.total_limit {
            break 'inlined_consume Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = inlined_self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= inlined_self.per_origin_limit {
            break 'inlined_consume Err("Per-origin active-request budget exhausted".to_owned());
        }
        inlined_self.used += 1;
        *origin_used += 1;
        Ok(())

}
};
inlined_result
})?;
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("{method} {}", {
let (url,): (& Url,) = (url,);

    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )

}),
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
})
            .await
        };
        let Ok(baseline) = baseline else {
            errors.push(baseline.err().unwrap_or_default());
            continue;
        };
        let token = format!("{}-{index}", ({
let (context,): (ProbeContext < '_ >,) = (context,);
let inlined_result: String = {

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{now:x}{:x}{}", context.port, context.ip)
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(28)
        .collect()

};
inlined_result
}));
        let element = format!("<nancy-probe data-nancy=\"{token}\">");
        let payload = format!("nancy-{token}'\">{element}");
        let (mutated, parameter) = {
let (url, value,): (& Url, & str,) = (candidate, &payload,);
'inlined_mutate_first_parameter: {

    let pairs = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        let mut mutated = url.clone();
        mutated.query_pairs_mut().append_pair("nancy_probe", value);
        break 'inlined_mutate_first_parameter (mutated, "nancy_probe".to_owned());
    }
    let name = pairs[0].0.clone();
    (({
let (url, index, value,): (& Url, usize, & str,) = (url, 0, value,);
let inlined_result: Url = {

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

};
inlined_result
}), name)

}
};
        let response = ({
let (context, origin, method, url, headers, body, cookie_header, host_override, budget, progress,): (ProbeContext < '_ >, & OriginKey, & str, & Url, & [(String , String)], & [u8], Option < & str >, Option < & str >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, origin, "GET", &mutated, &[], &[], None, None, budget, progress,);
async move {

    ({
let (inlined_self, origin,): (& mut RequestBudget, & OriginKey,) = (&mut *budget, origin,);
let inlined_result: Result < () , String > = {
'inlined_consume: {

        if endpoint_health::stopped(origin.ip, origin.port) {
            break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
        }
        if inlined_self.used >= inlined_self.total_limit {
            break 'inlined_consume Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = inlined_self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= inlined_self.per_origin_limit {
            break 'inlined_consume Err("Per-origin active-request budget exhausted".to_owned());
        }
        inlined_self.used += 1;
        *origin_used += 1;
        Ok(())

}
};
inlined_result
})?;
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("{method} {}", {
let (url,): (& Url,) = (url,);

    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )

}),
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
})
        .await;
        let Ok(response) = response else {
            errors.push(response.err().unwrap_or_default());
            continue;
        };
        checked += 1;
        let baseline_text = String::from_utf8_lossy(&baseline.body);
        let response_text = String::from_utf8_lossy(&response.body);
        if xss.is_none()
            && {
let (response,): (& HttpObservation,) = (&response,);

    ({ let (response, name): (&crate::HttpObservation, &str) = (response, "content-type"); response.headers.iter().filter(move |(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()) }).any(|value| value.to_ascii_lowercase().contains("html"))
        || String::from_utf8_lossy(&response.body)
            .to_ascii_lowercase()
            .contains("<html")

}
            && response_text.contains(&element)
            && !baseline_text.contains(&element)
        {
            xss = Some((mutated.clone(), parameter.clone(), response.status));
        }
        if sql.is_none()
            && let Some(marker) = {
let (baseline, response,): (& str, & str,) = (&baseline_text, &response_text,);

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
        {
            sql = Some((mutated, parameter, response.status, marker.to_owned()));
        }
        if xss.is_some() && sql.is_some() {
            break;
        }
    }
    let xss_check = if let Some((url, parameter, status)) = xss {
        {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "client.reflected-markup", VulnerabilityClass::ClientSide, "Unencoded reflected markup", FindingSeverity::Medium, Confidence::Medium, CheckOutcome::Potential, Some(url.to_string()), Some(format!("GET with a benign markup probe in '{parameter}'")), vec![format!(
                "HTTP {status} reflected the exact custom-element probe without HTML encoding"
            )], Some("Browser execution context was not established, so this is not a confirmed XSS finding".to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}
    } else {
        {
let (context, check_id, class, title, severity, attempted, error,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, usize, Option < String >,) = (context, "client.reflected-markup", VulnerabilityClass::ClientSide, "Unencoded reflected markup", FindingSeverity::Medium, checked, errors.first().cloned(),);
let inlined_result: SecurityCheckResult = {
'inlined_observed_or_inconclusive: {

    if attempted == 0 {
        break 'inlined_observed_or_inconclusive ({
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, check_id, class, title, None, error.unwrap_or_else(|| "No probe could be completed".to_owned()),);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

});
    }
    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, severity, Confidence::Medium, CheckOutcome::NotObserved, None, None, vec![format!("{attempted} bounded probe(s) completed")], error,);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

}
};
inlined_result
}
    };
    let sql_check = if let Some((url, parameter, status, marker)) = sql {
        {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "injection.sql-error", VulnerabilityClass::Injection, "SQL error disclosure after input mutation", FindingSeverity::High, Confidence::Medium, CheckOutcome::Potential, Some(url.to_string()), Some(format!("GET with a quote-bearing marker in '{parameter}'")), vec![format!(
                "HTTP {status} introduced the database error signature '{marker}'"
            )], Some("An error differential indicates unsafe input handling but does not prove query control".to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}
    } else {
        {
let (context, check_id, class, title, severity, attempted, error,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, usize, Option < String >,) = (context, "injection.sql-error", VulnerabilityClass::Injection, "SQL error disclosure after input mutation", FindingSeverity::High, checked, errors.first().cloned(),);
let inlined_result: SecurityCheckResult = {
'inlined_observed_or_inconclusive: {

    if attempted == 0 {
        break 'inlined_observed_or_inconclusive ({
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, check_id, class, title, None, error.unwrap_or_else(|| "No probe could be completed".to_owned()),);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

});
    }
    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, severity, Confidence::Medium, CheckOutcome::NotObserved, None, None, vec![format!("{attempted} bounded probe(s) completed")], error,);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

}
};
inlined_result
}
    };
    vec![xss_check, sql_check]

}
})
            .await,
        );
        checks
            .push(({
let (context, origin, candidates, budget, progress,): (ProbeContext < '_ >, & OriginKey, & [Url], & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, &origin, &candidates, &mut budget, progress,);
async move {

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
            let token = {

let inlined_result: String = {

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{now:x}{:x}{}", context.port, context.ip)
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(28)
        .collect()

};
inlined_result
};
            let external = format!("https://nancy-{token}.invalid/redirect-check");
            let mutated = {
let (url, index, value,): (& Url, usize, & str,) = (candidate, index, &external,);
let inlined_result: Url = {

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

};
inlined_result
};
            let response = ({
let (context, origin, method, url, headers, body, cookie_header, host_override, budget, progress,): (ProbeContext < '_ >, & OriginKey, & str, & Url, & [(String , String)], & [u8], Option < & str >, Option < & str >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, origin, "GET", &mutated, &[], &[], None, None, budget, progress,);
async move {

    ({
let (inlined_self, origin,): (& mut RequestBudget, & OriginKey,) = (&mut *budget, origin,);
let inlined_result: Result < () , String > = {
'inlined_consume: {

        if endpoint_health::stopped(origin.ip, origin.port) {
            break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
        }
        if inlined_self.used >= inlined_self.total_limit {
            break 'inlined_consume Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = inlined_self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= inlined_self.per_origin_limit {
            break 'inlined_consume Err("Per-origin active-request budget exhausted".to_owned());
        }
        inlined_self.used += 1;
        *origin_used += 1;
        Ok(())

}
};
inlined_result
})?;
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("{method} {}", {
let (url,): (& Url,) = (url,);

    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )

}),
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
})
            .await;
            match response {
                Ok(response) if {
let (response, host,): (& HttpObservation, & str,) = (&response, &format!("nancy-{token}.invalid"),);
'inlined_redirects_to_host: {

    let Some(location) = response.redirect_location.as_deref() else {
        break 'inlined_redirects_to_host false;
    };
    Url::parse(&response.url)
        .ok()
        .and_then(|base| base.join(location).ok())
        .and_then(|url| url.host_str().map(str::to_owned))
        .is_some_and(|location_host| location_host.eq_ignore_ascii_case(host))

}
} => {
                    return {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "client.open-redirect", VulnerabilityClass::ClientSide, "Open redirect", FindingSeverity::Medium, Confidence::High, CheckOutcome::Vulnerable, Some(mutated.to_string()), Some(format!("GET with an external URL in '{name}'")), vec![format!(
                            "HTTP {} redirected to the supplied external .invalid host",
                            response.status
                        )], None,);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

};
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
        return {
let (context, check_id, class, title, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, & str,) = (context, "client.open-redirect", VulnerabilityClass::ClientSide, "Open redirect", "No redirect-like query parameter was discovered",);
let inlined_result: SecurityCheckResult = {

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Skipped, None, None, Vec::new(), Some(reason.to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

};
inlined_result
};
    }
    {
let (context, check_id, class, title, severity, attempted, error,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, usize, Option < String >,) = (context, "client.open-redirect", VulnerabilityClass::ClientSide, "Open redirect", FindingSeverity::Medium, attempted, last_error,);
let inlined_result: SecurityCheckResult = {
'inlined_observed_or_inconclusive: {

    if attempted == 0 {
        break 'inlined_observed_or_inconclusive ({
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, check_id, class, title, None, error.unwrap_or_else(|| "No probe could be completed".to_owned()),);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

});
    }
    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, severity, Confidence::Medium, CheckOutcome::NotObserved, None, None, vec![format!("{attempted} bounded probe(s) completed")], error,);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

}
};
inlined_result
}

}
}).await);
        checks.push(({
let (context, origin, candidates, budget, progress,): (ProbeContext < '_ >, & OriginKey, & [Url], & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, &origin, &candidates, &mut budget, progress,);
async move {

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
            let baseline = ({
let (context, origin, method, url, headers, body, cookie_header, host_override, budget, progress,): (ProbeContext < '_ >, & OriginKey, & str, & Url, & [(String , String)], & [u8], Option < & str >, Option < & str >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, origin, "GET", candidate, &[], &[], None, None, budget, progress,);
async move {

    ({
let (inlined_self, origin,): (& mut RequestBudget, & OriginKey,) = (&mut *budget, origin,);
let inlined_result: Result < () , String > = {
'inlined_consume: {

        if endpoint_health::stopped(origin.ip, origin.port) {
            break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
        }
        if inlined_self.used >= inlined_self.total_limit {
            break 'inlined_consume Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = inlined_self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= inlined_self.per_origin_limit {
            break 'inlined_consume Err("Per-origin active-request budget exhausted".to_owned());
        }
        inlined_self.used += 1;
        *origin_used += 1;
        Ok(())

}
};
inlined_result
})?;
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("{method} {}", {
let (url,): (& Url,) = (url,);

    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )

}),
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
})
            .await;
            let token = {

let inlined_result: String = {

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{now:x}{:x}{}", context.port, context.ip)
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(28)
        .collect()

};
inlined_result
};
            let payload = format!("http://127.0.0.1:1/nancy-{token}");
            let mutated = {
let (url, index, value,): (& Url, usize, & str,) = (candidate, index, &payload,);
let inlined_result: Url = {

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

};
inlined_result
};
            let response = ({
let (context, origin, method, url, headers, body, cookie_header, host_override, budget, progress,): (ProbeContext < '_ >, & OriginKey, & str, & Url, & [(String , String)], & [u8], Option < & str >, Option < & str >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, origin, "GET", &mutated, &[], &[], None, None, budget, progress,);
async move {

    ({
let (inlined_self, origin,): (& mut RequestBudget, & OriginKey,) = (&mut *budget, origin,);
let inlined_result: Result < () , String > = {
'inlined_consume: {

        if endpoint_health::stopped(origin.ip, origin.port) {
            break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
        }
        if inlined_self.used >= inlined_self.total_limit {
            break 'inlined_consume Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = inlined_self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= inlined_self.per_origin_limit {
            break 'inlined_consume Err("Per-origin active-request budget exhausted".to_owned());
        }
        inlined_self.used += 1;
        *origin_used += 1;
        Ok(())

}
};
inlined_result
})?;
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("{method} {}", {
let (url,): (& Url,) = (url,);

    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )

}),
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
})
            .await;
            match (baseline, response) {
                (Ok(baseline), Ok(response))
                    if {
let (baseline, response, token,): (& HttpObservation, & HttpObservation, & str,) = (&baseline, &response, &token,);

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

} =>
                {
                    return {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "server-side.ssrf-loopback", VulnerabilityClass::ServerSideRequestHandling, "Possible server-side URL fetch", FindingSeverity::High, Confidence::Medium, CheckOutcome::Potential, Some(mutated.to_string()), Some(format!("GET with a loopback URL in '{name}'")), vec![format!(
                            "HTTP {} introduced a loopback connection-error signature",
                            response.status
                        )], Some("The bounded loopback probe did not access a listening internal service; confirm with an authorized callback endpoint".to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

};
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
        return {
let (context, check_id, class, title, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, & str,) = (context, "server-side.ssrf-loopback", VulnerabilityClass::ServerSideRequestHandling, "Possible server-side URL fetch", "No server-side URL input candidate was discovered",);
let inlined_result: SecurityCheckResult = {

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Skipped, None, None, Vec::new(), Some(reason.to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

};
inlined_result
};
    }
    {
let (context, check_id, class, title, severity, attempted, error,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, usize, Option < String >,) = (context, "server-side.ssrf-loopback", VulnerabilityClass::ServerSideRequestHandling, "Possible server-side URL fetch", FindingSeverity::High, attempted, last_error,);
let inlined_result: SecurityCheckResult = {
'inlined_observed_or_inconclusive: {

    if attempted == 0 {
        break 'inlined_observed_or_inconclusive ({
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, check_id, class, title, None, error.unwrap_or_else(|| "No probe could be completed".to_owned()),);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

});
    }
    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, severity, Confidence::Medium, CheckOutcome::NotObserved, None, None, vec![format!("{attempted} bounded probe(s) completed")], error,);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

}
};
inlined_result
}

}
}).await);
        checks.push(
            ({
let (context, origin, root, root_response, candidates, budget, progress,): (ProbeContext < '_ >, & OriginKey, & Url, Option < & HttpObservation >, & [(Url , u16)], & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, &origin, &root, root_response.as_ref().ok(), &protected, &mut budget, progress,);
async move {

    let Some((protected, status)) = candidates.first() else {
        return {
let (context, check_id, class, title, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, & str,) = (context, "access-control.route-bypass", VulnerabilityClass::AccessControl, "Protected-route method or rewrite bypass", "No HTTP 401 or 403 resource was discovered",);
let inlined_result: SecurityCheckResult = {

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Skipped, None, None, Vec::new(), Some(reason.to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

};
inlined_result
};
    };
    let mut attempted = 0usize;
    let mut last_error = None;
    let head = ({
let (context, origin, method, url, headers, body, cookie_header, host_override, budget, progress,): (ProbeContext < '_ >, & OriginKey, & str, & Url, & [(String , String)], & [u8], Option < & str >, Option < & str >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, origin, "HEAD", protected, &[], &[], None, None, budget, progress,);
async move {

    ({
let (inlined_self, origin,): (& mut RequestBudget, & OriginKey,) = (&mut *budget, origin,);
let inlined_result: Result < () , String > = {
'inlined_consume: {

        if endpoint_health::stopped(origin.ip, origin.port) {
            break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
        }
        if inlined_self.used >= inlined_self.total_limit {
            break 'inlined_consume Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = inlined_self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= inlined_self.per_origin_limit {
            break 'inlined_consume Err("Per-origin active-request budget exhausted".to_owned());
        }
        inlined_self.used += 1;
        *origin_used += 1;
        Ok(())

}
};
inlined_result
})?;
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("{method} {}", {
let (url,): (& Url,) = (url,);

    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )

}),
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
})
    .await;
    match head {
        Ok(response) if (200..300).contains(&response.status) => {
            return {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "access-control.route-bypass", VulnerabilityClass::AccessControl, "Protected-route method or rewrite bypass", FindingSeverity::High, Confidence::Medium, CheckOutcome::Potential, Some(protected.to_string()), Some(format!("HEAD {}", url_path(protected))), vec![format!(
                    "GET was recorded as HTTP {status}, while HEAD returned HTTP {}",
                    response.status
                )], Some(
                    "Confirm that the HEAD response traversed the same authorization path as GET"
                        .to_owned(),
                ),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

};
        }
        Err(error) => last_error = Some(error),
        Ok(_) => attempted += 1,
    }
    for header in ["X-Original-URL", "X-Rewrite-URL"] {
        let headers = [(header.to_owned(), url_path(protected))];
        let response = ({
let (context, origin, method, url, headers, body, cookie_header, host_override, budget, progress,): (ProbeContext < '_ >, & OriginKey, & str, & Url, & [(String , String)], & [u8], Option < & str >, Option < & str >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, origin, "GET", root, &headers, &[], None, None, budget, progress,);
async move {

    ({
let (inlined_self, origin,): (& mut RequestBudget, & OriginKey,) = (&mut *budget, origin,);
let inlined_result: Result < () , String > = {
'inlined_consume: {

        if endpoint_health::stopped(origin.ip, origin.port) {
            break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
        }
        if inlined_self.used >= inlined_self.total_limit {
            break 'inlined_consume Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = inlined_self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= inlined_self.per_origin_limit {
            break 'inlined_consume Err("Per-origin active-request budget exhausted".to_owned());
        }
        inlined_self.used += 1;
        *origin_used += 1;
        Ok(())

}
};
inlined_result
})?;
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("{method} {}", {
let (url,): (& Url,) = (url,);

    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )

}),
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
})
        .await;
        match response {
            Ok(response)
                if (200..300).contains(&response.status)
                    && root_response
                        .is_none_or(|baseline| {
let (left, right,): (& HttpObservation, & HttpObservation,) = (baseline, &response,);
'inlined_materially_different: {

    if left.status != right.status {
        break 'inlined_materially_different true;
    }
    let left = &left.body[..left.body.len().min(16_384)];
    let right = &right.body[..right.body.len().min(16_384)];
    left != right && left.len().abs_diff(right.len()) > left.len().max(right.len()) / 10

}
}) =>
            {
                return {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "access-control.route-bypass", VulnerabilityClass::AccessControl, "Protected-route method or rewrite bypass", FindingSeverity::High, Confidence::Medium, CheckOutcome::Potential, Some(protected.to_string()), Some(format!("GET / with {header}: {}", url_path(protected))), vec![format!(
                        "Direct access returned HTTP {status}; the rewrite-header probe returned HTTP {} with content distinct from the root baseline",
                        response.status
                    )], Some("Verify the returned representation before treating this as an authorization bypass".to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

};
            }
            Err(error) => last_error = Some(error),
            Ok(_) => attempted += 1,
        }
    }
    {
let (context, check_id, class, title, severity, attempted, error,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, usize, Option < String >,) = (context, "access-control.route-bypass", VulnerabilityClass::AccessControl, "Protected-route method or rewrite bypass", FindingSeverity::High, attempted, last_error,);
let inlined_result: SecurityCheckResult = {
'inlined_observed_or_inconclusive: {

    if attempted == 0 {
        break 'inlined_observed_or_inconclusive ({
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, check_id, class, title, None, error.unwrap_or_else(|| "No probe could be completed".to_owned()),);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

});
    }
    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, severity, Confidence::Medium, CheckOutcome::NotObserved, None, None, vec![format!("{attempted} bounded probe(s) completed")], error,);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

}
};
inlined_result
}

}
})
            .await,
        );
        checks.push(({
let (context, origin, root, budget, progress,): (ProbeContext < '_ >, & OriginKey, & Url, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, &origin, &root, &mut budget, progress,);
async move {

    if let Err(error) = {
let (inlined_self, origin,): (& mut RequestBudget, & OriginKey,) = (&mut *budget, origin,);
let inlined_result: Result < () , String > = {
'inlined_consume: {

        if endpoint_health::stopped(origin.ip, origin.port) {
            break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
        }
        if inlined_self.used >= inlined_self.total_limit {
            break 'inlined_consume Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = inlined_self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= inlined_self.per_origin_limit {
            break 'inlined_consume Err("Per-origin active-request budget exhausted".to_owned());
        }
        inlined_self.used += 1;
        *origin_used += 1;
        Ok(())

}
};
inlined_result
} {
        return {
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, "http.ambiguous-framing", VulnerabilityClass::HttpInfrastructure, "Ambiguous HTTP/1.1 framing handling", Some(root.to_string()), error,);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

};
    }
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("OPTIONS {} framing check", {
let (url,): (& Url,) = (root,);

    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )

}),
    );
    let host = {
let (url,): (& Url,) = (root,);

    let hostname = { let hostname: &str = url.host_str().unwrap_or_default(); if hostname.parse::<std::net::Ipv6Addr>().is_ok() { format!("[{hostname}]") } else { hostname.to_owned() } };
    let port = url.port_or_known_default().unwrap_or_default();
    if (url.scheme() == "http" && port == 80) || (url.scheme() == "https" && port == 443) {
        hostname
    } else {
        format!("{hostname}:{port}")
    }

};
    let raw = format!(
        "OPTIONS / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nancywebdebug-active/{}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    match active_raw_http_exchange(context, &origin.scheme, raw.as_bytes()).await {
        Ok((bytes, duration_ms, false))
            if {
let (bytes,): (& [u8],) = (&bytes,);
'inlined_http_status: {

    let line_end = bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(bytes.len());
    let line = match std::str::from_utf8(&bytes[..line_end]).ok() { Some(value) => value, None => break 'inlined_http_status None };
    let mut parts = line.split_whitespace();
    match match parts.next() { Some(value) => value, None => break 'inlined_http_status None }.starts_with("HTTP/").then_some(()) { Some(value) => value, None => break 'inlined_http_status None };
    match parts.next() { Some(value) => value, None => break 'inlined_http_status None }.parse::<u16>().ok()

}

}.is_some() && !{
let (bytes,): (& [u8],) = (&bytes,);

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

} =>
        {
            {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "http.ambiguous-framing", VulnerabilityClass::HttpInfrastructure, "Ambiguous HTTP/1.1 framing handling", FindingSeverity::Medium, Confidence::Medium, CheckOutcome::Potential, Some(root.to_string()), Some("OPTIONS / with aligned Content-Length and Transfer-Encoding framing".to_owned()), vec![format!(
                "The server responded in {duration_ms:.1} ms but did not close the connection after receiving both framing headers"
            )], Some("No second request was sent; confirm parser behavior across every intermediary before concluding request smuggling is possible".to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}
        }
        Ok((bytes, _, peer_closed))
            if {
let (bytes,): (& [u8],) = (&bytes,);
'inlined_http_status: {

    let line_end = bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(bytes.len());
    let line = match std::str::from_utf8(&bytes[..line_end]).ok() { Some(value) => value, None => break 'inlined_http_status None };
    let mut parts = line.split_whitespace();
    match match parts.next() { Some(value) => value, None => break 'inlined_http_status None }.starts_with("HTTP/").then_some(()) { Some(value) => value, None => break 'inlined_http_status None };
    match parts.next() { Some(value) => value, None => break 'inlined_http_status None }.parse::<u16>().ok()

}

}.is_some() && (peer_closed || {
let (bytes,): (& [u8],) = (&bytes,);

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

}) =>
        {
            {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "http.ambiguous-framing", VulnerabilityClass::HttpInfrastructure, "Ambiguous HTTP/1.1 framing handling", FindingSeverity::Medium, Confidence::High, CheckOutcome::NotObserved, Some(root.to_string()), Some("OPTIONS / with aligned Content-Length and Transfer-Encoding framing".to_owned()), vec![
                "The peer closed the connection or declared Connection: close after the ambiguous request"
                    .to_owned(),
            ], None,);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}
        }
        Ok((bytes, _, _)) => {
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, "http.ambiguous-framing", VulnerabilityClass::HttpInfrastructure, "Ambiguous HTTP/1.1 framing handling", Some(root.to_string()), format!(
                "The peer returned {} bytes without a complete HTTP status line",
                bytes.len()
            ),);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

},
        Err(error) => {
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, "http.ambiguous-framing", VulnerabilityClass::HttpInfrastructure, "Ambiguous HTTP/1.1 framing handling", Some(root.to_string()), error,);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

},
    }

}
}).await);
        checks.push(
            ({
let (context, origin, root, baseline, budget, progress,): (ProbeContext < '_ >, & OriginKey, & Url, Option < & HttpObservation >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, &origin, &root, root_response.as_ref().ok(), &mut budget, progress,);
async move {

    let Some(baseline) = baseline else {
        return {
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, "session.fixation", VulnerabilityClass::SessionAuthentication, "Session fixation", Some(root.to_string()), "Root response was unavailable".to_owned(),);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

};
    };
    let names = ({
let (response,): (& HttpObservation,) = (baseline,);
let inlined_result: Vec < (String , String , String) > = {

    ({ let (response, name): (&crate::HttpObservation, &str) = (response, "set-cookie"); response.headers.iter().filter(move |(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()) })
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

};
inlined_result
})
        .into_iter()
        .filter(|(name, _, _)| {
let (name,): (& str,) = (name,);

    let name = name.to_ascii_lowercase();
    ["session", "sess", "sid", "auth", "token", "jwt"]
        .iter()
        .any(|marker| name.contains(marker))

})
        .map(|(name, _, _)| name)
        .take(2)
        .collect::<Vec<_>>();
    if names.is_empty() {
        return {
let (context, check_id, class, title, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, & str,) = (context, "session.fixation", VulnerabilityClass::SessionAuthentication, "Session fixation", "No session-like response cookie was observed",);
let inlined_result: SecurityCheckResult = {

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Skipped, None, None, Vec::new(), Some(reason.to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

};
inlined_result
};
    }
    let mut attempted = 0usize;
    let mut last_error = None;
    for name in names {
        let marker = format!("nancyfix{}", ({
let (context,): (ProbeContext < '_ >,) = (context,);
let inlined_result: String = {

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{now:x}{:x}{}", context.port, context.ip)
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(28)
        .collect()

};
inlined_result
}));
        let cookie = format!("{name}={marker}");
        match ({
let (context, origin, method, url, headers, body, cookie_header, host_override, budget, progress,): (ProbeContext < '_ >, & OriginKey, & str, & Url, & [(String , String)], & [u8], Option < & str >, Option < & str >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, origin, "GET", root, &[], &[], Some(&cookie), None, budget, progress,);
async move {

    ({
let (inlined_self, origin,): (& mut RequestBudget, & OriginKey,) = (&mut *budget, origin,);
let inlined_result: Result < () , String > = {
'inlined_consume: {

        if endpoint_health::stopped(origin.ip, origin.port) {
            break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
        }
        if inlined_self.used >= inlined_self.total_limit {
            break 'inlined_consume Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = inlined_self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= inlined_self.per_origin_limit {
            break 'inlined_consume Err("Per-origin active-request budget exhausted".to_owned());
        }
        inlined_self.used += 1;
        *origin_used += 1;
        Ok(())

}
};
inlined_result
})?;
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("{method} {}", {
let (url,): (& Url,) = (url,);

    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )

}),
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
})
        .await
        {
            Ok(response)
                if ({
let (response,): (& HttpObservation,) = (&response,);
let inlined_result: Vec < (String , String , String) > = {

    ({ let (response, name): (&crate::HttpObservation, &str) = (response, "set-cookie"); response.headers.iter().filter(move |(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()) })
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

};
inlined_result
})
                    .iter()
                    .any(|(response_name, value, _)| {
                        response_name.eq_ignore_ascii_case(&name) && value == &marker
                    }) =>
            {
                return {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "session.fixation", VulnerabilityClass::SessionAuthentication, "Session fixation", FindingSeverity::High, Confidence::Medium, CheckOutcome::Potential, Some(root.to_string()), Some(format!("GET / with a caller-selected {name} cookie")), vec![format!(
                        "The response reissued the supplied marker as the value of '{name}'"
                    )], Some("Confirm that the cookie controls an authenticated session before treating fixation as exploitable".to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

};
            }
            Err(error) => last_error = Some(error),
            Ok(_) => attempted += 1,
        }
    }
    {
let (context, check_id, class, title, severity, attempted, error,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, usize, Option < String >,) = (context, "session.fixation", VulnerabilityClass::SessionAuthentication, "Session fixation", FindingSeverity::High, attempted, last_error,);
let inlined_result: SecurityCheckResult = {
'inlined_observed_or_inconclusive: {

    if attempted == 0 {
        break 'inlined_observed_or_inconclusive ({
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, check_id, class, title, None, error.unwrap_or_else(|| "No probe could be completed".to_owned()),);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

});
    }
    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, severity, Confidence::Medium, CheckOutcome::NotObserved, None, None, vec![format!("{attempted} bounded probe(s) completed")], error,);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

}
};
inlined_result
}

}
})
            .await,
        );
        checks.push(
            ({
let (context, origin, root, baseline, forms, budget, progress,): (ProbeContext < '_ >, & OriginKey, & Url, Option < & HttpObservation >, & [& CrawlFormAction], & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, &origin, &root, root_response.as_ref().ok(), &endpoint_forms, &mut budget, progress,);
async move {

    let unprotected = forms
        .iter()
        .copied()
        .filter(|form| form.likely_csrf_tokens.is_empty())
        .collect::<Vec<_>>();
    if forms.is_empty() {
        return {
let (context, check_id, class, title, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, & str,) = (context, "session.csrf-form", VulnerabilityClass::SessionAuthentication, "Cross-site request forgery protection", "No state-changing forms were discovered",);
let inlined_result: SecurityCheckResult = {

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Skipped, None, None, Vec::new(), Some(reason.to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

};
inlined_result
};
    }
    if unprotected.is_empty() {
        return {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "session.csrf-form", VulnerabilityClass::SessionAuthentication, "Cross-site request forgery protection", FindingSeverity::Medium, Confidence::Low, CheckOutcome::NotObserved, None, None, vec!["All discovered state-changing forms contained a token-like control".to_owned()], None,);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

};
    }
    if !matches!( context.scan.request.web_probe_level, crate::WebProbeLevel::StateChanging) {
        return {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "session.csrf-form", VulnerabilityClass::SessionAuthentication, "Cross-site request forgery protection", FindingSeverity::Medium, Confidence::Low, CheckOutcome::Potential, Some(unprotected[0].action_url.clone()), None, vec![format!(
                "{} state-changing form(s) had no token-like control",
                unprotected.len()
            )], Some("No form was submitted at the non-state-changing probe level; SameSite, Origin, or Referer enforcement may still prevent CSRF".to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

};
    }
    let Some(baseline) = baseline else {
        return {
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, "session.csrf-form", VulnerabilityClass::SessionAuthentication, "Cross-site request forgery protection", Some(root.to_string()), "Root response was unavailable".to_owned(),);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

};
    };
    let cookie = {
let (response, scheme,): (& HttpObservation, & str,) = (baseline, root.scheme(),);

    let cookies = ({
let (response,): (& HttpObservation,) = (response,);
let inlined_result: Vec < (String , String , String) > = {

    ({ let (response, name): (&crate::HttpObservation, &str) = (response, "set-cookie"); response.headers.iter().filter(move |(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()) })
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

};
inlined_result
})
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

};
    let Some(cookie) = cookie else {
        return {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "session.csrf-form", VulnerabilityClass::SessionAuthentication, "Cross-site request forgery protection", FindingSeverity::Medium, Confidence::Low, CheckOutcome::Deferred, Some(unprotected[0].action_url.clone()), None, Vec::new(), Some("No cookie eligible for a cross-site form POST was observed in the anonymous session".to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

};
    };
    let mut attempted = 0usize;
    let mut last_error = None;
    for form in unprotected
        .into_iter()
        .filter(|form| {
let (form,): (& CrawlFormAction,) = (form,);
{
'inlined_safe_form_probe: {

    if !form.method.eq_ignore_ascii_case("POST")
        || form.has_password
        || !form
            .encoding
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        || form.controls.iter().any(|control| {
            control.control_type.eq_ignore_ascii_case("file") || {
let (value,): (& str,) = (&control.name,);

    let value = value.to_ascii_lowercase();
    [
        "delete", "remove", "destroy", "logout", "password", "reset", "checkout", "payment",
        "purchase", "order", "transfer", "withdraw", "upload", "admin", "amount", "card",
    ]
    .iter()
    .any(|term| value.contains(term))

}
        })
    {
        break 'inlined_safe_form_probe false;
    }
    Url::parse(&form.action_url)
        .ok()
        .is_some_and(|url| !{
let (value,): (& str,) = (url.path(),);

    let value = value.to_ascii_lowercase();
    [
        "delete", "remove", "destroy", "logout", "password", "reset", "checkout", "payment",
        "purchase", "order", "transfer", "withdraw", "upload", "admin", "amount", "card",
    ]
    .iter()
    .any(|term| value.contains(term))

})

}
}

})
        .take(2)
    {
        let Ok(action) = Url::parse(&form.action_url) else {
            continue;
        };
        let body = {
let (form, token,): (& CrawlFormAction, & str,) = (form, &({

let inlined_result: String = {

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{now:x}{:x}{}", context.port, context.ip)
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(28)
        .collect()

};
inlined_result
}),);

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

};
        let headers = [
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
        match ({
let (context, origin, method, url, headers, body, cookie_header, host_override, budget, progress,): (ProbeContext < '_ >, & OriginKey, & str, & Url, & [(String , String)], & [u8], Option < & str >, Option < & str >, & mut RequestBudget, & Option < Sender < ExposureScanProgress > >,) = (context, origin, &form.method, &action, &headers, body.as_bytes(), Some(&cookie), None, budget, progress,);
async move {

    ({
let (inlined_self, origin,): (& mut RequestBudget, & OriginKey,) = (&mut *budget, origin,);
let inlined_result: Result < () , String > = {
'inlined_consume: {

        if endpoint_health::stopped(origin.ip, origin.port) {
            break 'inlined_consume Err(endpoint_health::STOP_REASON.to_owned());
        }
        if inlined_self.used >= inlined_self.total_limit {
            break 'inlined_consume Err("Total active-request budget exhausted".to_owned());
        }
        let origin_used = inlined_self.per_origin.entry(origin.clone()).or_default();
        if *origin_used >= inlined_self.per_origin_limit {
            break 'inlined_consume Err("Per-origin active-request budget exhausted".to_owned());
        }
        inlined_self.used += 1;
        *origin_used += 1;
        Ok(())

}
};
inlined_result
})?;
    send_phase_progress(
        progress,
        ExposureScanPhase::ActiveWebAssessment,
        ExposureScanPhaseState::Running,
        budget.used as f32 / budget.total_limit.max(1) as f32,
        format!("{method} {}", {
let (url,): (& Url,) = (url,);

    format!(
        "{}://{}:{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default(),
        url.path()
    )

}),
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
})
        .await
        {
            Ok(response) if {
let (response,): (& HttpObservation,) = (&response,);
'inlined_cross_site_submission_accepted: {

    if !(200..400).contains(&response.status) {
        break 'inlined_cross_site_submission_accepted false;
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
} => {
                return {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "session.csrf-form", VulnerabilityClass::SessionAuthentication, "Cross-site request forgery protection", FindingSeverity::Medium, Confidence::Medium, CheckOutcome::Potential, Some(action.to_string()), Some(format!(
                        "{} with a foreign Origin and Referer using a cross-site-eligible cookie",
                        form.method
                    )), vec![format!(
                        "The tokenless cross-site submission returned HTTP {} without a recognizable CSRF rejection",
                        response.status
                    )], Some("The application response did not prove that a durable state change occurred".to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

};
            }
            Err(error) => last_error = Some(error),
            Ok(_) => attempted += 1,
        }
    }
    if attempted == 0 {
        return {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, "session.csrf-form", VulnerabilityClass::SessionAuthentication, "Cross-site request forgery protection", FindingSeverity::Medium, Confidence::Low, CheckOutcome::Deferred, Some(root.to_string()), None, Vec::new(), Some("Discovered forms were excluded from automated submission because they involved credentials, files, or destructive-looking actions".to_owned()),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

};
    }
    {
let (context, check_id, class, title, severity, attempted, error,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, usize, Option < String >,) = (context, "session.csrf-form", VulnerabilityClass::SessionAuthentication, "Cross-site request forgery protection", FindingSeverity::Medium, attempted, last_error,);
let inlined_result: SecurityCheckResult = {
'inlined_observed_or_inconclusive: {

    if attempted == 0 {
        break 'inlined_observed_or_inconclusive ({
let (context, check_id, class, title, probe_url, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, Option < String >, String,) = (context, check_id, class, title, None, error.unwrap_or_else(|| "No probe could be completed".to_owned()),);

    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, FindingSeverity::Informational, Confidence::Low, CheckOutcome::Inconclusive, probe_url, None, Vec::new(), Some(reason),);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

});
    }
    {
let (context, check_id, class, title, severity, confidence, outcome, probe_url, request_evidence, evidence, reason,): (ProbeContext < '_ >, & str, VulnerabilityClass, & str, FindingSeverity, Confidence, CheckOutcome, Option < String >, Option < String >, Vec < String >, Option < String >,) = (context, check_id, class, title, severity, Confidence::Medium, CheckOutcome::NotObserved, None, None, vec![format!("{attempted} bounded probe(s) completed")], error,);
{

    let interrupted = ({ let context = context; crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        && matches!(
            outcome,
            CheckOutcome::NotObserved | CheckOutcome::Inconclusive
        );
    let outcome = if interrupted {
        if evidence.is_empty() {
            CheckOutcome::Skipped
        } else {
            CheckOutcome::Inconclusive
        }
    } else {
        outcome
    };
    let reason = if interrupted {
        Some(endpoint_health::STOP_REASON.to_owned())
    } else {
        reason
    };
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

}

}
};
inlined_result
}

}
})
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
