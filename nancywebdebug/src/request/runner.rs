use crate::auth::{self, SharedAuthStore};
use crate::diagnostics::*;
use ::http::{HeaderName, HeaderValue, Method};
use std::collections::HashSet;
use std::sync::mpsc::Sender;
use std::sync::{Arc, mpsc};
use tokio_util::sync::CancellationToken;
use url::Url;

use super::dns::{finish_interrupted_dns_attempt, resolve_host};
use super::http::{self, add_automatic_headers, header_map_to_trace, parse_request_headers};
use super::http3;
use super::stages::*;

const MAX_REDIRECTS: usize = 10;

pub async fn run_diagnostic_session(
    initial_index: usize,
    mut request: DiagnosticRequest,
    auth_store: SharedAuthStore,
    cancel: CancellationToken,
    progress: Option<Sender<DiagnosticProgress>>,
) -> Vec<DiagnosticTrace> {
    let progress = progress.unwrap_or_else(|| {
        let (progress, receiver) = mpsc::channel();
        drop(receiver);
        progress
    });
    let mut traces = Vec::new();
    let mut visited_urls = HashSet::new();
    let mut redirects_followed = 0;
    let mut index = initial_index;

    loop {
        let mut trace = run_diagnostic_inner(
            index,
            request,
            auth_store.clone(),
            cancel.clone(),
            progress.clone(),
        )
        .await;
        let next_request = prepare_redirect(&mut trace, &mut visited_urls, redirects_followed);
        let _ = progress.send(DiagnosticProgress::Finished(trace.clone()));
        traces.push(trace);
        let Some(next_request) = next_request else {
            break;
        };
        redirects_followed += 1;
        index += 1;
        request = next_request;
    }

    traces
}

async fn run_diagnostic_inner(
    index: usize,
    request: DiagnosticRequest,
    auth_store: SharedAuthStore,
    cancel: CancellationToken,
    progress: Sender<DiagnosticProgress>,
) -> DiagnosticTrace {
    let mut trace = DiagnosticTrace::new(index, request);
    let url_started = begin_stage(&mut trace, StageKind::Url, &progress);
    let normalized = normalize_url_input(&trace.request.url);
    let mut url = match Url::parse(&normalized) {
        Ok(url) => url,
        Err(error) => {
            return fail_trace(
                trace,
                StageKind::Url,
                StageStatus::Failed,
                url_started,
                error.to_string(),
                &progress,
            );
        }
    };
    url.set_fragment(None);
    if !matches!(url.scheme(), "http" | "https") {
        return fail_trace(
            trace,
            StageKind::Url,
            StageStatus::Failed,
            url_started,
            format!("Unsupported URL scheme: {}", url.scheme()),
            &progress,
        );
    }
    if trace.request.protocol == ProtocolPreference::Http3 && url.scheme() != "https" {
        return fail_trace(
            trace,
            StageKind::Url,
            StageStatus::Failed,
            url_started,
            "HTTP/3 requires an HTTPS URL".to_owned(),
            &progress,
        );
    }
    let host = match url.host_str() {
        Some(host) => host.to_owned(),
        None => {
            return fail_trace(
                trace,
                StageKind::Url,
                StageStatus::Failed,
                url_started,
                "URL has no host".to_owned(),
                &progress,
            );
        }
    };
    let port = url.port_or_known_default().unwrap_or(80);
    let mut path_and_query = url.path().to_owned();
    if let Some(query) = url.query() {
        path_and_query.push('?');
        path_and_query.push_str(query);
    }
    trace.url = UrlTrace {
        normalized: url.to_string(),
        scheme: url.scheme().to_owned(),
        host: host.clone(),
        port,
        path_and_query,
    };
    trace.http.final_url = trace.url.normalized.clone();
    finish_stage(
        &mut trace,
        StageKind::Url,
        StageStatus::Succeeded,
        url_started,
        format!("{}://{}:{}", url.scheme(), host, port),
        &progress,
    );

    let authentication_started = begin_stage(&mut trace, StageKind::Authentication, &progress);
    let resolved_auth =
        if let Some(profile_id) = trace.request.auth.as_ref().map(|auth| auth.profile_id) {
            match auth::resolve(
                auth_store,
                profile_id,
                url.as_str(),
                trace.request.timeouts.authentication,
                cancel.clone(),
            )
            .await
            {
                Ok(resolved) => {
                    finish_stage(
                        &mut trace,
                        StageKind::Authentication,
                        StageStatus::Succeeded,
                        authentication_started,
                        resolved.detail.clone(),
                        &progress,
                    );
                    Some(resolved)
                }
                Err(error) => {
                    let status = if cancel.is_cancelled() {
                        StageStatus::Cancelled
                    } else if error.to_ascii_lowercase().contains("timed out") {
                        StageStatus::TimedOut
                    } else {
                        StageStatus::Failed
                    };
                    return fail_trace(
                        trace,
                        StageKind::Authentication,
                        status,
                        authentication_started,
                        error,
                        &progress,
                    );
                }
            }
        } else {
            finish_stage(
                &mut trace,
                StageKind::Authentication,
                StageStatus::Skipped,
                authentication_started,
                "No authentication profile".to_owned(),
                &progress,
            );
            None
        };

    let (mut headers, input_headers) = match parse_request_headers(&trace.request.headers) {
        Ok(headers) => headers,
        Err(error) => {
            let started = begin_stage(&mut trace, StageKind::HttpHeaders, &progress);
            return fail_trace(
                trace,
                StageKind::HttpHeaders,
                StageStatus::Failed,
                started,
                error,
                &progress,
            );
        }
    };
    if let Some(auth) = resolved_auth.as_ref() {
        let name = HeaderName::from_static(auth.header_name);
        if headers.contains_key(&name) {
            let started = begin_stage(&mut trace, StageKind::HttpHeaders, &progress);
            return fail_trace(
                trace,
                StageKind::HttpHeaders,
                StageStatus::Failed,
                started,
                format!(
                    "Custom {} header conflicts with the selected authentication profile",
                    auth.header_name
                ),
                &progress,
            );
        }
        let value = match HeaderValue::from_str(auth.header_value.as_str()) {
            Ok(value) => value,
            Err(error) => {
                let started = begin_stage(&mut trace, StageKind::HttpHeaders, &progress);
                return fail_trace(
                    trace,
                    StageKind::HttpHeaders,
                    StageStatus::Failed,
                    started,
                    format!("Authentication produced an invalid header value: {error}"),
                    &progress,
                );
            }
        };
        headers.insert(name, value);
    }
    let method = match Method::from_bytes(trace.request.method.as_bytes()) {
        Ok(method) => method,
        Err(error) => {
            let started = begin_stage(&mut trace, StageKind::HttpHeaders, &progress);
            return fail_trace(
                trace,
                StageKind::HttpHeaders,
                StageStatus::Failed,
                started,
                error.to_string(),
                &progress,
            );
        }
    };
    add_automatic_headers(
        &url,
        &mut headers,
        trace.request.body.len(),
        trace.request.user_agent,
    );
    trace.http.request_headers = header_map_to_trace(&headers);
    for input in input_headers {
        if let Some(header) = trace.http.request_headers.iter_mut().find(|header| {
            header.name.eq_ignore_ascii_case(&input.name) && header.value == input.value
        }) {
            header.name = input.name;
        }
    }

    let dns_started = begin_stage(&mut trace, StageKind::Dns, &progress);
    let dns_result = wait_for(
        trace.request.timeouts.dns,
        &cancel,
        resolve_host(&host, &mut trace.dns),
    )
    .await;
    let addresses = match dns_result {
        Ok(Ok(())) => {
            let addresses = trace.dns.addresses.clone();
            if addresses.is_empty() {
                return fail_trace(
                    trace,
                    StageKind::Dns,
                    StageStatus::Failed,
                    dns_started,
                    "DNS returned no A or AAAA addresses".to_owned(),
                    &progress,
                );
            }
            finish_stage(
                &mut trace,
                StageKind::Dns,
                StageStatus::Succeeded,
                dns_started,
                format!("{} address(es)", addresses.len()),
                &progress,
            );
            addresses
        }
        Ok(Err(error)) => {
            return fail_trace(
                trace,
                StageKind::Dns,
                StageStatus::Failed,
                dns_started,
                error,
                &progress,
            );
        }
        Err(WaitError::TimedOut) => {
            finish_interrupted_dns_attempt(&mut trace.dns, dns_started, "DNS stage timed out");
            return fail_trace(
                trace,
                StageKind::Dns,
                StageStatus::TimedOut,
                dns_started,
                "DNS stage timed out".to_owned(),
                &progress,
            );
        }
        Err(WaitError::Cancelled) => {
            finish_interrupted_dns_attempt(&mut trace.dns, dns_started, "Request cancelled");
            return fail_trace(
                trace,
                StageKind::Dns,
                StageStatus::Cancelled,
                dns_started,
                "Request cancelled".to_owned(),
                &progress,
            );
        }
    };

    if trace.request.protocol == ProtocolPreference::Http3 {
        http3::run(trace, method, headers, addresses, cancel, progress).await
    } else {
        http::run(trace, method, headers, addresses, cancel, progress).await
    }
}

fn prepare_redirect(
    trace: &mut DiagnosticTrace,
    visited_urls: &mut HashSet<String>,
    redirects_followed: usize,
) -> Option<DiagnosticRequest> {
    if !trace.url.normalized.is_empty() {
        visited_urls.insert(trace.url.normalized.clone());
    }
    if !trace.request.follow_redirects {
        return None;
    }
    let target = trace.redirect_target.as_ref()?.clone();
    if trace.outcome != TraceOutcome::Success {
        trace.redirect_stop_reason = Some(
            "Redirect not followed because the request did not complete successfully".to_owned(),
        );
        return None;
    }
    if !matches!(trace.http.status, Some(301 | 302 | 303 | 307 | 308)) {
        trace.redirect_stop_reason = Some(format!(
            "HTTP status {} is not followed automatically",
            trace.http.status.unwrap_or_default()
        ));
        return None;
    }
    if redirects_followed >= MAX_REDIRECTS {
        trace.redirect_stop_reason = Some(format!("Redirect limit of {MAX_REDIRECTS} reached"));
        return None;
    }
    if visited_urls.contains(&target) {
        trace.redirect_stop_reason = Some("Redirect loop detected".to_owned());
        return None;
    }
    trace.redirect_followed = true;
    trace.redirect_stop_reason = None;
    Some(redirect_request(trace, target))
}

fn redirect_request(trace: &DiagnosticTrace, target: String) -> DiagnosticRequest {
    let mut request = trace.request.clone();
    request.url = target.clone();
    let mut removed_headers = vec!["host"];
    let switch_to_get = matches!(trace.http.status, Some(303))
        && !trace.request.method.eq_ignore_ascii_case("HEAD")
        || matches!(trace.http.status, Some(301 | 302))
            && trace.request.method.eq_ignore_ascii_case("POST");
    if switch_to_get {
        request.method = "GET".to_owned();
        request.body = Arc::from([]);
        removed_headers.extend([
            "content-encoding",
            "content-length",
            "content-type",
            "transfer-encoding",
        ]);
    }
    if redirect_crosses_origin(&trace.url.normalized, &target) {
        removed_headers.extend(["authorization", "cookie", "proxy-authorization"]);
        request.auth = None;
    }
    request.headers = remove_headers(&request.headers, &removed_headers);
    request
}

fn redirect_crosses_origin(source: &str, target: &str) -> bool {
    match (Url::parse(source), Url::parse(target)) {
        (Ok(source), Ok(target)) => source.origin() != target.origin(),
        _ => true,
    }
}

fn remove_headers(headers: &str, names: &[&str]) -> String {
    headers
        .lines()
        .filter(|line| {
            line.split_once(':').is_none_or(|(name, _)| {
                !names
                    .iter()
                    .any(|removed| name.trim().eq_ignore_ascii_case(removed))
            })
        })
        .collect::<Vec<_>>()
        .join("\n")
}
