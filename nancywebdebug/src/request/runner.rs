use crate::auth::{self, SharedAuthStore};
use crate::diagnostics::*;
use crate::network::{ConnectionRateLimiter, non_public_reason};
use ::http::{HeaderName, HeaderValue, Method};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::dns::{finish_interrupted_dns_attempt, resolve_host, resolve_host_exhaustive};
use super::fingerprint;
use super::http::{self, add_automatic_headers, parse_request_headers};
use super::http3;
use super::stages::*;

const MAX_REDIRECTS: usize = 10;

pub async fn run_diagnostic_session(
    initial_index: usize,
    request: DiagnosticRequest,
    auth_store: SharedAuthStore,
    cancel: CancellationToken,
    progress: Option<Sender<DiagnosticProgress>>,
) -> Vec<DiagnosticTrace> {
    run_diagnostic_session_inner(
        initial_index,
        request,
        auth_store,
        cancel,
        progress,
        None,
        false,
        None,
    )
    .await
}

pub(crate) async fn run_diagnostic_session_for_exposure(
    initial_index: usize,
    request: DiagnosticRequest,
    auth_store: SharedAuthStore,
    cancel: CancellationToken,
    pinned_ip: IpAddr,
    limiter: Arc<ConnectionRateLimiter>,
) -> Vec<DiagnosticTrace> {
    run_diagnostic_session_inner(
        initial_index,
        request,
        auth_store,
        cancel,
        None,
        Some(pinned_ip),
        true,
        Some(limiter),
    )
    .await
}

async fn run_diagnostic_session_inner(
    initial_index: usize,
    mut request: DiagnosticRequest,
    auth_store: SharedAuthStore,
    cancel: CancellationToken,
    progress: Option<Sender<DiagnosticProgress>>,
    mut pinned_ip: Option<IpAddr>,
    public_only: bool,
    limiter: Option<Arc<ConnectionRateLimiter>>,
) -> Vec<DiagnosticTrace> {
    let mut traces = Vec::new();
    let mut visited_urls = HashSet::new();
    let mut redirects_followed = 0;
    let mut index = initial_index;

    loop {
        let mut trace = ({
let (index, request, auth_store, cancel, progress, pinned_ip, public_only, limiter,): (usize, DiagnosticRequest, SharedAuthStore, CancellationToken, Option < Sender < DiagnosticProgress > >, Option < IpAddr >, bool, Option < Arc < ConnectionRateLimiter > >,) = (index, request, auth_store.clone(), cancel.clone(), progress.clone(), pinned_ip.take(), public_only, limiter.clone(),);
async move {

    let mut trace = DiagnosticTrace::new(index, request);
    if let Some(ip) = pinned_ip {
        trace.connection_mode = format!("Pinned exposure endpoint ({ip})");
    }
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
        );
    }
    if trace.request.protocol == ProtocolPreference::Http3 && url.scheme() != "https" {
        return fail_trace(
            trace,
            StageKind::Url,
            StageStatus::Failed,
            url_started,
            "HTTP/3 requires an HTTPS URL".to_owned(),
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
    let client_certificate = if let Some(profile_id) = trace
        .request
        .client_certificate
        .as_ref()
        .map(|profile| profile.profile_id)
    {
        match auth::resolve_client_certificate(auth_store.clone(), profile_id, url.as_str()) {
            Ok(certificate) => Some(certificate),
            Err(error) => {
                return fail_trace(
                    trace,
                    StageKind::Authentication,
                    StageStatus::Failed,
                    authentication_started,
                    error,
                );
            }
        }
    } else {
        None
    };
    let resolved_auth =
        if let Some(profile_id) = trace.request.auth.as_ref().map(|auth| auth.profile_id) {
            match auth::resolve(
                auth_store.clone(),
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
                        if let Some(certificate) = &client_certificate {
                            format!(
                                "{}; mTLS identity '{}'",
                                resolved.detail, certificate.profile_name
                            )
                        } else {
                            resolved.detail.clone()
                        },
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
                    );
                }
            }
        } else {
            finish_stage(
                &mut trace,
                StageKind::Authentication,
                StageStatus::Skipped,
                authentication_started,
                client_certificate.as_ref().map_or_else(
                    || "No authentication profile".to_owned(),
                    |certificate| format!("mTLS identity '{}'", certificate.profile_name),
                ),
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
            );
        }
    };
    add_automatic_headers(
        &url,
        &mut headers,
        trace.request.body.len(),
        trace.request.user_agent,
    );
    trace.http.request_headers = (&headers).iter().map(|(name, value)| crate::diagnostics::HeaderTrace { name: name.to_string(), value: value.as_bytes().to_vec(), pseudo: false }).collect::<Vec<_>>();
    for input in input_headers {
        if let Some(header) = trace.http.request_headers.iter_mut().find(|header| {
            header.name.eq_ignore_ascii_case(&input.name) && header.value == input.value
        }) {
            header.name = input.name;
        }
    }

    let dns_started = begin_stage(&mut trace, StageKind::Dns, &progress);
    let dns_result = if public_only {
        wait_for(
            trace.request.timeouts.dns,
            &cancel,
            resolve_host(&host, &mut trace.dns),
        )
        .await
    } else {
        wait_for(
            trace.request.timeouts.dns,
            &cancel,
            resolve_host_exhaustive(&host, &mut trace.dns),
        )
        .await
    };
    let inventory_timed_out = match dns_result {
        Ok(Ok(())) => false,
        Ok(Err(error)) => {
            return fail_trace(
                trace,
                StageKind::Dns,
                StageStatus::Failed,
                dns_started,
                error,
            );
        }
        Err(WaitError::TimedOut) => {
            finish_interrupted_dns_attempt(&mut trace.dns, dns_started, "DNS stage timed out");
            if public_only || trace.dns.addresses.is_empty() {
                return fail_trace(
                    trace,
                    StageKind::Dns,
                    StageStatus::TimedOut,
                    dns_started,
                    "DNS stage timed out".to_owned(),
                );
            }
            true
        }
        Err(WaitError::Cancelled) => {
            finish_interrupted_dns_attempt(&mut trace.dns, dns_started, "Request cancelled");
            return fail_trace(
                trace,
                StageKind::Dns,
                StageStatus::Cancelled,
                dns_started,
                "Request cancelled".to_owned(),
            );
        }
    };
    let mut addresses = trace.dns.addresses.clone();
    if let Some(ip) = pinned_ip {
        if public_only && non_public_reason(ip).is_some() {
            return fail_trace(
                trace,
                StageKind::Dns,
                StageStatus::Failed,
                dns_started,
                format!("Pinned destination {ip} is not publicly routable"),
            );
        }
        addresses.clear();
        addresses.push(ip);
    } else {
        if addresses.is_empty() {
            return fail_trace(
                trace,
                StageKind::Dns,
                StageStatus::Failed,
                dns_started,
                "DNS returned no A or AAAA addresses".to_owned(),
            );
        }
        if public_only {
            addresses.retain(|address| non_public_reason(*address).is_none());
            if addresses.is_empty() {
                return fail_trace(
                    trace,
                    StageKind::Dns,
                    StageStatus::Failed,
                    dns_started,
                    "Destination has no publicly routable A or AAAA address".to_owned(),
                );
            }
        }
    }
    let mut dns_detail = if pinned_ip.is_some() {
        format!("Pinned to {}", addresses[0])
    } else {
        format!("{} public address(es)", addresses.len())
    };
    if inventory_timed_out {
        dns_detail.push_str(&format!(
            "; record inventory incomplete ({} query type(s) unfinished)",
            trace.dns.incomplete_record_types.len()
        ));
    }
    finish_stage(
        &mut trace,
        StageKind::Dns,
        StageStatus::Succeeded,
        dns_started,
        dns_detail,
        &progress,
    );

    if trace.request.protocol == ProtocolPreference::Http3 {
        http3::run(
            trace,
            method,
            headers,
            addresses,
            cancel,
            progress,
            limiter,
            client_certificate,
        )
        .await
    } else {
        http::run(
            trace,
            method,
            headers,
            addresses,
            cancel,
            progress,
            limiter,
            client_certificate,
        )
        .await
    }

}
})
        .await;
        let next_request = {
            let (trace, visited_urls, redirects_followed): (
                &mut DiagnosticTrace,
                &mut HashSet<String>,
                usize,
            ) = (&mut trace, &mut visited_urls, redirects_followed);
            {
                'inlined_prepare_redirect: {
                    if !trace.url.normalized.is_empty() {
                        visited_urls.insert(trace.url.normalized.clone());
                    }
                    if !trace.request.follow_redirects {
                        break 'inlined_prepare_redirect None;
                    }
                    let target = match trace.redirect_target.as_ref() {
                        Some(value) => value,
                        None => break 'inlined_prepare_redirect None,
                    };
                    if trace.outcome != TraceOutcome::Success {
                        trace.redirect_stop_reason = Some(
            "Redirect not followed because the request did not complete successfully".to_owned(),
        );
                        break 'inlined_prepare_redirect None;
                    }
                    if !matches!(trace.http.status, Some(301 | 302 | 303 | 307 | 308)) {
                        trace.redirect_stop_reason = Some(format!(
                            "HTTP status {} is not followed automatically",
                            trace.http.status.unwrap_or_default()
                        ));
                        break 'inlined_prepare_redirect None;
                    }
                    if redirects_followed >= MAX_REDIRECTS {
                        trace.redirect_stop_reason =
                            Some(format!("Redirect limit of {MAX_REDIRECTS} reached"));
                        break 'inlined_prepare_redirect None;
                    }
                    if visited_urls.contains(target) {
                        trace.redirect_stop_reason = Some("Redirect loop detected".to_owned());
                        break 'inlined_prepare_redirect None;
                    }
                    trace.redirect_followed = true;
                    trace.redirect_stop_reason = None;
                    Some({
                        let (trace, target): (&DiagnosticTrace, &str) = (trace, target);
                        let inlined_result: DiagnosticRequest = {
                            let mut request = trace.request.clone();
                            request.url = target.to_owned();
                            let switch_to_get = matches!(trace.http.status, Some(303))
                                && !trace.request.method.eq_ignore_ascii_case("HEAD")
                                || matches!(trace.http.status, Some(301 | 302))
                                    && trace.request.method.eq_ignore_ascii_case("POST");
                            let (crosses_origin, crosses_host) =
                                match (Url::parse(&trace.url.normalized), Url::parse(target)) {
                                    (Ok(source), Ok(target)) => (
                                        source.origin() != target.origin(),
                                        source.host_str().zip(target.host_str()).is_none_or(
                                            |(source, target)| !source.eq_ignore_ascii_case(target),
                                        ),
                                    ),
                                    _ => (true, true),
                                };
                            if switch_to_get {
                                request.method = "GET".to_owned();
                                request.body = Arc::from([]);
                            }
                            if crosses_origin {
                                request.auth = None;
                            }
                            if crosses_host {
                                request.client_certificate = None;
                            }
                            request.headers = trace
                                .request
                                .headers
                                .lines()
                                .filter(|line| {
                                    line.split_once(':').is_none_or(|(name, _)| {
                                        let name = name.trim();
                                        !name.eq_ignore_ascii_case("host")
                                            && !(switch_to_get
                                                && [
                                                    "content-encoding",
                                                    "content-length",
                                                    "content-type",
                                                    "transfer-encoding",
                                                ]
                                                .iter()
                                                .any(|removed| name.eq_ignore_ascii_case(removed)))
                                            && !(crosses_origin
                                                && [
                                                    "authorization",
                                                    "cookie",
                                                    "proxy-authorization",
                                                ]
                                                .iter()
                                                .any(|removed| name.eq_ignore_ascii_case(removed)))
                                    })
                                })
                                .enumerate()
                                .fold(String::new(), |mut headers, (index, line)| {
                                    if index > 0 {
                                        headers.push('\n');
                                    }
                                    headers.push_str(line);
                                    headers
                                });
                            request
                        };
                        inlined_result
                    })
                }
            }
        };
        fingerprint::analyze(&mut trace);
        if let Some(progress) = &progress {
            let _ = progress.send(DiagnosticProgress::HttpHopCompleted(trace.clone()));
        }
        traces.push(trace);
        let Some(next_request) = next_request else {
            break;
        };
        redirects_followed += 1;
        index += 1;
        request = next_request;
    }

    if let Some(progress) = &progress {
        let _ = progress.send(DiagnosticProgress::SessionCompleted);
    }

    traces
}
