use crate::auth::LoadedClientCertificate;
use crate::diagnostics::*;
use crate::network::ConnectionRateLimiter;
use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, USER_AGENT};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri, Version};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::body::read_hyper_body;
use super::stages::*;
use super::tls::{
    CertificateCapture, make_tls_config, tls_trace_from_capture, tls_trace_from_stream,
};
use super::transport::{IoStream, RecordingIo, connect_tcp_all, select_tcp_candidate};

pub(super) async fn run(
    mut trace: DiagnosticTrace,
    method: Method,
    headers: HeaderMap,
    addresses: Vec<IpAddr>,
    cancel: CancellationToken,
    progress: Option<Sender<DiagnosticProgress>>,
    limiter: Option<Arc<ConnectionRateLimiter>>,
    client_certificate: Option<LoadedClientCertificate>,
) -> DiagnosticTrace {
    let tcp_started = begin_stage(&mut trace, StageKind::Tcp, &progress);
    let mut candidates = connect_tcp_all(
        &addresses,
        trace.url.port,
        trace.request.timeouts.transport,
        &cancel,
        limiter.as_deref(),
    )
    .await;
    let selected = select_tcp_candidate(&mut candidates);
    trace.connections = candidates
        .iter()
        .map(|candidate| candidate.attempt.clone())
        .collect();
    if cancel.is_cancelled() {
        return fail_trace(
            trace,
            StageKind::Tcp,
            StageStatus::Cancelled,
            tcp_started,
            "Request cancelled".to_owned(),
        );
    }
    let stream = match selected {
        Some(stream) => {
            finish_stage(
                &mut trace,
                StageKind::Tcp,
                StageStatus::Succeeded,
                tcp_started,
                format!(
                    "Selected {}",
                    stream
                        .peer_addr()
                        .map_or_else(|_| "unknown".to_owned(), |a| a.to_string())
                ),
                &progress,
            );
            stream
        }
        None => {
            let status = if trace
                .connections
                .iter()
                .all(|attempt| attempt.outcome == ConnectionOutcome::TimedOut)
            {
                StageStatus::TimedOut
            } else {
                StageStatus::Failed
            };
            return fail_trace(
                trace,
                StageKind::Tcp,
                status,
                tcp_started,
                "All TCP connection attempts failed".to_owned(),
            );
        }
    };

    let io = if trace.url.scheme == "https" {
        let tls_started = begin_stage(&mut trace, StageKind::Tls, &progress);
        let capture = Arc::new(Mutex::new(CertificateCapture::default()));
        let config = match make_tls_config(
            trace.request.protocol,
            capture.clone(),
            false,
            client_certificate.as_ref(),
        ) {
            Ok(config) => config,
            Err(error) => {
                return fail_trace(
                    trace,
                    StageKind::Tls,
                    StageStatus::Failed,
                    tls_started,
                    error,
                );
            }
        };
        let server_name = match ServerName::try_from(trace.url.host.clone()) {
            Ok(name) => name,
            Err(error) => {
                return fail_trace(
                    trace,
                    StageKind::Tls,
                    StageStatus::Failed,
                    tls_started,
                    error.to_string(),
                );
            }
        };
        let handshake = wait_for(
            trace.request.timeouts.tls,
            &cancel,
            TlsConnector::from(config).connect(server_name, stream),
        )
        .await;
        match handshake {
            Ok(Ok(tls_stream)) => {
                trace.tls = Some(tls_trace_from_stream(
                    &trace.url.host,
                    &tls_stream,
                    &capture,
                ));
                let detail = trace
                    .tls
                    .as_ref()
                    .and_then(|tls| tls.alpn.clone())
                    .unwrap_or_else(|| "no ALPN".to_owned());
                finish_stage(
                    &mut trace,
                    StageKind::Tls,
                    StageStatus::Succeeded,
                    tls_started,
                    detail,
                    &progress,
                );
                IoStream::Tls(Box::new(tls_stream))
            }
            Ok(Err(error)) => {
                trace.tls = Some(tls_trace_from_capture(&trace.url.host, &capture));
                return fail_trace(
                    trace,
                    StageKind::Tls,
                    StageStatus::Failed,
                    tls_started,
                    error.to_string(),
                );
            }
            Err(WaitError::TimedOut) => {
                trace.tls = Some(tls_trace_from_capture(&trace.url.host, &capture));
                return fail_trace(
                    trace,
                    StageKind::Tls,
                    StageStatus::TimedOut,
                    tls_started,
                    "TLS handshake timed out".to_owned(),
                );
            }
            Err(WaitError::Cancelled) => {
                trace.tls = Some(tls_trace_from_capture(&trace.url.host, &capture));
                return fail_trace(
                    trace,
                    StageKind::Tls,
                    StageStatus::Cancelled,
                    tls_started,
                    "Request cancelled".to_owned(),
                );
            }
        }
    } else {
        let tls_started = begin_stage(&mut trace, StageKind::Tls, &progress);
        finish_stage(
            &mut trace,
            StageKind::Tls,
            StageStatus::Skipped,
            tls_started,
            "Plain HTTP".to_owned(),
            &progress,
        );
        IoStream::Plain(stream)
    };

    let version = {
        let (trace, io): (&DiagnosticTrace, &IoStream) = (&trace, &io);
        let inlined_result: Result<Version, String> = {
            let negotiated = match io {
                IoStream::Tls(stream) => stream
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|value| value.to_vec()),
                IoStream::Plain(_) => None,
            };
            match trace.request.protocol {
                ProtocolPreference::Auto => Ok(if negotiated.as_deref() == Some(b"h2") {
                    Version::HTTP_2
                } else {
                    Version::HTTP_11
                }),
                ProtocolPreference::Http11 => {
                    if negotiated
                        .as_deref()
                        .is_some_and(|value| value != b"http/1.1")
                    {
                        Err(format!(
                            "Server negotiated unexpected ALPN: {:?}",
                            negotiated
                        ))
                    } else {
                        Ok(Version::HTTP_11)
                    }
                }
                ProtocolPreference::Http2 => {
                    if trace.url.scheme == "https" && negotiated.as_deref() != Some(b"h2") {
                        Err("Server did not negotiate HTTP/2".to_owned())
                    } else {
                        Ok(Version::HTTP_2)
                    }
                }
                ProtocolPreference::Http3 => Ok(Version::HTTP_3),
            }
        };
        inlined_result
    };
    if let Err(error) = &version {
        let started = begin_stage(&mut trace, StageKind::HttpHeaders, &progress);
        return fail_trace(
            trace,
            StageKind::HttpHeaders,
            StageStatus::Failed,
            started,
            error.clone(),
        );
    }
    let version = version.unwrap();
    trace.http.request_headers = request_headers_for_version(&trace, &headers, &method, version);
    trace.http.request_header_representation = if version == Version::HTTP_2 {
        "Decoded HTTP/2 header and pseudoheader fields".to_owned()
    } else {
        "Actual transmitted HTTP/1.1 header bytes".to_owned()
    };
    let request = match build_request(&trace, method, headers, version) {
        Ok(request) => request.map(|()| Full::new(Bytes::from_owner(trace.request.body.clone()))),
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
    trace.http.headers_sent = true;

    let headers_started = begin_stage(&mut trace, StageKind::HttpHeaders, &progress);
    let response = if version == Version::HTTP_2 {
        ({
            let (io, request, timeout, cancel): (
                IoStream,
                Request<Full<Bytes>>,
                Duration,
                &CancellationToken,
            ) = (io, request, trace.request.timeouts.headers, &cancel);
            async move {
                let io = TokioIo::new(io);
                let operation = async {
                    let (mut sender, connection) =
                        hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                            .handshake(io)
                            .await
                            .map_err(|error| error.to_string())?;
                    tokio::spawn(async move {
                        let _ = connection.await;
                    });
                    sender
                        .send_request(request)
                        .await
                        .map_err(|error| error.to_string())
                };
                match wait_for(timeout, cancel, operation).await {
                    Ok(Ok(response)) => Ok(response),
                    Ok(Err(error)) => Err((StageStatus::Failed, error)),
                    Err(WaitError::TimedOut) => Err((
                        StageStatus::TimedOut,
                        "HTTP header stage timed out".to_owned(),
                    )),
                    Err(WaitError::Cancelled) => {
                        Err((StageStatus::Cancelled, "Request cancelled".to_owned()))
                    }
                }
            }
        })
        .await
    } else {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let response = ({
            let (io, request, timeout, cancel, writes): (
                IoStream,
                Request<Full<Bytes>>,
                Duration,
                &CancellationToken,
                Arc<Mutex<Vec<u8>>>,
            ) = (
                io,
                request,
                trace.request.timeouts.headers,
                &cancel,
                writes.clone(),
            );
            async move {
                let io = TokioIo::new(RecordingIo { inner: io, writes });
                let operation = async {
                    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
                        .await
                        .map_err(|error| error.to_string())?;
                    tokio::spawn(async move {
                        let _ = connection.await;
                    });
                    sender
                        .send_request(request)
                        .await
                        .map_err(|error| error.to_string())
                };
                match wait_for(timeout, cancel, operation).await {
                    Ok(Ok(response)) => Ok(response),
                    Ok(Err(error)) => Err((StageStatus::Failed, error)),
                    Err(WaitError::TimedOut) => Err((
                        StageStatus::TimedOut,
                        "HTTP header stage timed out".to_owned(),
                    )),
                    Err(WaitError::Cancelled) => {
                        Err((StageStatus::Cancelled, "Request cancelled".to_owned()))
                    }
                }
            }
        })
        .await;
        trace.http.actual_http1_request_headers = {
            let (writes,): (&Arc<Mutex<Vec<u8>>>,) = (&writes,);
            {
                'inlined_captured_http1_headers: {
                    let writes = writes.lock().unwrap();
                    let end = match writes
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|position| position + 4)
                    {
                        Some(value) => value,
                        None => break 'inlined_captured_http1_headers None,
                    };
                    Some(Arc::from(&writes[..end]))
                }
            }
        };
        response
    };
    let response = match response {
        Ok(response) => response,
        Err((status, error)) => {
            return fail_trace(
                trace,
                StageKind::HttpHeaders,
                status,
                headers_started,
                error,
            );
        }
    };
    ({
        let (trace, response): (&mut DiagnosticTrace, &http::Response<Incoming>) =
            (&mut trace, &response);

        apply_response_parts(
            trace,
            response.status(),
            response.version(),
            response.headers(),
        );
    });
    let status_text = trace.status_text();
    finish_stage(
        &mut trace,
        StageKind::HttpHeaders,
        StageStatus::Succeeded,
        headers_started,
        status_text,
        &progress,
    );
    read_hyper_body(trace, response.into_body(), cancel, progress).await
}

pub(super) fn build_request(
    trace: &DiagnosticTrace,
    method: Method,
    mut headers: HeaderMap,
    version: Version,
) -> Result<Request<()>, String> {
    let uri = if version == Version::HTTP_11 {
        Uri::from_str(&trace.url.path_and_query)
    } else {
        Uri::from_str(&trace.url.normalized)
    }
    .map_err(|error| error.to_string())?;
    if matches!(version, Version::HTTP_2 | Version::HTTP_3) {
        headers.remove(HOST);
    }
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .version(version)
        .body(())
        .map_err(|error| error.to_string())?;
    *request.headers_mut() = headers;
    Ok(request)
}

pub(super) fn parse_request_headers(input: &str) -> Result<(HeaderMap, Vec<HeaderTrace>), String> {
    let mut headers = HeaderMap::new();
    let mut trace = Vec::new();
    for (index, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("Line {} must use 'Name: value' format", index + 1))?;
        let parsed_name = HeaderName::from_str(name.trim())
            .map_err(|error| format!("Invalid header name on line {}: {error}", index + 1))?;
        let parsed_value = HeaderValue::from_str(value.trim())
            .map_err(|error| format!("Invalid header value on line {}: {error}", index + 1))?;
        trace.push(HeaderTrace {
            name: name.trim().to_owned(),
            value: parsed_value.as_bytes().to_vec(),
            pseudo: false,
        });
        headers.append(parsed_name, parsed_value);
    }
    Ok((headers, trace))
}

pub(super) fn add_automatic_headers(
    url: &Url,
    headers: &mut HeaderMap,
    body_length: usize,
    user_agent: UserAgentPreset,
) {
    if !headers.contains_key(HOST)
        && let Ok(value) = HeaderValue::from_str(
            &({
                let (url,): (&Url,) = (url,);
                {
                    let host = match url.host() {
                        Some(url::Host::Ipv6(ip)) => format!("[{ip}]"),
                        Some(host) => host.to_string(),
                        None => String::new(),
                    };
                    match url.port() {
                        Some(port) => format!("{host}:{port}"),
                        None => host,
                    }
                }
            }),
        )
    {
        headers.insert(HOST, value);
    }
    if !headers.contains_key(CONTENT_LENGTH)
        && let Ok(value) = HeaderValue::from_str(&body_length.to_string())
    {
        headers.insert(CONTENT_LENGTH, value);
    }
    if !headers.contains_key(USER_AGENT)
        && let Some(value) = user_agent.header_value()
    {
        headers.insert(USER_AGENT, HeaderValue::from_static(value));
    }
}

pub(super) fn request_headers_for_version(
    trace: &DiagnosticTrace,
    headers: &HeaderMap,
    method: &Method,
    version: Version,
) -> Vec<HeaderTrace> {
    let mut result = Vec::new();
    if matches!(version, Version::HTTP_2 | Version::HTTP_3) {
        result.extend([
            HeaderTrace {
                name: ":method".to_owned(),
                value: method.as_str().as_bytes().to_vec(),
                pseudo: true,
            },
            HeaderTrace {
                name: ":scheme".to_owned(),
                value: trace.url.scheme.as_bytes().to_vec(),
                pseudo: true,
            },
            HeaderTrace {
                name: ":authority".to_owned(),
                value: ({
                    let (trace,): (&DiagnosticTrace,) = (trace,);
                    {
                        let host = if trace.url.host.contains(':') {
                            format!("[{}]", trace.url.host)
                        } else {
                            trace.url.host.clone()
                        };
                        let default_port = if trace.url.scheme == "https" { 443 } else { 80 };
                        if trace.url.port == default_port {
                            host
                        } else {
                            format!("{host}:{}", trace.url.port)
                        }
                    }
                })
                .into_bytes(),
                pseudo: true,
            },
            HeaderTrace {
                name: ":path".to_owned(),
                value: trace.url.path_and_query.as_bytes().to_vec(),
                pseudo: true,
            },
        ]);
    }
    result.extend(
        headers
            .iter()
            .filter(|(name, _)| {
                !(matches!(version, Version::HTTP_2 | Version::HTTP_3) && *name == HOST)
            })
            .map(|(name, value)| HeaderTrace {
                name: name.to_string(),
                value: value.as_bytes().to_vec(),
                pseudo: false,
            }),
    );
    result
}

pub(super) fn apply_response_parts(
    trace: &mut DiagnosticTrace,
    status: http::StatusCode,
    version: Version,
    headers: &HeaderMap,
) {
    trace.http.status = Some(status.as_u16());
    trace.http.reason = status.canonical_reason().map(str::to_owned);
    trace.http.version = Some(
        match version {
            Version::HTTP_09 => "HTTP/0.9",
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_2 => "HTTP/2",
            Version::HTTP_3 => "HTTP/3",
            _ => "Unknown",
        }
        .to_owned(),
    );
    trace.http.response_headers = (headers)
        .iter()
        .map(|(name, value)| crate::diagnostics::HeaderTrace {
            name: name.to_string(),
            value: value.as_bytes().to_vec(),
            pseudo: false,
        })
        .collect::<Vec<_>>();
    trace.body.content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    trace.body.content_encoding = headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
}

pub(super) fn apply_redirect_report(trace: &mut DiagnosticTrace) {
    if !trace
        .http
        .status
        .is_some_and(|status| (300..=399).contains(&status))
    {
        return;
    }
    let location_header = trace
        .http
        .response_headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(LOCATION.as_str()));
    let Some(location_header) = location_header else {
        trace.redirect_stop_reason = Some("Redirect response has no Location header".to_owned());
        return;
    };
    let displayed_location = location_header.display_value().into_owned();
    let Ok(location) = std::str::from_utf8(&location_header.value) else {
        trace.redirect_stop_reason = Some(format!(
            "Invalid redirect Location: {displayed_location}; redirect not followed"
        ));
        return;
    };
    let location = location.trim();
    if location.is_empty() {
        trace.redirect_stop_reason =
            Some("Redirect response has an empty Location header".to_owned());
        return;
    }
    let mut target = Url::parse(&trace.url.normalized)
        .ok()
        .and_then(|url| url.join(location).ok())
        .filter(|url| matches!(url.scheme(), "http" | "https"));
    if let Some(target) = &mut target {
        target.set_fragment(None);
    }
    trace.redirect_target = target.as_ref().map(Url::to_string);
    trace.redirect_stop_reason = Some(if trace.redirect_target.is_some() {
        if trace.request.follow_redirects {
            "Redirect is waiting for a follow-up request".to_owned()
        } else {
            "Redirect not followed (direct diagnostic mode)".to_owned()
        }
    } else {
        format!("Invalid redirect Location: {displayed_location}; redirect not followed")
    });
}
