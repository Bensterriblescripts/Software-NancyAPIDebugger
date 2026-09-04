use crate::diagnostics::{
    ConnectionOutcome, DiagnosticProgress, DiagnosticTrace, StageKind, StageStatus,
    format_byte_size,
};
use bytes::{Buf, Bytes};
use h3::error::Code;
use http::{HeaderMap, Method, Version};
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

use super::body::{BoundedCapture, finish_body};
use super::http::{apply_response_parts, build_request, request_headers_for_version};
use super::stages::{WaitError, begin_stage, fail_trace, finish_stage, wait_for};
use super::tls::{tls_trace_from_capture, tls_trace_from_quic};
use super::transport::connect_quic_all;

pub(super) async fn run(
    mut trace: DiagnosticTrace,
    method: Method,
    headers: HeaderMap,
    addresses: Vec<IpAddr>,
    cancel: CancellationToken,
    progress: Sender<DiagnosticProgress>,
) -> DiagnosticTrace {
    let quic_started = begin_stage(&mut trace, StageKind::QuicTls, &progress);
    let mut candidates = connect_quic_all(
        &addresses,
        trace.url.port,
        &trace.url.host,
        trace
            .request
            .timeouts
            .transport
            .saturating_add(trace.request.timeouts.tls),
        &cancel,
    )
    .await;
    let selected_index = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.connection.is_some())
        .min_by(|(_, a), (_, b)| a.attempt.duration_ms.total_cmp(&b.attempt.duration_ms))
        .map(|(index, _)| index);
    if let Some(index) = selected_index {
        candidates[index].attempt.selected = true;
    }
    trace.connections = candidates
        .iter()
        .map(|candidate| candidate.attempt.clone())
        .collect();
    let Some(selected_index) = selected_index else {
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| !candidate.capture.lock().unwrap().certificates.is_empty())
        {
            trace.tls = Some(tls_trace_from_capture(&trace.url.host, &candidate.capture));
        }
        let status = if cancel.is_cancelled() {
            StageStatus::Cancelled
        } else if trace
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
            StageKind::QuicTls,
            status,
            quic_started,
            "All QUIC connection attempts failed".to_owned(),
            &progress,
        );
    };
    let selected = &mut candidates[selected_index];
    let endpoint = selected.endpoint.take().unwrap();
    let connection = selected.connection.take().unwrap();
    trace.tls = Some(tls_trace_from_quic(
        &trace.url.host,
        &connection,
        &selected.capture,
    ));
    for (index, candidate) in candidates.iter().enumerate() {
        if index != selected_index
            && let Some(connection) = &candidate.connection
        {
            connection.close(0u32.into(), b"diagnostic probe complete");
        }
    }
    finish_stage(
        &mut trace,
        StageKind::QuicTls,
        StageStatus::Succeeded,
        quic_started,
        format!("Selected {}", connection.remote_address()),
        &progress,
    );

    trace.http.version = Some("HTTP/3".to_owned());
    trace.http.request_header_representation =
        "Decoded HTTP/3 header and pseudoheader fields".to_owned();
    trace.http.request_headers =
        request_headers_for_version(&trace, &headers, &method, Version::HTTP_3);
    let request = match build_request(&trace, method, headers, Version::HTTP_3) {
        Ok(request) => request.map(|_| ()),
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
    trace.http.headers_sent = true;
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut sender) = match h3::client::new(h3_connection).await {
        Ok(client) => client,
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
    let driver_task = tokio::spawn(async move { driver.wait_idle().await });
    let headers_started = begin_stage(&mut trace, StageKind::HttpHeaders, &progress);
    let send = async {
        let mut stream = sender
            .send_request(request)
            .await
            .map_err(|error| error.to_string())?;
        if !trace.request.body.is_empty() {
            stream
                .send_data(Bytes::copy_from_slice(&trace.request.body))
                .await
                .map_err(|error| error.to_string())?;
        }
        stream.finish().await.map_err(|error| error.to_string())?;
        let response = stream
            .recv_response()
            .await
            .map_err(|error| error.to_string())?;
        Ok::<_, String>((stream, response))
    };
    let (mut stream, response) = match wait_for(trace.request.timeouts.headers, &cancel, send).await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            driver_task.abort();
            return fail_trace(
                trace,
                StageKind::HttpHeaders,
                StageStatus::Failed,
                headers_started,
                error,
                &progress,
            );
        }
        Err(WaitError::TimedOut) => {
            driver_task.abort();
            return fail_trace(
                trace,
                StageKind::HttpHeaders,
                StageStatus::TimedOut,
                headers_started,
                "HTTP header stage timed out".to_owned(),
                &progress,
            );
        }
        Err(WaitError::Cancelled) => {
            driver_task.abort();
            return fail_trace(
                trace,
                StageKind::HttpHeaders,
                StageStatus::Cancelled,
                headers_started,
                "Request cancelled".to_owned(),
                &progress,
            );
        }
    };
    apply_response_parts(
        &mut trace,
        response.status(),
        response.version(),
        response.headers(),
    );
    let status_text = trace.status_text();
    finish_stage(
        &mut trace,
        StageKind::HttpHeaders,
        StageStatus::Succeeded,
        headers_started,
        status_text,
        &progress,
    );

    let mut captured_body = BoundedCapture::new();
    let first_started = begin_stage(&mut trace, StageKind::FirstByte, &progress);
    let first_data = async {
        loop {
            match stream.recv_data().await {
                Ok(Some(bytes)) if bytes.has_remaining() => return Ok(Some(bytes)),
                Ok(Some(_)) => continue,
                result => return result,
            }
        }
    };
    let first = wait_for(trace.request.timeouts.first_byte, &cancel, first_data).await;
    match first {
        Ok(Ok(Some(mut bytes))) => {
            while bytes.has_remaining() {
                let chunk = bytes.chunk();
                let truncated = captured_body.append(chunk);
                let length = chunk.len();
                bytes.advance(length);
                if truncated {
                    stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                    break;
                }
            }
            let length = captured_body.len();
            finish_stage(
                &mut trace,
                StageKind::FirstByte,
                StageStatus::Succeeded,
                first_started,
                format_byte_size(length),
                &progress,
            );
        }
        Ok(Ok(None)) => {
            finish_stage(
                &mut trace,
                StageKind::FirstByte,
                StageStatus::Skipped,
                first_started,
                "Response body is empty".to_owned(),
                &progress,
            );
        }
        Ok(Err(error)) => {
            driver_task.abort();
            return fail_trace(
                trace,
                StageKind::FirstByte,
                StageStatus::Failed,
                first_started,
                error.to_string(),
                &progress,
            );
        }
        Err(WaitError::TimedOut) => {
            driver_task.abort();
            return fail_trace(
                trace,
                StageKind::FirstByte,
                StageStatus::TimedOut,
                first_started,
                "First response byte timed out".to_owned(),
                &progress,
            );
        }
        Err(WaitError::Cancelled) => {
            driver_task.abort();
            return fail_trace(
                trace,
                StageKind::FirstByte,
                StageStatus::Cancelled,
                first_started,
                "Request cancelled".to_owned(),
                &progress,
            );
        }
    }

    let body_started = begin_stage(&mut trace, StageKind::Body, &progress);
    let body_timeout = trace.request.timeouts.body;
    let body_read = async {
        while !captured_body.is_truncated() {
            match stream.recv_data().await {
                Ok(Some(mut bytes)) => {
                    while bytes.has_remaining() {
                        let chunk = bytes.chunk();
                        let truncated = captured_body.append(chunk);
                        let length = chunk.len();
                        bytes.advance(length);
                        if truncated {
                            stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                            break;
                        }
                    }
                }
                Ok(None) => break,
                Err(error) => return Err(error.to_string()),
            }
        }
        if !captured_body.is_truncated()
            && let Some(trailers) = stream
                .recv_trailers()
                .await
                .map_err(|error| error.to_string())?
        {
            trace
                .http
                .response_trailers
                .extend(super::http::header_map_to_trace(&trailers));
        }
        Ok(())
    };
    match wait_for(body_timeout, &cancel, body_read).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            driver_task.abort();
            captured_body.store(&mut trace);
            return fail_trace(
                trace,
                StageKind::Body,
                StageStatus::Failed,
                body_started,
                error,
                &progress,
            );
        }
        Err(WaitError::TimedOut) => {
            driver_task.abort();
            captured_body.store(&mut trace);
            return fail_trace(
                trace,
                StageKind::Body,
                StageStatus::TimedOut,
                body_started,
                "Response body timed out".to_owned(),
                &progress,
            );
        }
        Err(WaitError::Cancelled) => {
            driver_task.abort();
            captured_body.store(&mut trace);
            return fail_trace(
                trace,
                StageKind::Body,
                StageStatus::Cancelled,
                body_started,
                "Request cancelled".to_owned(),
                &progress,
            );
        }
    }
    driver_task.abort();
    connection.close(0u32.into(), b"complete");
    endpoint.wait_idle().await;
    captured_body.store(&mut trace);
    finish_body(trace, body_started, progress)
}
