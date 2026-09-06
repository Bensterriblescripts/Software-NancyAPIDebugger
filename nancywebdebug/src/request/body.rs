use crate::diagnostics::{
    DiagnosticProgress, DiagnosticTrace, MAX_CAPTURE_BYTES, StageKind, StageStatus, TraceOutcome,
};
use bytes::Bytes;
use encoding_rs::{CoderResult, Encoding};
use hyper::body::Incoming;
use markup_fmt::{Language, config::FormatOptions, format_text};
use std::borrow::Cow;
use std::io::{Cursor, Read};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::Instant;
use tokio_util::sync::CancellationToken;

use super::http::apply_redirect_report;
use super::stages::{WaitError, begin_stage, fail_trace, finish_stage, set_stage, wait_for};

pub(super) struct BoundedCapture {
    pub(super) bytes: Vec<u8>,
    pub(super) truncated: bool,
}

impl BoundedCapture {
    pub(super) fn append(&mut self, chunk: &[u8]) -> bool {
        if chunk.is_empty() {
            return self.truncated;
        }
        let available = MAX_CAPTURE_BYTES.saturating_sub(self.bytes.len());
        let captured = available.min(chunk.len());
        let required = self.bytes.len() + captured;
        if required > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(required)
                .min(MAX_CAPTURE_BYTES);
            self.bytes.reserve_exact(capacity - self.bytes.len());
        }
        self.bytes.extend_from_slice(&chunk[..captured]);
        if captured < chunk.len() {
            self.truncated = true;
        }
        self.truncated
    }
}

pub(super) async fn read_hyper_body(
    mut trace: DiagnosticTrace,
    mut body: Incoming,
    cancel: CancellationToken,
    progress: Option<Sender<DiagnosticProgress>>,
) -> DiagnosticTrace {
    use http_body_util::BodyExt;

    let mut captured_body = BoundedCapture {
        bytes: Vec::new(),
        truncated: false,
    };
    let first_started = begin_stage(&mut trace, StageKind::FirstByte, &progress);
    let first_data = async {
        loop {
            match body.frame().await {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) if !data.is_empty() => return Ok::<Option<Bytes>, String>(Some(data)),
                    Ok(_) => continue,
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            trace.http.response_trailers.extend(
                                (&trailers)
                                    .iter()
                                    .map(|(name, value)| crate::diagnostics::HeaderTrace {
                                        name: name.to_string(),
                                        value: value.as_bytes().to_vec(),
                                        pseudo: false,
                                    })
                                    .collect::<Vec<_>>(),
                            );
                        }
                    }
                },
                Some(Err(error)) => return Err(error.to_string()),
                None => return Ok(None),
            }
        }
    };
    match wait_for(trace.request.timeouts.first_byte, &cancel, first_data).await {
        Ok(Ok(Some(data))) => {
            captured_body.append(&data);
            finish_stage(
                &mut trace,
                StageKind::FirstByte,
                StageStatus::Succeeded,
                first_started,
                {
                    let bytes: usize = data.len();
                    if bytes >= 1_000_000 {
                        format!("{:.2} MB", bytes as f64 / 1_000_000.0)
                    } else if bytes >= 1_000 {
                        format!("{:.2} KB", bytes as f64 / 1_000.0)
                    } else {
                        format!("{bytes} bytes")
                    }
                },
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
            return fail_trace(
                trace,
                StageKind::FirstByte,
                StageStatus::Failed,
                first_started,
                error,
            );
        }
        Err(WaitError::TimedOut) => {
            return fail_trace(
                trace,
                StageKind::FirstByte,
                StageStatus::TimedOut,
                first_started,
                "First response byte timed out".to_owned(),
            );
        }
        Err(WaitError::Cancelled) => {
            return fail_trace(
                trace,
                StageKind::FirstByte,
                StageStatus::Cancelled,
                first_started,
                "Request cancelled".to_owned(),
            );
        }
    }

    let body_started = begin_stage(&mut trace, StageKind::Body, &progress);
    let read = async {
        while !captured_body.truncated
            && let Some(frame) = body.frame().await
        {
            let frame = frame.map_err(|error| error.to_string())?;
            match frame.into_data() {
                Ok(data) => {
                    captured_body.append(&data);
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        trace.http.response_trailers.extend(
                            (&trailers)
                                .iter()
                                .map(|(name, value)| crate::diagnostics::HeaderTrace {
                                    name: name.to_string(),
                                    value: value.as_bytes().to_vec(),
                                    pseudo: false,
                                })
                                .collect::<Vec<_>>(),
                        );
                    }
                }
            }
        }
        Ok::<(), String>(())
    };
    match wait_for(trace.request.timeouts.body, &cancel, read).await {
        Ok(Ok(())) => {
            ({
                let trace: &mut crate::diagnostics::DiagnosticTrace = &mut trace;
                trace.body.raw = std::sync::Arc::from((captured_body).bytes);
                trace.body.raw_truncated = (captured_body).truncated;
            });
            finish_body(trace, body_started)
        }
        Ok(Err(error)) => {
            ({
                let trace: &mut crate::diagnostics::DiagnosticTrace = &mut trace;
                trace.body.raw = std::sync::Arc::from((captured_body).bytes);
                trace.body.raw_truncated = (captured_body).truncated;
            });
            fail_trace(
                trace,
                StageKind::Body,
                StageStatus::Failed,
                body_started,
                error,
            )
        }
        Err(WaitError::TimedOut) => {
            ({
                let trace: &mut crate::diagnostics::DiagnosticTrace = &mut trace;
                trace.body.raw = std::sync::Arc::from((captured_body).bytes);
                trace.body.raw_truncated = (captured_body).truncated;
            });
            fail_trace(
                trace,
                StageKind::Body,
                StageStatus::TimedOut,
                body_started,
                "Response body timed out".to_owned(),
            )
        }
        Err(WaitError::Cancelled) => {
            ({
                let trace: &mut crate::diagnostics::DiagnosticTrace = &mut trace;
                trace.body.raw = std::sync::Arc::from((captured_body).bytes);
                trace.body.raw_truncated = (captured_body).truncated;
            });
            fail_trace(
                trace,
                StageKind::Body,
                StageStatus::Cancelled,
                body_started,
                "Request cancelled".to_owned(),
            )
        }
    }
}

pub(super) fn finish_body(mut trace: DiagnosticTrace, started: Instant) -> DiagnosticTrace {
    decode_body(&mut trace);
    let detail = format!(
        "Raw: {}; decoded: {}",
        trace.body.raw_capture_status(),
        trace.body.decoded_capture_status()
    );
    set_stage(
        &mut trace,
        StageKind::Body,
        StageStatus::Succeeded,
        started,
        detail,
    );
    trace.outcome = TraceOutcome::Success;
    trace.complete = true;
    apply_redirect_report(&mut trace);
    trace
}

pub(super) fn decode_body(trace: &mut DiagnosticTrace) {
    trace.body.decoded = Arc::from("");
    trace.body.decoded_is_text = false;
    let (decoded_bytes, content_truncated, content_error) = {
        let (raw, encoding): (&'_ [u8], Option<&str>) =
            (&trace.body.raw, trace.body.content_encoding.as_deref());
        let inlined_result: (Cow<'_, [u8]>, bool, Option<String>) = {
            'inlined_decode_content_encoding: {
                let mut data = Cow::Borrowed(raw);
                let mut truncated = false;
                for encoding in encoding
                    .unwrap_or_default()
                    .rsplit(',')
                    .map(|value| value.trim().to_ascii_lowercase())
                    .filter(|value| !value.is_empty() && value != "identity")
                {
                    let (output, output_truncated, error) =
                        match encoding.as_str() {
                            "gzip" | "x-gzip" => {
                                let (mut reader, name): (_, &str) = (
                                    flate2::read::GzDecoder::new(Cursor::new(data.as_ref())),
                                    "gzip",
                                );
                                let inlined_result: (Vec<u8>, bool, Option<String>) = {
                                    'inlined_read_decoded_bounded: {
                                        let mut capture = BoundedCapture {
                                            bytes: Vec::new(),
                                            truncated: false,
                                        };
                                        let mut buffer = [0_u8; 64 * 1024];
                                        loop {
                                            match reader.read(&mut buffer) {
                                                Ok(0) => {
                                                    break 'inlined_read_decoded_bounded (
                                                        capture.bytes,
                                                        capture.truncated,
                                                        None,
                                                    );
                                                }
                                                Ok(length) if capture.append(&buffer[..length]) => {
                                                    break 'inlined_read_decoded_bounded (
                                                        capture.bytes,
                                                        true,
                                                        None,
                                                    );
                                                }
                                                Ok(_) => {}
                                                Err(error) => {
                                                    break 'inlined_read_decoded_bounded (
                                                        capture.bytes,
                                                        capture.truncated,
                                                        Some(format!(
                                                            "Unable to decode {name} body: {error}"
                                                        )),
                                                    );
                                                }
                                            }
                                        }
                                    }
                                };
                                inlined_result
                            }
                            "deflate" => {
                                let (mut reader, name): (_, &str) = (
                                    flate2::read::ZlibDecoder::new(Cursor::new(data.as_ref())),
                                    "deflate",
                                );
                                let inlined_result: (Vec<u8>, bool, Option<String>) = {
                                    'inlined_read_decoded_bounded: {
                                        let mut capture = BoundedCapture {
                                            bytes: Vec::new(),
                                            truncated: false,
                                        };
                                        let mut buffer = [0_u8; 64 * 1024];
                                        loop {
                                            match reader.read(&mut buffer) {
                                                Ok(0) => {
                                                    break 'inlined_read_decoded_bounded (
                                                        capture.bytes,
                                                        capture.truncated,
                                                        None,
                                                    );
                                                }
                                                Ok(length) if capture.append(&buffer[..length]) => {
                                                    break 'inlined_read_decoded_bounded (
                                                        capture.bytes,
                                                        true,
                                                        None,
                                                    );
                                                }
                                                Ok(_) => {}
                                                Err(error) => {
                                                    break 'inlined_read_decoded_bounded (
                                                        capture.bytes,
                                                        capture.truncated,
                                                        Some(format!(
                                                            "Unable to decode {name} body: {error}"
                                                        )),
                                                    );
                                                }
                                            }
                                        }
                                    }
                                };
                                inlined_result
                            }
                            "br" => {
                                let (mut reader, name): (_, &str) = (
                                    brotli::Decompressor::new(Cursor::new(data.as_ref()), 4096),
                                    "Brotli",
                                );
                                let inlined_result: (Vec<u8>, bool, Option<String>) = {
                                    'inlined_read_decoded_bounded: {
                                        let mut capture = BoundedCapture {
                                            bytes: Vec::new(),
                                            truncated: false,
                                        };
                                        let mut buffer = [0_u8; 64 * 1024];
                                        loop {
                                            match reader.read(&mut buffer) {
                                                Ok(0) => {
                                                    break 'inlined_read_decoded_bounded (
                                                        capture.bytes,
                                                        capture.truncated,
                                                        None,
                                                    );
                                                }
                                                Ok(length) if capture.append(&buffer[..length]) => {
                                                    break 'inlined_read_decoded_bounded (
                                                        capture.bytes,
                                                        true,
                                                        None,
                                                    );
                                                }
                                                Ok(_) => {}
                                                Err(error) => {
                                                    break 'inlined_read_decoded_bounded (
                                                        capture.bytes,
                                                        capture.truncated,
                                                        Some(format!(
                                                            "Unable to decode {name} body: {error}"
                                                        )),
                                                    );
                                                }
                                            }
                                        }
                                    }
                                };
                                inlined_result
                            }
                            "zstd" => {
                                match zstd::stream::read::Decoder::new(Cursor::new(data.as_ref())) {
                                    Ok(decoder) => {
                                        let (mut reader, name): (_, &str) = (decoder, "Zstandard");
                                        let inlined_result: (Vec<u8>, bool, Option<String>) =
                                            {
                                                'inlined_read_decoded_bounded: {
                                                    let mut capture = BoundedCapture {
                                                        bytes: Vec::new(),
                                                        truncated: false,
                                                    };
                                                    let mut buffer = [0_u8; 64 * 1024];
                                                    loop {
                                                        match reader.read(&mut buffer) {
            Ok(0) => break 'inlined_read_decoded_bounded (capture.bytes, capture.truncated, None),
            Ok(length) if capture.append(&buffer[..length]) => {
                break 'inlined_read_decoded_bounded (capture.bytes, true, None);
            }
            Ok(_) => {}
            Err(error) => {
                break 'inlined_read_decoded_bounded (
                    capture.bytes,
                    capture.truncated,
                    Some(format!("Unable to decode {name} body: {error}")),
                );
            }
        }
                                                    }
                                                }
                                            };
                                        inlined_result
                                    }
                                    Err(error) => {
                                        break 'inlined_decode_content_encoding (
                                            data,
                                            truncated,
                                            Some(format!(
                                                "Unable to initialise Zstandard decoder: {error}"
                                            )),
                                        );
                                    }
                                }
                            }
                            other => {
                                break 'inlined_decode_content_encoding (
                                    data,
                                    truncated,
                                    Some(format!("Unsupported content encoding: {other}")),
                                );
                            }
                        };
                    truncated |= output_truncated;
                    if let Some(error) = error {
                        break 'inlined_decode_content_encoding (
                            if output.is_empty() {
                                data
                            } else {
                                Cow::Owned(output)
                            },
                            truncated,
                            Some(error),
                        );
                    }
                    data = Cow::Owned(output);
                }
                (data, truncated, None)
            }
        };
        inlined_result
    };
    trace.body.decode_error = content_error;
    trace.body.decoded_truncated = trace.body.raw_truncated || content_truncated;
    if trace.body.decode_error.is_some() {
        return;
    }
    let charset = match {
        let (content_type,): (Option<&str>,) = (trace.body.content_type.as_deref(),);
        let inlined_result: Result<Option<&'static encoding_rs::Encoding>, String> = {
            'inlined_text_charset: {
                let Some(content_type) = content_type else {
                    break 'inlined_text_charset Ok(None);
                };
                let mut parts = content_type.split(';');
                let media_type = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
                let charset = parts.find_map(|part| {
                    let (name, value) = part.trim().split_once('=')?;
                    name.trim()
                        .eq_ignore_ascii_case("charset")
                        .then(|| value.trim().trim_matches(['\'', '"']))
                });
                if let Some(charset) = charset {
                    break 'inlined_text_charset encoding_rs::Encoding::for_label(
                        charset.as_bytes(),
                    )
                    .map(Some)
                    .ok_or_else(|| format!("Unsupported response charset: {charset}"));
                }
                let textual = media_type.starts_with("text/")
                    || matches!(
                        media_type.as_str(),
                        "application/json"
                            | "application/xml"
                            | "application/xhtml+xml"
                            | "application/javascript"
                            | "application/x-javascript"
                            | "application/x-www-form-urlencoded"
                    )
                    || media_type.ends_with("+json")
                    || media_type.ends_with("+xml");
                Ok(textual.then_some(encoding_rs::UTF_8))
            }
        };
        inlined_result
    } {
        Ok(Some(charset)) => charset,
        Ok(None) => return,
        Err(error) => {
            ({
                let (destination, error): (&mut Option<String>, String) =
                    (&mut trace.body.decode_error, error);

                *destination = Some(match destination.take() {
                    Some(existing) => format!("{existing}; {error}"),
                    None => error,
                });
            });
            return;
        }
    };
    let (text, text_truncated, had_errors) = {
        let (charset, bytes): (&'static Encoding, &[u8]) = (charset, &decoded_bytes);
        let inlined_result: (String, bool, bool) = {
            'inlined_decode_text_bounded: {
                let work_limit = MAX_CAPTURE_BYTES + 4;
                let mut decoder = charset.new_decoder_without_bom_handling();
                let initial_capacity = bytes.len().saturating_add(4).clamp(1, work_limit);
                let mut output = String::with_capacity(initial_capacity);
                let mut offset = 0;
                let mut had_errors = false;
                loop {
                    let (result, read, errors) =
                        decoder.decode_to_string(&bytes[offset..], &mut output, true);
                    offset += read;
                    had_errors |= errors;
                    match result {
                        CoderResult::InputEmpty => {
                            break 'inlined_decode_text_bounded (output, false, had_errors);
                        }
                        CoderResult::OutputFull if output.capacity() >= work_limit => {
                            break 'inlined_decode_text_bounded (output, true, had_errors);
                        }
                        CoderResult::OutputFull => {
                            let capacity = output.capacity();
                            let next_capacity =
                                capacity.saturating_mul(2).max(capacity + 1).min(work_limit);
                            output.reserve_exact(next_capacity - output.len());
                        }
                    }
                }
            }
        };
        inlined_result
    };
    if had_errors {
        ({
            let (destination, error): (&mut Option<String>, String) = (
                &mut trace.body.decode_error,
                format!(
                    "Invalid {} sequences were replaced with \u{FFFD}; original bytes are available in Raw / Hex",
                    charset.name()
                ),
            );

            *destination = Some(match destination.take() {
                Some(existing) => format!("{existing}; {error}"),
                None => error,
            });
        });
    }
    trace.body.decoded_truncated |= text_truncated;
    let mut formatted = if text.len() <= 256 * 1024 {
        {
            let (body, content_type): (&str, Option<&str>) =
                (&text, trace.body.content_type.as_deref());
            {
                'inlined_format_response_body: {
                    if body.is_empty() {
                        break 'inlined_format_response_body String::new();
                    }
                    let media_type = content_type
                        .and_then(|value| value.split(';').next())
                        .map(str::trim)
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if media_type == "application/json"
                        || media_type == "text/json"
                        || media_type.ends_with("+json")
                    {
                        break 'inlined_format_response_body serde_json::from_str::<
                            serde_json::Value,
                        >(body)
                        .and_then(|value| serde_json::to_string_pretty(&value))
                        .unwrap_or_else(|_| body.to_owned());
                    }
                    let language =
                        if media_type == "text/html" || media_type == "application/xhtml+xml" {
                            Some(Language::Html)
                        } else if media_type == "application/xml"
                            || media_type == "text/xml"
                            || media_type.ends_with("+xml")
                        {
                            Some(Language::Xml)
                        } else {
                            None
                        };
                    language
                        .and_then(|language| {
                            format_text(body, language, &FormatOptions::default(), |code, _| {
                                Ok(code.into())
                            })
                            .ok()
                        })
                        .unwrap_or_else(|| body.to_owned())
                }
            }
        }
    } else {
        text
    };
    if formatted.len() > MAX_CAPTURE_BYTES {
        let mut end = MAX_CAPTURE_BYTES;
        while !formatted.is_char_boundary(end) {
            end -= 1;
        }
        formatted.truncate(end);
        trace.body.decoded_truncated = true;
    }
    trace.body.decoded = Arc::from(formatted);
    trace.body.decoded_is_text = true;
}
