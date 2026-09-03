use crate::diagnostics::{
    DiagnosticProgress, DiagnosticTrace, StageKind, StageStatus, TraceOutcome,
};
use bytes::Bytes;
use encoding_rs::{DecoderResult, Encoding};
use hyper::body::Incoming;
use markup_fmt::{Language, config::FormatOptions, format_text};
use std::io::{Cursor, Read};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::Instant;
use tokio_util::sync::CancellationToken;

use super::http::{apply_redirect_report, header_map_to_trace};
use super::stages::{WaitError, begin_stage, fail_trace, finish_stage, set_stage, wait_for};

pub(super) const MAX_CAPTURE_BYTES: usize = 50 * 1024 * 1024;

pub(super) struct BoundedCapture {
    bytes: Vec<u8>,
    truncated: bool,
}

impl BoundedCapture {
    pub(super) fn new() -> Self {
        Self {
            bytes: Vec::new(),
            truncated: false,
        }
    }

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

    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(super) fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub(super) fn store(self, trace: &mut DiagnosticTrace) {
        trace.body.raw = Arc::from(self.bytes);
        trace.body.raw_truncated = self.truncated;
    }
}

pub(super) async fn read_hyper_body(
    mut trace: DiagnosticTrace,
    mut body: Incoming,
    cancel: CancellationToken,
    progress: Sender<DiagnosticProgress>,
) -> DiagnosticTrace {
    use http_body_util::BodyExt;

    let mut captured_body = BoundedCapture::new();
    let first_started = begin_stage(&mut trace, StageKind::FirstByte, &progress);
    let first_data = async {
        loop {
            match body.frame().await {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) if !data.is_empty() => return Ok::<Option<Bytes>, String>(Some(data)),
                    Ok(_) => continue,
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            trace
                                .http
                                .response_trailers
                                .extend(header_map_to_trace(&trailers));
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
                format!("{} byte(s)", data.len()),
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
                &progress,
            );
        }
        Err(WaitError::TimedOut) => {
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
                        trace
                            .http
                            .response_trailers
                            .extend(header_map_to_trace(&trailers));
                    }
                }
            }
        }
        Ok::<(), String>(())
    };
    match wait_for(trace.request.timeouts.body, &cancel, read).await {
        Ok(Ok(())) => {
            captured_body.store(&mut trace);
            finish_body(trace, body_started, progress)
        }
        Ok(Err(error)) => {
            captured_body.store(&mut trace);
            fail_trace(
                trace,
                StageKind::Body,
                StageStatus::Failed,
                body_started,
                error,
                &progress,
            )
        }
        Err(WaitError::TimedOut) => {
            captured_body.store(&mut trace);
            fail_trace(
                trace,
                StageKind::Body,
                StageStatus::TimedOut,
                body_started,
                "Response body timed out".to_owned(),
                &progress,
            )
        }
        Err(WaitError::Cancelled) => {
            captured_body.store(&mut trace);
            fail_trace(
                trace,
                StageKind::Body,
                StageStatus::Cancelled,
                body_started,
                "Request cancelled".to_owned(),
                &progress,
            )
        }
    }
}

pub(super) fn finish_body(
    mut trace: DiagnosticTrace,
    started: Instant,
    _progress: Sender<DiagnosticProgress>,
) -> DiagnosticTrace {
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
    let (decoded_bytes, content_truncated, content_error) =
        decode_content_encoding(&trace.body.raw, trace.body.content_encoding.as_deref());
    trace.body.decode_error = content_error;
    trace.body.decoded_truncated = trace.body.raw_truncated || content_truncated;
    if trace.body.decode_error.is_some() {
        return;
    }
    let charset = match text_charset(trace.body.content_type.as_deref()) {
        Ok(Some(charset)) => charset,
        Ok(None) => return,
        Err(error) => {
            append_decode_error(&mut trace.body.decode_error, error);
            return;
        }
    };
    let (text, text_truncated) = match decode_text_bounded(charset, &decoded_bytes) {
        Ok(result) => result,
        Err(()) => {
            append_decode_error(
                &mut trace.body.decode_error,
                format!("Body is not valid {} text; use Raw / Hex", charset.name()),
            );
            return;
        }
    };
    trace.body.decoded_truncated |= text_truncated;
    let mut formatted = if text.len() <= 256 * 1024 {
        format_response_body(&text, trace.body.content_type.as_deref())
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

fn decode_text_bounded(charset: &'static Encoding, bytes: &[u8]) -> Result<(String, bool), ()> {
    let work_limit = MAX_CAPTURE_BYTES + 4;
    let mut decoder = charset.new_decoder_without_bom_handling();
    let initial_capacity = bytes.len().saturating_add(4).clamp(1, work_limit);
    let mut output = String::with_capacity(initial_capacity);
    let mut offset = 0;
    loop {
        let (result, read) =
            decoder.decode_to_string_without_replacement(&bytes[offset..], &mut output, true);
        offset += read;
        match result {
            DecoderResult::InputEmpty => return Ok((output, false)),
            DecoderResult::Malformed(_, _) => return Err(()),
            DecoderResult::OutputFull if output.capacity() >= work_limit => {
                return Ok((output, true));
            }
            DecoderResult::OutputFull => {
                let capacity = output.capacity();
                let next_capacity = capacity.saturating_mul(2).max(capacity + 1).min(work_limit);
                output.reserve_exact(next_capacity - output.len());
            }
        }
    }
}

fn append_decode_error(destination: &mut Option<String>, error: String) {
    *destination = Some(match destination.take() {
        Some(existing) => format!("{existing}; {error}"),
        None => error,
    });
}

fn text_charset(
    content_type: Option<&str>,
) -> Result<Option<&'static encoding_rs::Encoding>, String> {
    let Some(content_type) = content_type else {
        return Ok(None);
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
        return encoding_rs::Encoding::for_label(charset.as_bytes())
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

fn decode_content_encoding(raw: &[u8], encoding: Option<&str>) -> (Vec<u8>, bool, Option<String>) {
    let mut data = raw.to_vec();
    let mut truncated = false;
    let encodings = encoding
        .unwrap_or_default()
        .split(',')
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty() && value != "identity")
        .collect::<Vec<_>>();
    for encoding in encodings.iter().rev() {
        let (output, output_truncated, error) = match encoding.as_str() {
            "gzip" | "x-gzip" => {
                read_decoded_bounded(flate2::read::GzDecoder::new(Cursor::new(&data)), "gzip")
            }
            "deflate" => read_decoded_bounded(
                flate2::read::ZlibDecoder::new(Cursor::new(&data)),
                "deflate",
            ),
            "br" => read_decoded_bounded(
                brotli::Decompressor::new(Cursor::new(&data), 4096),
                "Brotli",
            ),
            "zstd" => match zstd::stream::read::Decoder::new(Cursor::new(&data)) {
                Ok(decoder) => read_decoded_bounded(decoder, "Zstandard"),
                Err(error) => {
                    return (
                        data,
                        truncated,
                        Some(format!("Unable to initialise Zstandard decoder: {error}")),
                    );
                }
            },
            other => {
                return (
                    data,
                    truncated,
                    Some(format!("Unsupported content encoding: {other}")),
                );
            }
        };
        truncated |= output_truncated;
        if let Some(error) = error {
            return (
                if output.is_empty() { data } else { output },
                truncated,
                Some(error),
            );
        }
        data = output;
    }
    (data, truncated, None)
}

fn read_decoded_bounded<R: Read>(mut reader: R, name: &str) -> (Vec<u8>, bool, Option<String>) {
    let mut capture = BoundedCapture::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return (capture.bytes, capture.truncated, None),
            Ok(length) if capture.append(&buffer[..length]) => {
                return (capture.bytes, true, None);
            }
            Ok(_) => {}
            Err(error) => {
                return (
                    capture.bytes,
                    capture.truncated,
                    Some(format!("Unable to decode {name} body: {error}")),
                );
            }
        }
    }
}

fn format_response_body(body: &str, content_type: Option<&str>) -> String {
    if body.is_empty() {
        return String::new();
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
        return serde_json::from_str::<serde_json::Value>(body)
            .and_then(|value| serde_json::to_string_pretty(&value))
            .unwrap_or_else(|_| body.to_owned());
    }
    let language = if media_type == "text/html" || media_type == "application/xhtml+xml" {
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
