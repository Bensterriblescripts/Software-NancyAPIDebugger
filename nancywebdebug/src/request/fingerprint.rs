use crate::diagnostics::{DiagnosticTrace, FingerprintStatus, FingerprintTrace, TraceOutcome};
use crate::web_server::detect_primary_web_server;

pub(super) fn analyze(trace: &mut DiagnosticTrace) {
    let fingerprint_headers = trace
        .http
        .response_headers
        .iter()
        .map(|header| (header.name.as_str(), header.display_value()))
        .collect::<Vec<_>>();
    let detection = detect_primary_web_server(
        fingerprint_headers
            .iter()
            .map(|(name, value)| (*name, value.as_ref())),
        if trace.body.decoded_is_text {
            trace.body.decoded.as_bytes()
        } else {
            &trace.body.raw
        },
        trace.http.status,
    );

    let response_available = trace.http.status.is_some();
    let (status, web_server, confidence) = if response_available {
        if let Some(detection) = detection {
            (
                FingerprintStatus::Detected,
                detection.display_identity(),
                detection.confidence.to_string(),
            )
        } else if let Some(server) = observed_header(trace, "server") {
            (
                FingerprintStatus::Detected,
                server,
                "Unverified self-reported Server header".to_owned(),
            )
        } else {
            (
                FingerprintStatus::Unknown,
                "Unknown".to_owned(),
                "No server identity reported".to_owned(),
            )
        }
    } else {
        let status = match trace.outcome {
            TraceOutcome::TimedOut => FingerprintStatus::TimedOut,
            TraceOutcome::Cancelled => FingerprintStatus::Cancelled,
            _ => FingerprintStatus::Unavailable,
        };
        (status, "Unknown".to_owned(), "None".to_owned())
    };

    trace.fingerprint = FingerprintTrace {
        status,
        web_server,
        confidence,
    };
}

fn observed_header(trace: &DiagnosticTrace, name: &str) -> Option<String> {
    trace
        .http
        .response_headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.display_value().trim().to_owned())
        .find(|value| !value.is_empty())
}
