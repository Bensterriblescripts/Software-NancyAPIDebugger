use crate::diagnostics::{DiagnosticTrace, FingerprintStatus, FingerprintTrace, TraceOutcome};
use crate::web_server::detect_web_servers;

pub(super) fn analyze(trace: &mut DiagnosticTrace) {
    if !trace.request.fingerprint_server {
        trace.fingerprint = FingerprintTrace {
            status: FingerprintStatus::Disabled,
            web_server: "Unknown".to_owned(),
            confidence: "None".to_owned(),
            evidence: Vec::new(),
        };
        return;
    }

    let mut evidence = contextual_evidence(trace);
    let server_headers = observed_headers(trace, "server");
    for value in &server_headers {
        evidence.push(format!("Observed Server header: {value}"));
    }
    for name in ["Via", "X-Powered-By"] {
        for value in observed_headers(trace, name) {
            evidence.push(format!("Observed {name} header: {value}"));
        }
    }

    let fingerprint_headers = trace
        .http
        .response_headers
        .iter()
        .map(|header| (header.name.clone(), header.display_value().into_owned()))
        .collect::<Vec<_>>();
    let detections = detect_web_servers(
        fingerprint_headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        if trace.body.decoded_is_text {
            trace.body.decoded.as_bytes()
        } else {
            &trace.body.raw
        },
    );
    for detection in &detections {
        for item in &detection.evidence {
            let item = format!("{} fingerprint evidence: {item}", detection.product);
            if !evidence.contains(&item) {
                evidence.push(item);
            }
        }
    }

    let response_available = trace.http.status.is_some();
    let (status, web_server, confidence) = if response_available {
        if let Some(detection) = detections.first() {
            (
                FingerprintStatus::Detected,
                detection.display_identity(),
                detection.confidence.to_string(),
            )
        } else if let Some(server) = server_headers.into_iter().next() {
            (
                FingerprintStatus::Detected,
                server,
                "Unverified self-reported Server header".to_owned(),
            )
        } else {
            evidence.push("No Server header was present in the response".to_owned());
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
        let detail = trace
            .error
            .as_ref()
            .map(|error| format!("No HTTP response was available: {}", error.message))
            .unwrap_or_else(|| "No HTTP response was available".to_owned());
        evidence.push(detail);
        (status, "Unknown".to_owned(), "None".to_owned())
    };

    trace.fingerprint = FingerprintTrace {
        status,
        web_server,
        confidence,
        evidence,
    };
}

fn contextual_evidence(trace: &DiagnosticTrace) -> Vec<String> {
    let endpoint = trace
        .connections
        .iter()
        .find(|attempt| attempt.selected)
        .map(|attempt| attempt.remote.to_string())
        .unwrap_or_else(|| "Not available".to_owned());
    let http_version = trace.http.version.as_deref().unwrap_or("Not available");
    let tls_version = trace
        .tls
        .as_ref()
        .and_then(|tls| tls.version.as_deref())
        .unwrap_or("Not available");
    let alpn = trace
        .tls
        .as_ref()
        .and_then(|tls| tls.alpn.as_deref())
        .unwrap_or("Not available");

    vec![
        format!("Selected endpoint: {endpoint}"),
        format!("Negotiated HTTP version: {http_version}"),
        format!("TLS version: {tls_version}"),
        format!("ALPN: {alpn}"),
    ]
}

fn observed_headers(trace: &DiagnosticTrace, name: &str) -> Vec<String> {
    trace
        .http
        .response_headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.display_value().trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}
