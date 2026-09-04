use crate::auth::AuthStore;
use crate::diagnostics::{
    DiagnosticRequest, DiagnosticTrace, HeaderTrace, ProtocolPreference, TraceOutcome,
    escaped_bytes, format_byte_size,
};
use crate::request::run_diagnostic_session;
use clap::{Parser, ValueEnum};
use http::{HeaderName, HeaderValue, Method};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "nancywebdebug-cli",
    version,
    about = "Inspect an HTTP request across DNS, connection, TLS, headers, and body stages"
)]
struct Arguments {
    #[arg(short = 'X', long, default_value = "GET", value_parser = parse_method)]
    method: String,
    #[arg(short = 'H', long, value_name = "Name: value", value_parser = parse_header)]
    header: Vec<String>,
    #[arg(long, value_name = "PATH")]
    body_file: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "auto")]
    protocol: CliProtocol,
    #[arg(long)]
    no_follow_redirects: bool,
    #[arg(long)]
    fingerprint_server: bool,
    #[arg(value_name = "URL")]
    url: String,
}

#[derive(Clone, Copy, ValueEnum)]
enum CliProtocol {
    #[value(name = "auto")]
    Auto,
    #[value(name = "http1.1")]
    Http11,
    #[value(name = "http2")]
    Http2,
    #[value(name = "http3")]
    Http3,
}

impl From<CliProtocol> for ProtocolPreference {
    fn from(value: CliProtocol) -> Self {
        match value {
            CliProtocol::Auto => Self::Auto,
            CliProtocol::Http11 => Self::Http11,
            CliProtocol::Http2 => Self::Http2,
            CliProtocol::Http3 => Self::Http3,
        }
    }
}

pub(crate) fn run() -> ExitCode {
    let arguments = Arguments::parse();
    let body = match arguments.body_file {
        Some(path) => match std::fs::read(&path) {
            Ok(body) => Arc::from(body),
            Err(error) => {
                eprintln!(
                    "error: unable to read body file '{}': {error}",
                    path.display()
                );
                return ExitCode::from(2);
            }
        },
        None => Arc::from([]),
    };
    let mut request = DiagnosticRequest::new(arguments.url);
    request.method = arguments.method;
    request.headers = arguments.header.join("\n");
    request.body = body;
    request.protocol = arguments.protocol.into();
    request.follow_redirects = !arguments.no_follow_redirects;
    request.fingerprint_server = arguments.fingerprint_server;

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: unable to create async runtime: {error}");
            return ExitCode::from(1);
        }
    };
    let cancel = CancellationToken::new();
    let traces = runtime.block_on(async {
        let signal_cancel = cancel.clone();
        let signal_task = tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                signal_cancel.cancel();
            }
        });
        let traces = run_diagnostic_session(1, request, AuthStore::shared(), cancel, None).await;
        signal_task.abort();
        traces
    });

    let report = render_report(&traces);
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = stdout
        .write_all(report.as_bytes())
        .and_then(|_| stdout.flush())
    {
        eprintln!("error: unable to write report: {error}");
        return ExitCode::from(1);
    }
    if traces
        .iter()
        .all(|trace| trace.outcome == TraceOutcome::Success)
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn parse_method(value: &str) -> Result<String, String> {
    Method::from_bytes(value.as_bytes())
        .map(|method| method.as_str().to_owned())
        .map_err(|error| error.to_string())
}

fn parse_header(value: &str) -> Result<String, String> {
    if value.contains(['\r', '\n']) {
        return Err("header must be a single 'Name: value' line".to_owned());
    }
    let (name, value_part) = value
        .split_once(':')
        .ok_or_else(|| "header must use 'Name: value' format".to_owned())?;
    HeaderName::from_str(name.trim()).map_err(|error| format!("invalid header name: {error}"))?;
    HeaderValue::from_str(value_part.trim())
        .map_err(|error| format!("invalid header value: {error}"))?;
    Ok(value.to_owned())
}

fn render_report(traces: &[DiagnosticTrace]) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Nancy Web Debugger diagnostic report");
    let _ = writeln!(output, "Completed hops: {}", traces.len());
    for (hop, trace) in traces.iter().enumerate() {
        let _ = writeln!(output, "\n{}", "=".repeat(72));
        let _ = writeln!(output, "Hop {} (trace #{})", hop + 1, trace.index);
        let _ = writeln!(output, "{}", "=".repeat(72));
        render_trace(&mut output, trace);
    }
    output
}

fn render_trace(output: &mut String, trace: &DiagnosticTrace) {
    let _ = writeln!(output, "Outcome: {}", trace.outcome);
    let _ = writeln!(
        output,
        "Complete: {}",
        if trace.complete { "Yes" } else { "No" }
    );
    let _ = writeln!(output, "Web server: {}", trace.fingerprint.web_server);
    let _ = writeln!(output, "Fingerprint status: {}", trace.fingerprint.status);
    let _ = writeln!(output, "Confidence: {}", trace.fingerprint.confidence);
    if trace.fingerprint.evidence.is_empty() {
        let _ = writeln!(output, "Evidence: None");
    } else {
        let _ = writeln!(output, "Evidence:");
        for evidence in &trace.fingerprint.evidence {
            let _ = writeln!(output, "  {evidence}");
        }
    }
    if let Some(error) = &trace.error {
        let _ = writeln!(output, "Error: {}: {}", error.stage, error.message);
    } else {
        let _ = writeln!(output, "Error: None");
    }
    let _ = writeln!(output, "Method: {}", trace.request.method);
    let _ = writeln!(
        output,
        "Request body: {}",
        format_byte_size(trace.request.body.len())
    );

    let _ = writeln!(output, "\nStage timings");
    for stage in &trace.stages {
        match stage.duration_ms {
            Some(duration) => {
                let _ = write!(
                    output,
                    "  {}: {} ({duration:.2} ms)",
                    stage.kind, stage.status
                );
            }
            None => {
                let _ = write!(output, "  {}: {}", stage.kind, stage.status);
            }
        }
        if !stage.detail.is_empty() {
            let _ = write!(output, " - {}", stage.detail);
        }
        output.push('\n');
    }

    let _ = writeln!(output, "\nURL");
    let _ = writeln!(output, "  Input: {}", trace.request.url);
    let _ = writeln!(
        output,
        "  Normalized: {}",
        value_or_none(&trace.url.normalized)
    );
    let _ = writeln!(output, "  Scheme: {}", value_or_none(&trace.url.scheme));
    let _ = writeln!(output, "  Host: {}", value_or_none(&trace.url.host));
    let _ = writeln!(output, "  Port: {}", trace.url.port);
    let _ = writeln!(
        output,
        "  Path and query: {}",
        value_or_none(&trace.url.path_and_query)
    );

    let _ = writeln!(output, "\nDNS");
    render_string_list(
        output,
        "Configured resolvers",
        &trace.dns.configured_resolvers,
    );
    let addresses = trace
        .dns
        .addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    render_string_list(output, "Addresses", &addresses);
    let _ = writeln!(output, "  Attempts: {}", trace.dns.attempts.len());
    for (index, attempt) in trace.dns.attempts.iter().enumerate() {
        let _ = writeln!(
            output,
            "    {}. {} via {} ({}, {:.2} ms)",
            index + 1,
            attempt.record_type,
            attempt.configured_resolver,
            attempt.transport,
            attempt.duration_ms
        );
        let _ = writeln!(
            output,
            "       Responder: {}; response: {}; error: {}",
            attempt
                .responder
                .map(|value| value.to_string())
                .unwrap_or_else(|| "None".to_owned()),
            attempt.response_code.as_deref().unwrap_or("None"),
            attempt.error.as_deref().unwrap_or("None")
        );
    }
    let _ = writeln!(output, "  Records: {}", trace.dns.records.len());
    for record in &trace.dns.records {
        let _ = writeln!(
            output,
            "    {} {} {}s {}",
            record.name, record.record_type, record.ttl, record.value
        );
    }

    let _ = writeln!(output, "\nConnections");
    let _ = writeln!(output, "  Mode: {}", trace.connection_mode);
    if trace.connections.is_empty() {
        let _ = writeln!(output, "  Attempts: None captured");
    }
    for (index, attempt) in trace.connections.iter().enumerate() {
        let _ = writeln!(
            output,
            "  {}. {} {} -> {} ({:.2} ms, {}, selected: {})",
            index + 1,
            attempt.family,
            attempt
                .local
                .map(|value| value.to_string())
                .unwrap_or_else(|| "None".to_owned()),
            attempt.remote,
            attempt.duration_ms,
            attempt.outcome,
            if attempt.selected { "Yes" } else { "No" }
        );
        let _ = writeln!(
            output,
            "     Error: {}; OS error: {}",
            attempt.error.as_deref().unwrap_or("None"),
            attempt
                .os_error
                .map(|value| value.to_string())
                .unwrap_or_else(|| "None".to_owned())
        );
    }

    let _ = writeln!(output, "\nTLS and certificates");
    if let Some(tls) = &trace.tls {
        let _ = writeln!(output, "  Server name: {}", value_or_none(&tls.server_name));
        let _ = writeln!(
            output,
            "  Version: {}",
            tls.version.as_deref().unwrap_or("None")
        );
        let _ = writeln!(
            output,
            "  Cipher suite: {}",
            tls.cipher_suite.as_deref().unwrap_or("None")
        );
        let _ = writeln!(output, "  ALPN: {}", tls.alpn.as_deref().unwrap_or("None"));
        let _ = writeln!(
            output,
            "  Validation: {}",
            tls.validation.as_deref().unwrap_or("None")
        );
        let _ = writeln!(
            output,
            "  Validation error: {}",
            tls.validation_error.as_deref().unwrap_or("None")
        );
        let _ = writeln!(output, "  Certificates: {}", tls.certificates.len());
        for (index, certificate) in tls.certificates.iter().enumerate() {
            let _ = writeln!(output, "    Certificate {}", index + 1);
            let _ = writeln!(output, "      Subject: {}", certificate.subject);
            let _ = writeln!(output, "      Issuer: {}", certificate.issuer);
            let _ = writeln!(output, "      Serial: {}", certificate.serial);
            let _ = writeln!(output, "      Valid from: {}", certificate.not_before);
            let _ = writeln!(output, "      Valid until: {}", certificate.not_after);
            let _ = writeln!(
                output,
                "      Public key: {}",
                certificate.public_key_algorithm
            );
            let _ = writeln!(
                output,
                "      Signature: {}",
                certificate.signature_algorithm
            );
            let _ = writeln!(output, "      SHA-256: {}", certificate.sha256);
            render_string_list(
                output,
                "      Subject alternative names",
                &certificate.subject_alt_names,
            );
        }
    } else {
        let _ = writeln!(output, "  None captured");
    }

    let _ = writeln!(output, "\nHTTP");
    let _ = writeln!(
        output,
        "  Requested protocol: {}",
        trace.http.requested_protocol
    );
    let _ = writeln!(
        output,
        "  Negotiated protocol: {}",
        trace.http.version.as_deref().unwrap_or("None")
    );
    let _ = writeln!(output, "  Status: {}", trace.status_text());
    let _ = writeln!(
        output,
        "  Final URL: {}",
        value_or_none(&trace.http.final_url)
    );
    let _ = writeln!(
        output,
        "  Headers sent: {}",
        if trace.http.headers_sent { "Yes" } else { "No" }
    );
    if !trace.http.request_header_representation.is_empty() {
        let _ = writeln!(
            output,
            "  Request representation: {}",
            trace.http.request_header_representation
        );
    }
    render_headers(output, "Request headers", &trace.http.request_headers);
    if let Some(headers) = &trace.http.actual_http1_request_headers {
        let _ = writeln!(
            output,
            "  Actual HTTP/1.1 header bytes: {}",
            escaped_bytes(headers)
        );
    }
    render_headers(output, "Response headers", &trace.http.response_headers);
    render_headers(output, "Response trailers", &trace.http.response_trailers);

    let _ = writeln!(output, "\nRedirect");
    let _ = writeln!(
        output,
        "  Follow redirects: {}",
        if trace.request.follow_redirects {
            "Yes"
        } else {
            "No"
        }
    );
    let _ = writeln!(
        output,
        "  Target: {}",
        trace.redirect_target.as_deref().unwrap_or("None")
    );
    let _ = writeln!(
        output,
        "  Followed: {}",
        if trace.redirect_followed { "Yes" } else { "No" }
    );
    let _ = writeln!(
        output,
        "  Stop reason: {}",
        trace.redirect_stop_reason.as_deref().unwrap_or("None")
    );

    let _ = writeln!(output, "\nBody");
    let _ = writeln!(
        output,
        "  Content-Type: {}",
        trace.body.content_type.as_deref().unwrap_or("None")
    );
    let _ = writeln!(
        output,
        "  Content-Encoding: {}",
        trace.body.content_encoding.as_deref().unwrap_or("None")
    );
    let _ = writeln!(output, "  Raw capture: {}", trace.body.raw_capture_status());
    let _ = writeln!(
        output,
        "  Decoded capture: {}",
        trace.body.decoded_capture_status()
    );
    let _ = writeln!(
        output,
        "  Decode error: {}",
        trace.body.decode_error.as_deref().unwrap_or("None")
    );
    if trace.body.decoded_is_text {
        let _ = writeln!(output, "  Decoded text:");
        if trace.body.decoded.is_empty() {
            let _ = writeln!(output, "    (empty)");
        } else {
            let _ = writeln!(output, "{}", trace.body.decoded);
        }
    } else {
        let _ = writeln!(output, "  Decoded text: Omitted (binary or non-text body)");
    }
}

fn render_string_list(output: &mut String, label: &str, values: &[String]) {
    if values.is_empty() {
        let _ = writeln!(output, "  {label}: None");
    } else {
        let _ = writeln!(output, "  {label}:");
        for value in values {
            let _ = writeln!(output, "    {value}");
        }
    }
}

fn render_headers(output: &mut String, label: &str, headers: &[HeaderTrace]) {
    if headers.is_empty() {
        let _ = writeln!(output, "  {label}: None");
    } else {
        let _ = writeln!(output, "  {label}:");
        for header in headers {
            let _ = writeln!(output, "    {}: {}", header.name, header.display_value());
        }
    }
}

fn value_or_none(value: &str) -> &str {
    if value.is_empty() { "None" } else { value }
}
