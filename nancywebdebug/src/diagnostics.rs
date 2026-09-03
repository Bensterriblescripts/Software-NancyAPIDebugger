use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolPreference {
    Auto,
    Http11,
    Http2,
    Http3,
}

impl ProtocolPreference {
    pub const ALL: [Self; 4] = [Self::Auto, Self::Http11, Self::Http2, Self::Http3];
}

impl fmt::Display for ProtocolPreference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Auto => "Auto (HTTP/2 or HTTP/1.1)",
            Self::Http11 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
            Self::Http3 => "HTTP/3",
        })
    }
}

#[derive(Debug, Clone)]
pub struct StageTimeouts {
    pub authentication: Duration,
    pub dns: Duration,
    pub transport: Duration,
    pub tls: Duration,
    pub headers: Duration,
    pub first_byte: Duration,
    pub body: Duration,
}

impl Default for StageTimeouts {
    fn default() -> Self {
        Self {
            authentication: Duration::from_secs(30),
            dns: Duration::from_secs(5),
            transport: Duration::from_secs(10),
            tls: Duration::from_secs(10),
            headers: Duration::from_secs(30),
            first_byte: Duration::from_secs(30),
            body: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestAuth {
    pub profile_id: u64,
    pub profile_name: String,
    pub profile_kind: String,
}

#[derive(Debug, Clone)]
pub struct DiagnosticRequest {
    pub method: String,
    pub url: String,
    pub headers: String,
    pub body: Arc<[u8]>,
    pub protocol: ProtocolPreference,
    pub timeouts: StageTimeouts,
    pub auth: Option<RequestAuth>,
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceOutcome {
    Running,
    Success,
    Failed,
    TimedOut,
    Cancelled,
}

impl fmt::Display for TraceOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Running => "Running",
            Self::Success => "Success",
            Self::Failed => "Failed",
            Self::TimedOut => "Timed out",
            Self::Cancelled => "Cancelled",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageKind {
    Url,
    Authentication,
    Dns,
    Tcp,
    QuicTls,
    Tls,
    HttpHeaders,
    FirstByte,
    Body,
}

impl fmt::Display for StageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Url => "URL",
            Self::Authentication => "Authentication",
            Self::Dns => "DNS",
            Self::Tcp => "TCP",
            Self::QuicTls => "QUIC + TLS",
            Self::Tls => "TLS",
            Self::HttpHeaders => "HTTP headers",
            Self::FirstByte => "First byte",
            Self::Body => "Body",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
    Skipped,
}

impl fmt::Display for StageStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "Pending",
            Self::Running => "Running",
            Self::Succeeded => "Succeeded",
            Self::Failed => "Failed",
            Self::TimedOut => "Timed out",
            Self::Cancelled => "Cancelled",
            Self::Skipped => "Skipped",
        })
    }
}

#[derive(Debug, Clone)]
pub struct StageTrace {
    pub kind: StageKind,
    pub status: StageStatus,
    pub duration_ms: Option<f64>,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct UrlTrace {
    pub normalized: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

#[derive(Debug, Clone, Default)]
pub struct DnsTrace {
    pub configured_resolvers: Vec<String>,
    pub attempts: Vec<DnsAttempt>,
    pub records: Vec<DnsRecord>,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct DnsAttempt {
    pub record_type: String,
    pub configured_resolver: String,
    pub responder: Option<SocketAddr>,
    pub transport: String,
    pub response_code: Option<String>,
    pub duration_ms: f64,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOutcome {
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
}

impl fmt::Display for ConnectionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Succeeded => "Succeeded",
            Self::Failed => "Failed",
            Self::TimedOut => "Timed out",
            Self::Cancelled => "Cancelled",
        })
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionAttempt {
    pub remote: SocketAddr,
    pub local: Option<SocketAddr>,
    pub family: String,
    pub duration_ms: f64,
    pub outcome: ConnectionOutcome,
    pub error: Option<String>,
    pub os_error: Option<i32>,
    pub selected: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TlsTrace {
    pub server_name: String,
    pub version: Option<String>,
    pub cipher_suite: Option<String>,
    pub alpn: Option<String>,
    pub validation: Option<String>,
    pub validation_error: Option<String>,
    pub certificates: Vec<CertificateTrace>,
}

#[derive(Debug, Clone)]
pub struct CertificateTrace {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub subject_alt_names: Vec<String>,
    pub public_key_algorithm: String,
    pub signature_algorithm: String,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct HeaderTrace {
    pub name: String,
    pub value: Vec<u8>,
    pub pseudo: bool,
}

impl HeaderTrace {
    pub fn display_value(&self) -> Cow<'_, str> {
        escaped_bytes(&self.value)
    }
}

pub fn escaped_bytes(bytes: &[u8]) -> Cow<'_, str> {
    if let Ok(value) = std::str::from_utf8(bytes)
        && value.chars().all(|character| !character.is_control())
    {
        return Cow::Borrowed(value);
    }
    let mut escaped = String::with_capacity(bytes.len());
    for &byte in bytes {
        if byte.is_ascii_graphic() || byte == b' ' {
            escaped.push(char::from(byte));
        } else {
            use std::fmt::Write;
            let _ = write!(escaped, "\\x{byte:02X}");
        }
    }
    Cow::Owned(escaped)
}

#[derive(Debug, Clone, Default)]
pub struct HttpTrace {
    pub requested_protocol: String,
    pub version: Option<String>,
    pub headers_sent: bool,
    pub request_headers: Vec<HeaderTrace>,
    pub request_header_representation: String,
    pub actual_http1_request_headers: Option<Arc<[u8]>>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub response_headers: Vec<HeaderTrace>,
    pub response_trailers: Vec<HeaderTrace>,
    pub final_url: String,
}

#[derive(Debug, Clone, Default)]
pub struct BodyTrace {
    pub raw: Arc<[u8]>,
    pub decoded: Arc<str>,
    pub raw_truncated: bool,
    pub decoded_truncated: bool,
    pub decoded_is_text: bool,
    pub decode_error: Option<String>,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
}

impl BodyTrace {
    pub fn raw_capture_status(&self) -> String {
        capture_status(self.raw.len(), self.raw_truncated)
    }

    pub fn decoded_capture_status(&self) -> String {
        if self.decoded_is_text {
            capture_status(self.decoded.len(), self.decoded_truncated)
        } else if self.decoded_truncated {
            "Not decoded as text (source or decoded data truncated)".to_owned()
        } else {
            "Not decoded as text".to_owned()
        }
    }
}

fn capture_status(length: usize, truncated: bool) -> String {
    if truncated {
        format!("{length} bytes (truncated at 50 MiB)")
    } else {
        format!("{length} bytes")
    }
}

#[derive(Debug, Clone)]
pub struct TraceError {
    pub stage: StageKind,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct DiagnosticTrace {
    pub index: usize,
    pub complete: bool,
    pub redirect_target: Option<String>,
    pub redirect_followed: bool,
    pub redirect_stop_reason: Option<String>,
    pub request: DiagnosticRequest,
    pub outcome: TraceOutcome,
    pub error: Option<TraceError>,
    pub stages: Vec<StageTrace>,
    pub url: UrlTrace,
    pub dns: DnsTrace,
    pub connection_mode: String,
    pub connections: Vec<ConnectionAttempt>,
    pub tls: Option<TlsTrace>,
    pub http: HttpTrace,
    pub body: BodyTrace,
}

impl DiagnosticTrace {
    pub fn new(index: usize, request: DiagnosticRequest) -> Self {
        let mut stage_kinds = vec![StageKind::Url, StageKind::Authentication, StageKind::Dns];
        if request.protocol == ProtocolPreference::Http3 {
            stage_kinds.push(StageKind::QuicTls);
        } else {
            stage_kinds.extend([StageKind::Tcp, StageKind::Tls]);
        }
        stage_kinds.extend([
            StageKind::HttpHeaders,
            StageKind::FirstByte,
            StageKind::Body,
        ]);
        Self {
            index,
            complete: false,
            redirect_target: None,
            redirect_followed: false,
            redirect_stop_reason: None,
            http: HttpTrace {
                requested_protocol: request.protocol.to_string(),
                final_url: request.url.clone(),
                ..Default::default()
            },
            request,
            outcome: TraceOutcome::Running,
            error: None,
            stages: stage_kinds
                .into_iter()
                .map(|kind| StageTrace {
                    kind,
                    status: StageStatus::Pending,
                    duration_ms: None,
                    detail: String::new(),
                })
                .collect(),
            url: UrlTrace::default(),
            dns: DnsTrace::default(),
            connection_mode: "Direct".to_owned(),
            connections: Vec::new(),
            tls: None,
            body: BodyTrace::default(),
        }
    }

    pub fn status_text(&self) -> String {
        match (self.http.status, &self.http.reason) {
            (Some(status), Some(reason)) if !reason.is_empty() => format!("{status} {reason}"),
            (Some(status), _) => status.to_string(),
            _ => self.outcome.to_string(),
        }
    }
}

pub fn normalize_url_input(input: &str) -> String {
    let input = input.trim();
    let has_scheme = input.find("://").is_some_and(|separator| {
        let scheme = &input[..separator];
        !scheme.is_empty()
            && scheme.bytes().enumerate().all(|(index, byte)| match index {
                0 => byte.is_ascii_alphabetic(),
                _ => byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'),
            })
    });
    if has_scheme {
        input.to_owned()
    } else {
        format!("http://{input}")
    }
}

#[derive(Debug)]
pub enum DiagnosticProgress {
    Running(DiagnosticTrace),
    Finished(DiagnosticTrace),
}
