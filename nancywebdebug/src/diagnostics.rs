use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub(crate) const MAX_CAPTURE_BYTES: usize = 50 * 1024 * 1024;

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ProtocolPreference {
        Auto => "Auto (HTTP/2 or HTTP/1.1)",
        Http11 => "HTTP/1.1",
        Http2 => "HTTP/2",
        Http3 => "HTTP/3",
    }
}

impl ProtocolPreference {
    pub const ALL: [Self; 4] = [Self::Auto, Self::Http11, Self::Http2, Self::Http3];
}

labeled_enum! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub enum UserAgentPreset[6] {
        #[default]
        Nancywebdebug => "nancywebdebug",
        Firefox => "firefox",
        Chrome => "chrome",
        Edge => "edge",
        Safari => "safari",
        None => "none",
    }
}

impl UserAgentPreset {
    pub const fn header_value(self) -> Option<&'static str> {
        match self {
            Self::Nancywebdebug => Some(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            )),
            Self::Firefox => Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0",
            ),
            Self::Chrome => Some(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            ),
            Self::Edge => Some(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
            ),
            Self::Safari => Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
            ),
            Self::None => None,
        }
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
pub struct RequestClientCertificate {
    pub profile_id: u64,
    pub profile_name: String,
    pub host_scope: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_after: String,
    pub sha256: String,
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
    pub client_certificate: Option<RequestClientCertificate>,
    pub follow_redirects: bool,
    pub user_agent: UserAgentPreset,
}

impl Default for DiagnosticRequest {
    fn default() -> Self {
        Self {
            method: "GET".to_owned(),
            url: String::new(),
            headers: String::new(),
            body: Arc::from([]),
            protocol: ProtocolPreference::Auto,
            timeouts: StageTimeouts::default(),
            auth: None,
            client_certificate: None,
            follow_redirects: true,
            user_agent: UserAgentPreset::default(),
        }
    }
}

impl DiagnosticRequest {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Self::default()
        }
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TraceOutcome {
        Running => "Running",
        Success => "Success",
        Failed => "Failed",
        TimedOut => "Timed out",
        Cancelled => "Cancelled",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StageKind {
        Url => "URL",
        Authentication => "Authentication",
        Dns => "DNS",
        Tcp => "TCP",
        QuicTls => "QUIC + TLS",
        Tls => "TLS",
        HttpHeaders => "HTTP headers",
        FirstByte => "First byte",
        Body => "Body",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StageStatus {
        Pending => "Pending",
        Running => "Running",
        Succeeded => "Succeeded",
        Failed => "Failed",
        TimedOut => "Timed out",
        Cancelled => "Cancelled",
        Skipped => "Skipped",
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
    pub incomplete_record_types: Vec<String>,
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

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ConnectionOutcome {
        Succeeded => "Succeeded",
        Failed => "Failed",
        TimedOut => "Timed out",
        Cancelled => "Cancelled",
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
    pub ocsp_response: Vec<u8>,
    pub certificates: Vec<CertificateTrace>,
    pub client_auth: ClientAuthObservation,
}

display_enum! {
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub enum ClientAuthStatus {
        Absent => "Absent",
        Optional => "Optional",
        Required => "Required",
        Accepted => "Accepted",
        Rejected => "Rejected",
        #[default]
        Inconclusive => "Inconclusive",
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClientAuthObservation {
    pub certificate_requested: bool,
    pub status: ClientAuthStatus,
    pub profile_name: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CertificateTrace {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub not_before_unix: Option<i64>,
    pub not_after_unix: Option<i64>,
    pub subject_alt_names: Vec<String>,
    pub public_key_algorithm: String,
    pub public_key_bits: Option<usize>,
    pub signature_algorithm: String,
    pub is_ca: Option<bool>,
    pub basic_constraints_critical: Option<bool>,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
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
        {
            let (length, truncated): (usize, bool) = (self.raw.len(), self.raw_truncated);

            if truncated {
                format!(
                    "{} (truncated at {})",
                    ({
                        let bytes: usize = length;
                        if bytes >= 1_000_000 {
                            format!("{:.2} MB", bytes as f64 / 1_000_000.0)
                        } else if bytes >= 1_000 {
                            format!("{:.2} KB", bytes as f64 / 1_000.0)
                        } else {
                            format!("{bytes} bytes")
                        }
                    }),
                    ({
                        let bytes: usize = MAX_CAPTURE_BYTES;
                        if bytes >= 1_000_000 {
                            format!("{:.2} MB", bytes as f64 / 1_000_000.0)
                        } else if bytes >= 1_000 {
                            format!("{:.2} KB", bytes as f64 / 1_000.0)
                        } else {
                            format!("{bytes} bytes")
                        }
                    })
                )
            } else {
                {
                    let bytes: usize = length;
                    if bytes >= 1_000_000 {
                        format!("{:.2} MB", bytes as f64 / 1_000_000.0)
                    } else if bytes >= 1_000 {
                        format!("{:.2} KB", bytes as f64 / 1_000.0)
                    } else {
                        format!("{bytes} bytes")
                    }
                }
            }
        }
    }

    pub fn decoded_capture_status(&self) -> String {
        if self.decoded_is_text {
            {
                let (length, truncated): (usize, bool) =
                    (self.decoded.len(), self.decoded_truncated);

                if truncated {
                    format!(
                        "{} (truncated at {})",
                        ({
                            let bytes: usize = length;
                            if bytes >= 1_000_000 {
                                format!("{:.2} MB", bytes as f64 / 1_000_000.0)
                            } else if bytes >= 1_000 {
                                format!("{:.2} KB", bytes as f64 / 1_000.0)
                            } else {
                                format!("{bytes} bytes")
                            }
                        }),
                        ({
                            let bytes: usize = MAX_CAPTURE_BYTES;
                            if bytes >= 1_000_000 {
                                format!("{:.2} MB", bytes as f64 / 1_000_000.0)
                            } else if bytes >= 1_000 {
                                format!("{:.2} KB", bytes as f64 / 1_000.0)
                            } else {
                                format!("{bytes} bytes")
                            }
                        })
                    )
                } else {
                    {
                        let bytes: usize = length;
                        if bytes >= 1_000_000 {
                            format!("{:.2} MB", bytes as f64 / 1_000_000.0)
                        } else if bytes >= 1_000 {
                            format!("{:.2} KB", bytes as f64 / 1_000.0)
                        } else {
                            format!("{bytes} bytes")
                        }
                    }
                }
            }
        } else if self.decoded_truncated {
            "Not decoded as text (source or decoded data truncated)".to_owned()
        } else {
            "Not decoded as text".to_owned()
        }
    }
}

#[derive(Debug, Clone)]
pub struct TraceError {
    pub stage: StageKind,
    pub message: String,
}

display_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FingerprintStatus {
        Pending => "Pending",
        Detected => "Detected",
        Unknown => "Unknown",
        TimedOut => "Timed out",
        Cancelled => "Cancelled",
        Unavailable => "Unavailable",
    }
}

#[derive(Debug, Clone)]
pub struct FingerprintTrace {
    pub status: FingerprintStatus,
    pub web_server: String,
    pub confidence: String,
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
    pub fingerprint: FingerprintTrace,
}

impl DiagnosticTrace {
    pub fn new(index: usize, request: DiagnosticRequest) -> Self {
        let fingerprint = {
            {
                FingerprintTrace {
                    status: FingerprintStatus::Pending,
                    web_server: "Unknown".to_owned(),
                    confidence: "None".to_owned(),
                }
            }
        };
        let stage_kinds: &[StageKind] = if request.protocol == ProtocolPreference::Http3 {
            &[
                StageKind::Url,
                StageKind::Authentication,
                StageKind::Dns,
                StageKind::QuicTls,
                StageKind::HttpHeaders,
                StageKind::FirstByte,
                StageKind::Body,
            ]
        } else {
            &[
                StageKind::Url,
                StageKind::Authentication,
                StageKind::Dns,
                StageKind::Tcp,
                StageKind::Tls,
                StageKind::HttpHeaders,
                StageKind::FirstByte,
                StageKind::Body,
            ]
        };
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
                .iter()
                .copied()
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
            fingerprint,
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
        format!("https://{input}")
    }
}

#[derive(Debug)]
pub enum DiagnosticProgress {
    HttpHopUpdated(DiagnosticTrace),
    HttpHopCompleted(DiagnosticTrace),
    SessionCompleted,
}
