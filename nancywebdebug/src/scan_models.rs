use super::*;
use crate::scan_limits as limits;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PortSelection {
    #[default]
    Curated,
    All,
    Custom(Vec<u16>),
}

impl PortSelection {
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("curated") {
            Ok(Self::Curated)
        } else if value.eq_ignore_ascii_case("all") {
            Ok(Self::All)
        } else {
            ({
                let (value,): (&str,) = (value,);
                let inlined_result: Result<Vec<u16>, String> =
                    {
                        'inlined_parse_custom_ports: {
                            let mut ports = Vec::new();
                            for part in value.split(',') {
                                let part = part.trim();
                                if part.is_empty() {
                                    break 'inlined_parse_custom_ports Err(
                                        "Port list contains an empty item".to_owned(),
                                    );
                                }
                                if let Some((start, end)) = part.split_once('-') {
                                    let start = match {
                                        let (value,): (&str,) = (start,);
                                        let inlined_result: Result<u16, String> = {
                                            value
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("Invalid port '{value}'"))
        .and_then(|port| {
            if port == 0 {
                Err("Port 0 is not a valid destination port".to_owned())
            } else {
                Ok(port)
            }
        })
                                        };
                                        inlined_result
                                    } {
                                        Ok(value) => value,
                                        Err(error) => {
                                            break 'inlined_parse_custom_ports Err(
                                                ::core::convert::From::from(error),
                                            );
                                        }
                                    };
                                    let end = match {
                                        let (value,): (&str,) = (end,);
                                        let inlined_result: Result<u16, String> = {
                                            value
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("Invalid port '{value}'"))
        .and_then(|port| {
            if port == 0 {
                Err("Port 0 is not a valid destination port".to_owned())
            } else {
                Ok(port)
            }
        })
                                        };
                                        inlined_result
                                    } {
                                        Ok(value) => value,
                                        Err(error) => {
                                            break 'inlined_parse_custom_ports Err(
                                                ::core::convert::From::from(error),
                                            );
                                        }
                                    };
                                    if start > end {
                                        break 'inlined_parse_custom_ports Err(format!(
                                            "Port range {part} is reversed"
                                        ));
                                    }
                                    ports.extend(start..=end);
                                } else {
                                    ports.push(
                                        match {
                                            let (value,): (&str,) = (part,);
                                            let inlined_result: Result<u16, String> = {
                                                value
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("Invalid port '{value}'"))
        .and_then(|port| {
            if port == 0 {
                Err("Port 0 is not a valid destination port".to_owned())
            } else {
                Ok(port)
            }
        })
                                            };
                                            inlined_result
                                        } {
                                            Ok(value) => value,
                                            Err(error) => {
                                                break 'inlined_parse_custom_ports Err(
                                                    ::core::convert::From::from(error),
                                                );
                                            }
                                        },
                                    );
                                }
                            }
                            normalize_ports(ports)
                        }
                    };
                inlined_result
            })
            .map(Self::Custom)
        }
    }

    pub fn ports(&self, transport: TransportProtocol) -> Result<Vec<u16>, String> {
        match (self, transport) {
            (Self::Curated, TransportProtocol::Tcp) => Ok(CURATED_TCP_PORTS.to_vec()),
            (Self::Curated, TransportProtocol::Udp) => Ok(CURATED_UDP_PORTS.to_vec()),
            (Self::All, TransportProtocol::Tcp) => Ok((1..=u16::MAX).collect()),
            (Self::All, TransportProtocol::Udp) => {
                Err("All ports is only supported for TCP".to_owned())
            }
            (Self::Custom(ports), _) => normalize_ports(ports.clone()),
        }
    }
}

impl FromStr for PortSelection {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

fn normalize_ports(mut ports: Vec<u16>) -> Result<Vec<u16>, String> {
    ports.sort_unstable();
    ports.dedup();
    match ports.first() {
        Some(0) => Err("Port 0 is not a valid destination port".to_owned()),
        Some(_) => Ok(ports),
        None => Err("Port selection contains no ports".to_owned()),
    }
}

#[derive(Debug, Clone)]
pub struct ExposureScanRequest {
    pub diagnostic_request: DiagnosticRequest,
    pub ports: PortSelection,
    pub connection_timeout: Duration,
    pub probe_timeout: Duration,
    pub concurrency: usize,
    pub connection_starts_per_second: u32,
    pub security_operations: bool,
    pub web_probe_level: WebProbeLevel,
    pub active_requests_per_origin: usize,
    pub active_requests_total: usize,
    pub udp_ports: PortSelection,
    pub service_access_checks: bool,
    pub udp_scanning: bool,
    pub asset_discovery: bool,
    pub dns_assessment: bool,
    pub ct_hostname_limit: usize,
    pub dkim_selectors: Vec<String>,
    pub crawl_max_urls: usize,
    pub crawl_concurrency: usize,
    pub crawl_requests_per_second: u32,
}

impl Default for ExposureScanRequest {
    fn default() -> Self {
        Self {
            diagnostic_request: DiagnosticRequest::default(),
            ports: PortSelection::Curated,
            connection_timeout: Duration::from_millis(1500),
            probe_timeout: Duration::from_secs(5),
            concurrency: 128,
            connection_starts_per_second: 200,
            security_operations: true,
            web_probe_level: WebProbeLevel::Passive,
            active_requests_per_origin: 80,
            active_requests_total: 300,
            udp_ports: PortSelection::Curated,
            service_access_checks: false,
            udp_scanning: false,
            asset_discovery: false,
            dns_assessment: false,
            ct_hostname_limit: 500,
            dkim_selectors: Vec::new(),
            crawl_max_urls: 100_000,
            crawl_concurrency: 10,
            crawl_requests_per_second: 200,
        }
    }
}

impl ExposureScanRequest {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            diagnostic_request: DiagnosticRequest::new(target),
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        parse_target(&self.diagnostic_request.url)?;
        self.ports
            .ports(TransportProtocol::Tcp)
            .map_err(|error| format!("TCP ports: {error}"))?;
        if self.udp_scanning {
            self.udp_ports
                .ports(TransportProtocol::Udp)
                .map_err(|error| format!("UDP ports: {error}"))?;
        }
        limits::validate_timeout(
            self.connection_timeout,
            limits::CONNECTION_TIMEOUT,
            "Connection timeout (seconds)",
        )?;
        limits::validate_timeout(
            self.probe_timeout,
            limits::PROBE_TIMEOUT,
            "Probe timeout (seconds)",
        )?;
        let timeouts = &self.diagnostic_request.timeouts;
        limits::validate_timeout(
            timeouts.authentication,
            limits::STAGE_TIMEOUT,
            "Authentication stage timeout (seconds)",
        )?;
        limits::validate_timeout(
            timeouts.dns,
            limits::STAGE_TIMEOUT,
            "DNS stage timeout (seconds)",
        )?;
        limits::validate_timeout(
            timeouts.transport,
            limits::STAGE_TIMEOUT,
            "TCP / QUIC stage timeout (seconds)",
        )?;
        limits::validate_timeout(
            timeouts.tls,
            limits::STAGE_TIMEOUT,
            "TLS stage timeout (seconds)",
        )?;
        limits::validate_timeout(
            timeouts.headers,
            limits::STAGE_TIMEOUT,
            "HTTP headers stage timeout (seconds)",
        )?;
        limits::validate_timeout(
            timeouts.first_byte,
            limits::STAGE_TIMEOUT,
            "First byte stage timeout (seconds)",
        )?;
        limits::validate_timeout(
            timeouts.body,
            limits::STAGE_TIMEOUT,
            "Body stage timeout (seconds)",
        )?;
        limits::validate(
            self.concurrency,
            limits::CONCURRENCY,
            "Concurrent endpoints",
        )?;
        limits::validate(
            self.connection_starts_per_second,
            limits::CONNECTION_RATE,
            "Connection starts / second",
        )?;
        if self.security_operations {
            limits::validate(
                self.crawl_max_urls,
                limits::CRAWL_URLS,
                "Crawl URLs / domain",
            )?;
            limits::validate(
                self.crawl_concurrency,
                limits::CRAWL_CONCURRENCY,
                "Concurrent crawl requests",
            )?;
            limits::validate(
                self.crawl_requests_per_second,
                limits::CRAWL_RATE,
                "Crawl requests / second",
            )?;
        }
        if self.web_probe_level != WebProbeLevel::Passive {
            limits::validate(
                self.active_requests_per_origin,
                limits::ACTIVE_PER_ORIGIN,
                "Active requests / origin",
            )?;
            limits::validate(
                self.active_requests_total,
                limits::ACTIVE_TOTAL,
                "Total active requests",
            )?;
        }
        if self.asset_discovery {
            limits::validate(
                self.ct_hostname_limit,
                limits::CT_HOSTNAMES,
                "CT hostname limit",
            )?;
        }
        if self.dns_assessment {
            if self.dkim_selectors.len() > 100 {
                return Err("No more than 100 DKIM selectors may be supplied".to_owned());
            }
            for selector in &self.dkim_selectors {
                let value = selector.trim();
                if value.is_empty()
                    || value.len() > 63
                    || value.starts_with('-')
                    || value.ends_with('-')
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return Err(format!(
                        "Invalid DKIM selector '{selector}': use 1-63 letters, digits, hyphens or underscores, with no leading or trailing hyphen"
                    ));
                }
            }
        }
        Ok(())
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
    pub enum WebProbeLevel {
        #[default]
        Passive => "Passive",
        Active => "Active, non-state-changing",
        StateChanging => "State-changing",
    }
}

impl WebProbeLevel {
    pub const ALL: [Self; 3] = [Self::Passive, Self::Active, Self::StateChanging];
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ExposureScanStatus {
        Running => "Running",
        Completed => "Completed",
        Failed => "Failed",
        Cancelled => "Cancelled",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum TransportProtocol {
        Tcp => "TCP",
        Udp => "UDP",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum UdpEndpointState {
        Responsive => "Responsive",
        Closed => "Closed",
        OpenOrFiltered => "Open or filtered",
        Error => "Error",
        Cancelled => "Cancelled",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ServiceAccessStatus {
        Confirmed => "Confirmed",
        Offered => "Offered",
        Protected => "Protected",
        OpenOrFiltered => "Open or filtered",
        Inconclusive => "Inconclusive",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DiscoveredAssetState {
        Public => "Public",
        NonPublic => "Non-public",
        Unresolved => "Unresolved",
        DanglingCname => "Potential dangling CNAME",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DnsObservationStatus {
        Error => "Error",
        Recommendation => "Recommendation",
        Pass => "Pass",
        Informational => "Informational",
        Warning => "Warning",
        Inconclusive => "Inconclusive",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PortState {
        Open => "Open",
        Closed => "Closed",
        FilteredOrNoResponse => "Filtered or no response",
        Error => "Error",
        Cancelled => "Cancelled",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceKind {
        Unknown => "Unknown",
        Http => "HTTP",
        Https => "HTTPS",
        Tls => "TLS",
        Ssh => "SSH",
        Ftp => "FTP",
        Smtp => "SMTP",
        Pop3 => "POP3",
        Imap => "IMAP",
        Mysql => "MySQL protocol",
        PostgreSql => "PostgreSQL protocol",
        Redis => "Redis protocol",
        Rdp => "RDP",
        Vnc => "VNC",
        Rsync => "rsync protocol",
        Memcached => "Memcached protocol",
        ZooKeeper => "ZooKeeper protocol",
        Cassandra => "Cassandra native protocol",
        ErlangEpmd => "Erlang EPMD",
        Git => "Git protocol",
        Ajp => "AJP",
        IsoOnTcp => "ISO-on-TCP",
        Modbus => "Modbus/TCP",
        Iec104 => "IEC 60870-5-104",
        OpcUa => "OPC UA",
        OmronFins => "Omron FINS/TCP",
        EtherNetIp => "EtherNet/IP",
        Ldap => "LDAP",
        Smb => "SMB",
        Mqtt => "MQTT",
        MongoDb => "MongoDB protocol",
        Rtsp => "RTSP",
        Rtmp => "RTMP",
        Dns => "DNS",
        Ntp => "NTP",
        Ike => "IKE",
        Quic => "QUIC",
        MqttSn => "MQTT-SN",
        Ssdp => "SSDP",
        Stun => "STUN",
        WsDiscovery => "WS-Discovery",
        Sip => "SIP",
        Mdns => "mDNS",
        Coap => "CoAP",
        Srt => "SRT",
        WebSocket => "WebSocket",
        Rpcbind => "rpcbind",
        Nfs => "NFS",
        Tftp => "TFTP",
        NetBiosName => "NetBIOS name service",
        Snmp => "SNMP",
        Rtp => "RTP",
        Rtcp => "RTCP",
        Dtls => "DTLS",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Confidence {
        #[default]
        None => "None",
        Low => "Low",
        Medium => "Medium",
        High => "High",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum TechnologyFileType {
        JavaScript => "JavaScript",
        Jsx => "JSX",
        TypeScript => "TypeScript",
        Tsx => "TSX",
        Php => "PHP",
        Python => "Python",
        Ruby => "Ruby",
        Erb => "ERB",
        Java => "Java",
        Jsp => "JSP",
        Kotlin => "Kotlin",
        Jar => "JAR",
        CSharp => "C#",
        Razor => "Razor",
        AspNet => "ASP.NET",
        DotNetAssembly => ".NET assembly",
        Go => "Go",
        Rust => "Rust",
    }
}

impl TechnologyFileType {
    pub fn language(self) -> &'static str {
        match self {
            Self::JavaScript | Self::Jsx => "JavaScript",
            Self::TypeScript | Self::Tsx => "TypeScript",
            Self::Php => "PHP",
            Self::Python => "Python",
            Self::Ruby | Self::Erb => "Ruby",
            Self::Java | Self::Jsp | Self::Jar => "JVM",
            Self::Kotlin => "Kotlin/JVM",
            Self::CSharp | Self::Razor | Self::AspNet | Self::DotNetAssembly => ".NET",
            Self::Go => "Go",
            Self::Rust => "Rust",
        }
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum TechnologyEcosystem {
        JavaScript => "JavaScript",
        Npm => "npm",
        Composer => "Composer/Packagist",
        WordPress => "WordPress",
        Moodle => "Moodle",
        PyPi => "PyPI",
        RubyGems => "RubyGems",
        MavenCentral => "Maven Central",
        NuGet => "NuGet",
        GoModules => "Go modules",
        CratesIo => "crates.io",
        Runtime => "Runtime release feed",
        WebServer => "Web server upstream",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum TechnologyComponentKind {
        Framework => "Framework",
        Cms => "CMS",
        Plugin => "Plugin",
        Runtime => "Runtime",
        Package => "Package",
        Server => "Server",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum TechnologySupportStatus {
        NotApplicable => "Not applicable",
        NotChecked => "Not checked",
        Supported => "Supported",
        Unsupported => "Unsupported",
        Unknown => "Unknown",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum TechnologyVersionStatus {
        Unknown => "Unknown",
        InventoryOnly => "Inventory only",
        NotChecked => "Not checked",
        Current => "Current",
        OutdatedPatch => "Outdated (patch)",
        OutdatedMinor => "Outdated (minor)",
        OutdatedMajor => "Outdated (major)",
        NewerThanLatest => "Newer than latest",
        Prerelease => "Prerelease",
        Unverifiable => "Unverifiable",
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TechnologyEvidence {
    pub source_url: String,
    pub endpoint: Option<String>,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub match_source: String,
    pub observed_value: Option<String>,
    pub extracted_version: Option<String>,
    pub supporting_detection: Option<String>,
    pub excerpt_shortened: bool,
    pub capture_truncated: bool,
}

#[derive(Debug, Clone)]
pub struct DetectedFileType {
    pub file_type: TechnologyFileType,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    pub observations: Vec<TechnologyEvidence>,
}

#[derive(Debug, Clone)]
pub struct TechnologyComponent {
    pub name: String,
    pub ecosystem: TechnologyEcosystem,
    pub kind: TechnologyComponentKind,
    pub package_identifier: Option<String>,
    pub installed_version: Option<String>,
    pub latest_version: Option<String>,
    pub status: TechnologyVersionStatus,
    pub support_status: TechnologySupportStatus,
    pub confidence: Confidence,
    pub release_source_url: Option<String>,
    pub evidence_urls: Vec<String>,
    pub evidence: Vec<String>,
    pub check_error: Option<String>,
    pub observations: Vec<TechnologyEvidence>,
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum ProductLayer {
        Protocol => "Protocol",
        Server => "Server",
        Proxy => "Proxy",
        Cdn => "CDN",
        Cloud => "Cloud",
        Framework => "Framework",
        Runtime => "Runtime",
        Cms => "CMS",
        Ecommerce => "E-commerce",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum WebSurfaceType {
        Api => "API",
        Login => "Login",
        Admin => "Admin",
        Cart => "Cart",
        Checkout => "Checkout",
    }
}

#[derive(Debug, Clone)]
pub struct ObservedWebSurface {
    pub technology: String,
    pub url: String,
    pub status: u16,
    pub surface_type: WebSurfaceType,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CrawlObservedWebSurface {
    pub ip: IpAddr,
    pub port: u16,
    pub url: String,
    pub status: u16,
    pub surface_type: WebSurfaceType,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TlsVersion {
        Tls12 => "TLS 1.2",
        Tls13 => "TLS 1.3",
    }
}

#[derive(Debug, Clone)]
pub struct ProductDetection {
    pub observations: Vec<TechnologyEvidence>,
    pub name: String,
    pub layer: ProductLayer,
    pub version: Option<String>,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WebTechnologyDetection {
    pub name: String,
    pub category_names: Vec<String>,
    pub version: Option<String>,
    pub confidence: Confidence,
    pub evidence_urls: Vec<String>,
    pub evidence: Vec<String>,
    pub observations: Vec<TechnologyEvidence>,
}

#[derive(Debug, Clone)]
pub struct TlsObservation {
    pub requested_version: TlsVersion,
    pub supported: bool,
    pub unverified: bool,
    pub alpn: Option<String>,
    pub validation_error: Option<String>,
    pub hostname_valid: Option<bool>,
    pub certificate_expired: Option<bool>,
    pub certificate_not_yet_valid: Option<bool>,
    pub revocation: RevocationState,
    pub ocsp: Option<OcspObservation>,
    pub chain_diagnostics: Vec<String>,
    pub certificates: Vec<CertificateTrace>,
    pub error: Option<String>,
    pub client_auth: ClientAuthObservation,
}

display_enum! {
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub enum RevocationState {
        Good => "Good",
        Revoked => "Revoked",
        Unknown => "Unknown",
        Offline => "Offline",
        #[default]
        NotChecked => "Not checked",
    }
}

#[derive(Debug, Clone)]
pub struct OcspObservation {
    pub bytes: usize,
    pub response_status: String,
    pub certificate_status: Option<String>,
    pub produced_at: Option<String>,
    pub this_update: Option<String>,
    pub next_update: Option<String>,
    pub fresh: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TlsProbeAttempt {
    pub check_id: String,
    pub offered_protocol: String,
    pub offered_cipher: Option<String>,
    pub accepted: bool,
    pub negotiated_protocol: Option<String>,
    pub negotiated_cipher: Option<String>,
    pub compression: Option<u8>,
    pub secure_renegotiation: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpObservation {
    pub method: String,
    pub url: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub body_truncated: bool,
    pub redirect_location: Option<String>,
    pub duration_ms: f64,
    pub framing: ResponseFraming,
}

#[derive(Debug, Clone, Default)]
pub struct ResponseFraming {
    pub transfer_chunked: bool,
    pub completed: bool,
    pub body_limit_reached: bool,
    pub read_timed_out: bool,
    pub body_read_events: usize,
    pub decoded_chunks: usize,
}

#[derive(Debug, Clone)]
pub struct JavaScriptLibrary {
    pub name: String,
    pub npm_package: Option<String>,
    pub installed_version: Option<String>,
    pub latest_version: Option<String>,
    pub status: TechnologyVersionStatus,
    pub evidence: Vec<String>,
    pub check_error: Option<String>,
    pub observations: Vec<TechnologyEvidence>,
}

#[derive(Debug, Clone)]
pub struct JavaScriptSource {
    pub source_url: String,
    pub final_url: Option<String>,
    pub http_status: Option<u16>,
    pub http_reason: Option<String>,
    pub captured_size: usize,
    pub truncated: bool,
    pub sha256: Option<String>,
    pub libraries: Vec<JavaScriptLibrary>,
    pub retrieval_error: Option<String>,
    pub analysis_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FindingLocation {
    pub url: Option<String>,
    pub method: Option<String>,
    pub subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FindingDetail {
    pub cause: String,
    pub location: FindingLocation,
}

#[derive(Debug, Clone)]
pub struct ExposureFinding {
    pub details: Vec<FindingDetail>,
    pub title: String,
    pub description: String,
    pub ip: IpAddr,
    pub port: u16,
    pub transport: TransportProtocol,
    pub evidence: Vec<String>,
    pub component_kind: Option<TechnologyComponentKind>,
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum VulnerabilityClass {
        Tls => "TLS",
        Injection => "Injection",
        ClientSide => "Client-side",
        AccessControl => "Access control",
        ServerSideRequestHandling => "Server-side request handling",
        HttpInfrastructure => "HTTP infrastructure",
        SessionAuthentication => "Session / authentication",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum CheckOutcome {
        Vulnerable => "Vulnerable",
        Potential => "Potential",
        NotObserved => "Not observed",
        Inconclusive => "Inconclusive",
        Skipped => "Skipped",
        Deferred => "Deferred",
    }
}

#[derive(Debug, Clone)]
pub struct SecurityCheckResult {
    pub ip: IpAddr,
    pub port: u16,
    pub check_id: String,
    pub class: VulnerabilityClass,
    pub title: String,
    pub confidence: Confidence,
    pub outcome: CheckOutcome,
    pub probe_url: Option<String>,
    pub request_evidence: Option<String>,
    pub evidence: Vec<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UdpEndpointScan {
    pub ip: IpAddr,
    pub port: u16,
    pub transport: TransportProtocol,
    pub state: UdpEndpointState,
    pub attempted: bool,
    pub service: ServiceKind,
    pub elapsed_ms: f64,
    pub evidence: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ServiceAccessResult {
    pub ip: IpAddr,
    pub port: u16,
    pub transport: TransportProtocol,
    pub service: ServiceKind,
    pub method: String,
    pub status: ServiceAccessStatus,
    pub summary: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredAsset {
    pub hostname: String,
    pub source: String,
    pub addresses: Vec<IpAddr>,
    pub cname_chain: Vec<String>,
    pub state: DiscoveredAssetState,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct DnsObservation {
    pub subject: String,
    pub check: String,
    pub status: DnsObservationStatus,
    pub summary: String,
    pub impact: String,
    pub remediation: String,
    pub evidence: Vec<String>,
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum StreamKind {
        ServerSentEvents => "Server-sent events",
        Ndjson => "NDJSON",
        JsonSequence => "JSON text sequence",
        Hls => "HLS",
        Dash => "DASH",
        WebRtcSdp => "WebRTC / SDP",
        StunTurn => "STUN / TURN",
        WebSocket => "WebSocket",
        ChunkedIncremental => "Chunked incremental response",
        ReadableStream => "JavaScript ReadableStream",
        EventSource => "JavaScript EventSource",
        MediaElement => "HTML media element",
    }
}

display_enum! {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub enum StreamStatus {
        Candidate => "Candidate",
        Confirmed => "Confirmed",
        Protected => "Protected",
        Inconclusive => "Inconclusive",
    }
}

#[derive(Debug, Clone)]
pub struct StreamObservation {
    pub source_url: String,
    pub kind: StreamKind,
    pub status: StreamStatus,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CrawlOrigin {
    pub ip: IpAddr,
    pub scheme: String,
    pub hostname: String,
    pub port: u16,
    pub seed_url: String,
    pub queued: usize,
    pub completed: usize,
    pub robots_exclusions: Vec<String>,
    pub sitemap_urls: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CrawledResource {
    pub ip: IpAddr,
    pub port: u16,
    pub url: String,
    pub depth: usize,
    pub source_url: Option<String>,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub bytes_inspected: usize,
    pub body_truncated: bool,
    pub detected_file_types: Vec<DetectedFileType>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CrawlFormAction {
    pub source_url: String,
    pub action_url: String,
    pub method: String,
    pub encoding: String,
    pub has_password: bool,
    pub likely_csrf_tokens: Vec<String>,
    pub controls: Vec<CrawlFormControl>,
    pub enqueued: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlFormControl {
    pub name: String,
    pub control_type: String,
    pub default_value: Option<String>,
    pub submit_control: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CrawlContactType {
    Email,
    Telephone,
}

#[derive(Debug, Clone)]
pub struct CrawlContact {
    pub contact_type: CrawlContactType,
    pub value: String,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CrawlExternalIndicator {
    pub source_url: String,
    pub kind: String,
    pub value: String,
    pub evidence: String,
}

#[derive(Debug, Clone)]
pub struct CrawlSkippedUrl {
    pub source_url: Option<String>,
    pub url: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct EndpointScan {
    pub ip: IpAddr,
    pub port: u16,
    pub transport: TransportProtocol,
    pub state: PortState,
    pub attempted: bool,
    pub connect_duration_ms: f64,
    pub service: ServiceKind,
    pub service_confidence: Confidence,
    pub products: Vec<ProductDetection>,
    pub web_technologies: Vec<WebTechnologyDetection>,
    pub evidence: Vec<String>,
    pub banner: Vec<u8>,
    pub tls: Vec<TlsObservation>,
    pub tls_probe_attempts: Vec<TlsProbeAttempt>,
    pub http: Vec<HttpObservation>,
    pub observed_web_surfaces: Vec<ObservedWebSurface>,
    pub javascript_sources: Vec<JavaScriptSource>,
    pub technology_components: Vec<TechnologyComponent>,
    pub findings: Vec<ExposureFinding>,
    pub security_checks: Vec<SecurityCheckResult>,
    pub diagnostics: Vec<DiagnosticTrace>,
    pub error: Option<String>,
    pub(super) javascript_candidates: Vec<String>,
}

impl EndpointScan {
    pub(super) fn new(ip: IpAddr, port: u16) -> Self {
        Self {
            ip,
            port,
            transport: TransportProtocol::Tcp,
            state: PortState::Error,
            attempted: false,
            connect_duration_ms: 0.0,
            service: ServiceKind::Unknown,
            service_confidence: Confidence::None,
            products: Vec::new(),
            web_technologies: Vec::new(),
            evidence: Vec::new(),
            banner: Vec::new(),
            tls: Vec::new(),
            tls_probe_attempts: Vec::new(),
            http: Vec::new(),
            observed_web_surfaces: Vec::new(),
            javascript_sources: Vec::new(),
            technology_components: Vec::new(),
            findings: Vec::new(),
            security_checks: Vec::new(),
            diagnostics: Vec::new(),
            error: None,
            javascript_candidates: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IgnoredAddress {
    pub address: IpAddr,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct ExposureScanTimings {
    pub resolution_ms: f64,
    pub scan_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug, Clone)]
pub struct ConnectivityCheck {
    pub label: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointHealthResolution {
    Inconclusive,
    Recovered,
    Stopped,
}

#[derive(Debug, Clone)]
pub struct EndpointHealthObservation {
    pub ip: IpAddr,
    pub port: u16,
    pub transport: TransportProtocol,
    pub request_number: usize,
    pub elapsed_ms: f64,
    pub timeouts: usize,
    pub rejections: usize,
    pub had_baseline: bool,
    pub connectivity: Vec<ConnectivityCheck>,
    pub retries: Vec<String>,
    pub resolution: EndpointHealthResolution,
    pub detail: String,
}

display_enum! {
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub enum DiscoveryCoverageStatus {
        #[default]
        Pending => "Pending",
        Running => "Running",
        Complete => "Selected discovery complete",
        Limited => "Limited coverage",
        Cancelled => "Cancelled; incomplete coverage",
        Unavailable => "Provider unavailable; incomplete coverage",
    }
}

#[derive(Debug, Clone, Default)]
pub struct DiscoveryCoverage {
    pub status: DiscoveryCoverageStatus,
    pub eligible: Option<usize>,
    pub selected: usize,
    pub completed: usize,
    pub omitted: usize,
    pub detail: String,
}

impl DiscoveryCoverage {
    pub fn summary(&self) -> String {
        format!("{}: {} eligible, {} selected, {} completed, {} omitted. {}", self.status,
            self.eligible.map(|count| count.to_string()).unwrap_or_else(|| "unknown".to_owned()),
            self.selected, self.completed, self.omitted, self.detail)
    }
}

#[derive(Debug, Clone)]
pub struct ExposureScanReport {
    pub request: ExposureScanRequest,
    pub hostname: String,
    pub supplied_port: Option<u16>,
    pub resolved_addresses: Vec<IpAddr>,
    pub ignored_addresses: Vec<IgnoredAddress>,
    pub warnings: Vec<String>,
    pub endpoint_health: Vec<EndpointHealthObservation>,
    pub endpoints: Vec<EndpointScan>,
    pub udp_endpoints: Vec<UdpEndpointScan>,
    pub service_access: Vec<ServiceAccessResult>,
    pub discovered_assets: Vec<DiscoveredAsset>,
    pub discovery_coverage: DiscoveryCoverage,
    pub dns_observations: Vec<DnsObservation>,
    pub stream_observations: Vec<StreamObservation>,
    pub findings: Vec<ExposureFinding>,
    pub security_checks: Vec<SecurityCheckResult>,
    pub crawl_observed_web_surfaces: Vec<CrawlObservedWebSurface>,
    pub crawl_origins: Vec<CrawlOrigin>,
    pub crawled_resources: Vec<CrawledResource>,
    pub crawl_forms: Vec<CrawlFormAction>,
    pub crawl_contacts: Vec<CrawlContact>,
    pub crawl_external_indicators: Vec<CrawlExternalIndicator>,
    pub crawl_skipped_urls: Vec<CrawlSkippedUrl>,
    pub timings: ExposureScanTimings,
    pub status: ExposureScanStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExposureScanPhase {
    PortScanning,
    UdpScanning,
    ServiceAccess,
    AssetDiscovery,
    DnsAssessment,
    EndpointDiagnostics,
    Crawl,
    ActiveWebAssessment,
    JavaScriptAnalysis,
    Fingerprinting,
    TechnologyAnalysis,
    FinalizingReport,
}

impl ExposureScanPhase {
    pub const ALL: [Self; 12] = [
        Self::PortScanning,
        Self::UdpScanning,
        Self::ServiceAccess,
        Self::AssetDiscovery,
        Self::DnsAssessment,
        Self::EndpointDiagnostics,
        Self::Crawl,
        Self::ActiveWebAssessment,
        Self::JavaScriptAnalysis,
        Self::Fingerprinting,
        Self::TechnologyAnalysis,
        Self::FinalizingReport,
    ];

    pub const fn label(&self) -> &'static str {
        match self {
            Self::PortScanning => "Port scanning",
            Self::UdpScanning => "UDP scanning",
            Self::ServiceAccess => "Service access",
            Self::AssetDiscovery => "Asset discovery",
            Self::DnsAssessment => "DNS assessment",
            Self::EndpointDiagnostics => "Endpoint diagnostics",
            Self::Crawl => "Crawl",
            Self::ActiveWebAssessment => "Active web assessment",
            Self::JavaScriptAnalysis => "JavaScript analysis",
            Self::Fingerprinting => "Fingerprinting",
            Self::TechnologyAnalysis => "Technology analysis",
            Self::FinalizingReport => "Finalizing report",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExposureScanPhaseState {
    Pending,
    Running,
    Complete,
    Skipped,
}

#[derive(Debug, Clone)]
pub enum ExposureScanProgress {
    Resolving {
        target: String,
    },
    Resolved {
        public_addresses: Vec<IpAddr>,
        total_endpoints: usize,
    },
    EndpointCompleted {
        completed: usize,
        total: usize,
        endpoint: EndpointScan,
    },
    UdpEndpointCompleted {
        completed: usize,
        total: usize,
        endpoint: UdpEndpointScan,
    },
    ServiceAccessCompleted {
        completed: usize,
        total: usize,
        result: ServiceAccessResult,
    },
    DiscoveryCoverageUpdated(DiscoveryCoverage),
    AssetDiscovered {
        completed: usize,
        total: usize,
        asset: DiscoveredAsset,
    },
    DnsObservationCompleted {
        completed: usize,
        total: usize,
        observation: DnsObservation,
    },
    CrawlProgress {
        origin: String,
        queued: usize,
        completed: usize,
        current_url: String,
    },
    PhaseProgress {
        phase: ExposureScanPhase,
        state: ExposureScanPhaseState,
        fraction: f32,
        text: String,
    },
    Completed(ExposureScanReport),
}
