use crate::auth::{AuthStore, SharedAuthStore};
use crate::diagnostics::{
    CertificateTrace, ConnectionOutcome, DiagnosticRequest, DiagnosticTrace, DnsTrace, TlsTrace,
    normalize_url_input,
};
use crate::request::{
    CertificateCapture, TcpCandidate, connect_tcp_endpoint, make_exposure_tls_config, resolve_host,
    run_diagnostic_session_for_exposure, tls_trace_from_capture, tls_trace_from_stream,
};
use crate::web_server::{FingerprintConfidence, WebProductRole, detect_web_servers};
use base64::Engine as _;
use cookie::{Cookie, SameSite};
use futures_util::stream::{FuturesUnordered, StreamExt};
use rustls::pki_types::ServerName;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;
use url::Url;

#[path = "crawl.rs"]
mod crawl;
#[path = "fingerprints.rs"]
pub(crate) mod fingerprints;
#[path = "javascript.rs"]
mod javascript;
#[path = "technology.rs"]
mod technology;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicPortMetadata {
    pub port: u16,
    pub service_name: &'static str,
    pub exposure_note: &'static str,
}

macro_rules! public_ports {
    ($(($port:literal, $service_name:literal, $exposure_note:literal)),* $(,)?) => {
        pub const CURATED_TCP_PORTS: &[u16] = &[$($port),*];
        pub const CURATED_TCP_PORT_METADATA: &[PublicPortMetadata] = &[
            $(PublicPortMetadata {
                port: $port,
                service_name: $service_name,
                exposure_note: $exposure_note,
            }),*
        ];
    };
}

public_ports![
    (
        21,
        "FTP",
        "File transfer service; identification requires protocol evidence"
    ),
    (22, "SSH", "Secure shell and remote administration service"),
    (
        23,
        "Telnet",
        "Cleartext terminal and remote administration service"
    ),
    (25, "SMTP", "Mail transfer service"),
    (53, "DNS", "TCP DNS service"),
    (80, "HTTP", "Cleartext web service"),
    (
        102,
        "ISO-on-TCP",
        "ISO transport commonly used by Siemens S7 systems"
    ),
    (110, "POP3", "Mail retrieval service"),
    (111, "rpcbind", "ONC RPC service mapper"),
    (135, "MS RPC", "Microsoft RPC endpoint mapper"),
    (139, "NetBIOS session", "NetBIOS session service"),
    (143, "IMAP", "Mail retrieval service"),
    (179, "BGP", "Border Gateway Protocol service"),
    (389, "LDAP", "Directory service"),
    (443, "HTTPS", "TLS-backed web service"),
    (
        445,
        "SMB",
        "Microsoft file sharing and remote administration service"
    ),
    (465, "SMTP over TLS", "TLS-backed mail submission service"),
    (502, "Modbus/TCP", "Industrial control protocol service"),
    (512, "rexec", "Legacy remote execution service"),
    (513, "rlogin", "Legacy remote login service"),
    (514, "remote shell", "Legacy remote shell service over TCP"),
    (548, "AFP", "Apple Filing Protocol service"),
    (587, "SMTP submission", "Mail submission service"),
    (636, "LDAP over TLS", "TLS-backed directory service"),
    (873, "rsync", "File synchronization service"),
    (993, "IMAP over TLS", "TLS-backed mail retrieval service"),
    (995, "POP3 over TLS", "TLS-backed mail retrieval service"),
    (1080, "SOCKS proxy", "SOCKS proxy service"),
    (
        1099,
        "Java RMI registry",
        "Java remote method invocation registry"
    ),
    (1194, "OpenVPN", "OpenVPN TCP listener association"),
    (1433, "Microsoft SQL Server", "Database service"),
    (1521, "Oracle database", "Database service"),
    (1723, "PPTP", "Legacy VPN control service"),
    (1883, "MQTT", "Message broker service"),
    (
        1911,
        "Niagara Fox",
        "Building automation protocol association"
    ),
    (2049, "NFS", "Network file system service"),
    (2181, "ZooKeeper", "Distributed coordination service"),
    (
        2222,
        "SSH alternate",
        "Common alternate secure shell and remote administration service"
    ),
    (
        2375,
        "Docker API",
        "Common cleartext Docker Engine API listener"
    ),
    (
        2376,
        "Docker API over TLS",
        "Common TLS-backed Docker Engine API listener"
    ),
    (2379, "etcd client API", "etcd client management API"),
    (2380, "etcd peer API", "etcd peer service"),
    (
        2404,
        "IEC 60870-5-104",
        "Industrial telecontrol protocol service"
    ),
    (3000, "HTTP application", "Common application web service"),
    (
        3268,
        "LDAP global catalog",
        "Active Directory global catalog service"
    ),
    (
        3269,
        "LDAP global catalog over TLS",
        "TLS-backed Active Directory global catalog service"
    ),
    (3306, "MySQL", "Database service"),
    (3389, "RDP", "Remote desktop service"),
    (4369, "Erlang EPMD", "Erlang port mapper service"),
    (
        4786,
        "Cisco Smart Install",
        "Network device management service association"
    ),
    (4840, "OPC UA", "Industrial interoperability service"),
    (
        5000,
        "HTTP application",
        "Common application and management web service"
    ),
    (5432, "PostgreSQL", "Database service"),
    (
        5601,
        "Kibana",
        "Elasticsearch visualization and management web service"
    ),
    (5671, "AMQP over TLS", "TLS-backed message broker service"),
    (5672, "AMQP", "Message broker service"),
    (5900, "VNC", "Remote desktop service"),
    (5901, "VNC display 1", "Remote desktop display service"),
    (5902, "VNC display 2", "Remote desktop display service"),
    (5903, "VNC display 3", "Remote desktop display service"),
    (
        5938,
        "TeamViewer direct/LAN",
        "Association-only TeamViewer direct or LAN listener port"
    ),
    (5984, "CouchDB", "CouchDB HTTP API"),
    (5985, "WinRM HTTP", "Windows remote management service"),
    (
        5986,
        "WinRM HTTPS",
        "TLS-backed Windows remote management service"
    ),
    (6000, "X11", "X Window System display service"),
    (6379, "Redis", "Data store service"),
    (6443, "Kubernetes API", "Kubernetes control-plane API"),
    (
        7001,
        "HTTP management",
        "Common application server management service"
    ),
    (
        7070,
        "AnyDesk direct connection",
        "Association-only AnyDesk direct-connection listener port"
    ),
    (8000, "HTTP alternate", "Alternate web service"),
    (8008, "HTTP alternate", "Alternate web service"),
    (8009, "AJP", "Apache JServ Protocol service"),
    (8080, "HTTP alternate", "Alternate web service"),
    (
        8081,
        "HTTP alternate",
        "Alternate web or management service"
    ),
    (8086, "InfluxDB", "InfluxDB HTTP API"),
    (8088, "HTTP management", "Common management web service"),
    (
        8089,
        "Splunk management",
        "Common TLS-backed Splunk management API"
    ),
    (
        8291,
        "MikroTik WinBox",
        "Network device management service association"
    ),
    (
        8443,
        "HTTPS alternate",
        "Alternate TLS-backed web or management service"
    ),
    (8500, "Consul", "Consul HTTP API"),
    (8883, "MQTT over TLS", "TLS-backed message broker service"),
    (
        8888,
        "HTTP alternate",
        "Alternate web or management service"
    ),
    (
        9000,
        "HTTP management",
        "Common application or management web service"
    ),
    (
        9001,
        "Supervisor HTTP",
        "Process supervisor management web service"
    ),
    (9042, "Cassandra", "Cassandra native database protocol"),
    (
        9090,
        "HTTP management",
        "Common monitoring or management web service"
    ),
    (9100, "Printer service", "Raw printing service"),
    (9200, "Elasticsearch", "Elasticsearch HTTP API"),
    (
        9300,
        "Elasticsearch transport",
        "Elasticsearch cluster transport service"
    ),
    (9418, "Git protocol", "Native Git repository service"),
    (
        9600,
        "Omron FINS",
        "Industrial controller protocol service association"
    ),
    (
        10000,
        "Webmin",
        "Common TLS-backed Webmin administration service"
    ),
    (10050, "Zabbix agent", "Monitoring agent service"),
    (10051, "Zabbix server", "Monitoring server service"),
    (
        10250,
        "Kubelet API",
        "TLS-backed Kubernetes node management API"
    ),
    (
        10255,
        "Kubelet read-only API",
        "Legacy cleartext Kubernetes node API"
    ),
    (11211, "Memcached", "In-memory cache service"),
    (
        15672,
        "RabbitMQ management",
        "RabbitMQ management web service"
    ),
    (
        20000,
        "DNP3",
        "Industrial telemetry and control protocol service"
    ),
    (
        25672,
        "Erlang distribution",
        "Erlang inter-node distribution service"
    ),
    (27017, "MongoDB", "Database service"),
    (
        44818,
        "EtherNet/IP",
        "Industrial automation protocol service"
    ),
    (50000, "IBM Db2", "Database service association"),
];

pub fn curated_tcp_port_metadata(port: u16) -> Option<&'static PublicPortMetadata> {
    CURATED_TCP_PORT_METADATA
        .binary_search_by_key(&port, |metadata| metadata.port)
        .ok()
        .map(|index| &CURATED_TCP_PORT_METADATA[index])
}

const HTTP_PORTS: &[u16] = &[
    80, 2375, 2379, 2380, 3000, 5000, 5601, 5984, 5985, 7001, 8000, 8008, 8080, 8081, 8086, 8088,
    8500, 8888, 9000, 9001, 9090, 9200, 10255, 15672,
];
const HTTPS_PORTS: &[u16] = &[443, 2376, 5986, 6443, 8089, 8443, 10000, 10250];
const TLS_PORTS: &[u16] = &[
    443, 465, 636, 993, 995, 2376, 3269, 5671, 5986, 6443, 8089, 8443, 8883, 10000, 10250,
];
const MAX_BANNER_BYTES: usize = 4096;
const MAX_HTTP_BODY_BYTES: usize = 32 * 1024;
const MAX_ROOT_HTML_BYTES: usize = 1024 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_WEB_ASSET_REQUESTS: usize = 8;
const MAX_WEB_DISCOVERY_REQUESTS: usize = 24;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CookieKey {
    name: String,
    domain: String,
    path: String,
}

#[derive(Clone)]
struct ParsedSetCookie {
    key: CookieKey,
    value: String,
    host_only: bool,
    secure: bool,
    http_only: bool,
    same_site: Option<SameSite>,
    domain_attribute: bool,
    expires_at: Option<i64>,
    deletion: bool,
    source_scheme: String,
}

#[derive(Clone)]
struct StoredCookie {
    key: CookieKey,
    value: String,
    host_only: bool,
    secure: bool,
    expires_at: Option<i64>,
}

#[derive(Default)]
struct EndpointCookieJar {
    cookies: Vec<StoredCookie>,
}

impl EndpointCookieJar {
    fn observe_response(&mut self, url: &Url, response: &HttpObservation) {
        for header in header_values(response, "set-cookie") {
            if let Some(cookie) = parse_set_cookie(url, header) {
                self.store(cookie);
            }
        }
    }

    fn store(&mut self, cookie: ParsedSetCookie) {
        self.remove_expired();
        if cookie.secure && cookie.source_scheme != "https" {
            return;
        }
        if cookie.source_scheme != "https"
            && self.cookies.iter().any(|existing| {
                existing.secure
                    && existing.key.name == cookie.key.name
                    && existing.key.domain == cookie.key.domain
                    && cookie_path_matches(&cookie.key.path, &existing.key.path)
            })
        {
            return;
        }
        self.cookies.retain(|existing| existing.key != cookie.key);
        if !cookie.deletion {
            self.cookies.push(StoredCookie {
                key: cookie.key,
                value: cookie.value,
                host_only: cookie.host_only,
                secure: cookie.secure,
                expires_at: cookie.expires_at,
            });
        }
    }

    fn eligible(&mut self, url: &Url) -> Vec<StoredCookie> {
        self.remove_expired();
        let Some(host) = url.host_str().map(|host| host.to_ascii_lowercase()) else {
            return Vec::new();
        };
        let mut cookies = self
            .cookies
            .iter()
            .filter(|cookie| {
                (!cookie.secure || url.scheme() == "https")
                    && if cookie.host_only {
                        host == cookie.key.domain
                    } else {
                        cookie_domain_matches(&host, &cookie.key.domain)
                    }
                    && cookie_path_matches(url.path(), &cookie.key.path)
            })
            .cloned()
            .collect::<Vec<_>>();
        cookies.sort_by(|left, right| right.key.path.len().cmp(&left.key.path.len()));
        cookies
    }

    fn cookie_header(&mut self, url: &Url) -> Option<String> {
        let cookies = self.eligible(url);
        (!cookies.is_empty()).then(|| {
            cookies
                .iter()
                .map(|cookie| format!("{}={}", cookie.key.name, cookie.value))
                .collect::<Vec<_>>()
                .join("; ")
        })
    }

    fn remove_expired(&mut self) {
        let now = unix_timestamp();
        self.cookies
            .retain(|cookie| cookie.expires_at.is_none_or(|expires| expires > now));
    }
}

fn parse_set_cookie(url: &Url, header: &str) -> Option<ParsedSetCookie> {
    let parsed = Cookie::parse(header.to_owned()).ok()?;
    let name = parsed.name().to_owned();
    let value = parsed.value().to_owned();
    if !valid_cookie_name(&name) || !valid_cookie_value(&value) {
        return None;
    }
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    let (domain, host_only, domain_attribute) = match parsed.domain() {
        Some(domain) => {
            let domain = domain
                .trim()
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if domain.is_empty() || !cookie_domain_matches(&host, &domain) {
                return None;
            }
            (domain, false, true)
        }
        None => (host, true, false),
    };
    let path = parsed
        .path()
        .filter(|path| path.starts_with('/'))
        .map(str::to_owned)
        .unwrap_or_else(|| default_cookie_path(url.path()));
    let now = unix_timestamp();
    let max_age = parsed.max_age().map(|age| age.whole_seconds());
    let expires_at = max_age
        .map(|seconds| now.saturating_add(seconds))
        .or_else(|| {
            parsed
                .expires_datetime()
                .map(|expires| expires.unix_timestamp())
        });
    let deletion = max_age.is_some_and(|seconds| seconds <= 0)
        || (max_age.is_none() && expires_at.is_some_and(|expires| expires <= now));
    Some(ParsedSetCookie {
        key: CookieKey { name, domain, path },
        value,
        host_only,
        secure: parsed.secure().unwrap_or(false),
        http_only: parsed.http_only().unwrap_or(false),
        same_site: parsed.same_site(),
        domain_attribute,
        expires_at,
        deletion,
        source_scheme: url.scheme().to_ascii_lowercase(),
    })
}

fn valid_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii()
                && !byte.is_ascii_control()
                && !matches!(
                    byte,
                    b' ' | b'\t'
                        | b'('
                        | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        })
}

fn valid_cookie_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e))
}

fn default_cookie_path(request_path: &str) -> String {
    if !request_path.starts_with('/') || request_path.matches('/').count() <= 1 {
        return "/".to_owned();
    }
    request_path
        .rfind('/')
        .map(|index| request_path[..index].to_owned())
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| "/".to_owned())
}

fn cookie_domain_matches(host: &str, domain: &str) -> bool {
    host.eq_ignore_ascii_case(domain)
        || (host.parse::<IpAddr>().is_err()
            && host
                .strip_suffix(domain)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

fn cookie_path_matches(request_path: &str, cookie_path: &str) -> bool {
    request_path == cookie_path
        || request_path
            .strip_prefix(cookie_path)
            .is_some_and(|suffix| cookie_path.ends_with('/') || suffix.starts_with('/'))
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

const SENSITIVE_PATHS: &[&str] = &[
    "/robots.txt",
    "/.well-known/security.txt",
    "/.git/HEAD",
    "/.env",
    "/server-status",
    "/server-info",
    "/debug",
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/swagger",
    "/swagger/index.html",
    "/openapi.json",
    "/api-docs",
    "/phpinfo.php",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PortSelection {
    #[default]
    Curated,
    All,
    Custom(Vec<u16>),
}

impl PortSelection {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "curated" => Ok(Self::Curated),
            "all" => Ok(Self::All),
            _ => parse_custom_ports(value).map(Self::Custom),
        }
    }

    pub fn ports(&self) -> Result<Vec<u16>, String> {
        match self {
            Self::Curated => Ok(CURATED_TCP_PORTS.to_vec()),
            Self::All => Ok((1..=u16::MAX).collect()),
            Self::Custom(ports) if ports.is_empty() => {
                Err("Port selection contains no ports".to_owned())
            }
            Self::Custom(ports) => {
                let mut ports = ports.clone();
                ports.sort_unstable();
                ports.dedup();
                if ports.contains(&0) {
                    Err("Port 0 is not a valid TCP destination port".to_owned())
                } else {
                    Ok(ports)
                }
            }
        }
    }
}

impl FromStr for PortSelection {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

fn parse_custom_ports(value: &str) -> Result<Vec<u16>, String> {
    let mut ports = BTreeSet::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err("Port list contains an empty item".to_owned());
        }
        if let Some((start, end)) = part.split_once('-') {
            let start = parse_port(start)?;
            let end = parse_port(end)?;
            if start > end {
                return Err(format!("Port range {part} is reversed"));
            }
            ports.extend(start..=end);
        } else {
            ports.insert(parse_port(part)?);
        }
    }
    if ports.is_empty() {
        Err("Port selection contains no ports".to_owned())
    } else {
        Ok(ports.into_iter().collect())
    }
}

fn parse_port(value: &str) -> Result<u16, String> {
    value
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("Invalid TCP port '{value}'"))
        .and_then(|port| {
            if port == 0 {
                Err("Port 0 is not a valid TCP destination port".to_owned())
            } else {
                Ok(port)
            }
        })
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
            security_operations: false,
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
        self.ports.ports()?;
        if self.connection_timeout.is_zero() {
            return Err("Connection timeout must be greater than zero".to_owned());
        }
        if self.probe_timeout.is_zero() {
            return Err("Probe timeout must be greater than zero".to_owned());
        }
        if self.concurrency == 0 {
            return Err("Concurrency must be greater than zero".to_owned());
        }
        if self.connection_starts_per_second == 0 {
            return Err("Connection rate must be greater than zero".to_owned());
        }
        if self.crawl_max_urls == 0 {
            return Err("Crawl URL limit must be greater than zero".to_owned());
        }
        if self.crawl_concurrency == 0 {
            return Err("Crawl concurrency must be greater than zero".to_owned());
        }
        if self.crawl_requests_per_second == 0 {
            return Err("Crawl rate must be greater than zero".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExposureScanStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl fmt::Display for ExposureScanStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Running => "Running",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::Cancelled => "Cancelled",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    FilteredOrNoResponse,
    Error,
    Cancelled,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "Open",
            Self::Closed => "Closed",
            Self::FilteredOrNoResponse => "Filtered or no response",
            Self::Error => "Error",
            Self::Cancelled => "Cancelled",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceKind {
    Unknown,
    Http,
    Https,
    Tls,
    Ssh,
    Ftp,
    Smtp,
    Pop3,
    Imap,
    Mysql,
    PostgreSql,
    Redis,
    Rdp,
    Vnc,
    Rsync,
    Memcached,
    ZooKeeper,
    Cassandra,
    ErlangEpmd,
    Git,
    Ajp,
    IsoOnTcp,
    Modbus,
    Iec104,
    OpcUa,
    OmronFins,
    EtherNetIp,
}

impl fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unknown => "Unknown",
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Tls => "TLS",
            Self::Ssh => "SSH",
            Self::Ftp => "FTP",
            Self::Smtp => "SMTP",
            Self::Pop3 => "POP3",
            Self::Imap => "IMAP",
            Self::Mysql => "MySQL protocol",
            Self::PostgreSql => "PostgreSQL protocol",
            Self::Redis => "Redis protocol",
            Self::Rdp => "RDP",
            Self::Vnc => "VNC",
            Self::Rsync => "rsync protocol",
            Self::Memcached => "Memcached protocol",
            Self::ZooKeeper => "ZooKeeper protocol",
            Self::Cassandra => "Cassandra native protocol",
            Self::ErlangEpmd => "Erlang EPMD",
            Self::Git => "Git protocol",
            Self::Ajp => "AJP",
            Self::IsoOnTcp => "ISO-on-TCP",
            Self::Modbus => "Modbus/TCP",
            Self::Iec104 => "IEC 60870-5-104",
            Self::OpcUa => "OPC UA",
            Self::OmronFins => "Omron FINS/TCP",
            Self::EtherNetIp => "EtherNet/IP",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    None,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TechnologyFileType {
    JavaScript,
    Jsx,
    TypeScript,
    Tsx,
    Php,
    Python,
    Ruby,
    Erb,
    Java,
    Jsp,
    Kotlin,
    Jar,
    CSharp,
    Razor,
    AspNet,
    DotNetAssembly,
    Go,
    Rust,
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

impl fmt::Display for TechnologyFileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::JavaScript => "JavaScript",
            Self::Jsx => "JSX",
            Self::TypeScript => "TypeScript",
            Self::Tsx => "TSX",
            Self::Php => "PHP",
            Self::Python => "Python",
            Self::Ruby => "Ruby",
            Self::Erb => "ERB",
            Self::Java => "Java",
            Self::Jsp => "JSP",
            Self::Kotlin => "Kotlin",
            Self::Jar => "JAR",
            Self::CSharp => "C#",
            Self::Razor => "Razor",
            Self::AspNet => "ASP.NET",
            Self::DotNetAssembly => ".NET assembly",
            Self::Go => "Go",
            Self::Rust => "Rust",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TechnologyEcosystem {
    JavaScript,
    Npm,
    Composer,
    WordPress,
    PyPi,
    RubyGems,
    MavenCentral,
    NuGet,
    GoModules,
    CratesIo,
    Runtime,
    WebServer,
}

impl fmt::Display for TechnologyEcosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::JavaScript => "JavaScript",
            Self::Npm => "npm",
            Self::Composer => "Composer/Packagist",
            Self::WordPress => "WordPress",
            Self::PyPi => "PyPI",
            Self::RubyGems => "RubyGems",
            Self::MavenCentral => "Maven Central",
            Self::NuGet => "NuGet",
            Self::GoModules => "Go modules",
            Self::CratesIo => "crates.io",
            Self::Runtime => "Runtime release feed",
            Self::WebServer => "Web server upstream",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TechnologyComponentKind {
    Framework,
    Plugin,
    Runtime,
    Package,
    Server,
}

impl fmt::Display for TechnologyComponentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Framework => "Framework",
            Self::Plugin => "Plugin",
            Self::Runtime => "Runtime",
            Self::Package => "Package",
            Self::Server => "Server",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TechnologySupportStatus {
    NotApplicable,
    NotChecked,
    Supported,
    Unsupported,
    Unknown,
}

impl fmt::Display for TechnologySupportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotApplicable => "Not applicable",
            Self::NotChecked => "Not checked",
            Self::Supported => "Supported",
            Self::Unsupported => "Unsupported",
            Self::Unknown => "Unknown",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TechnologyVersionStatus {
    Unknown,
    InventoryOnly,
    NotChecked,
    Current,
    OutdatedPatch,
    OutdatedMinor,
    OutdatedMajor,
    NewerThanLatest,
    Prerelease,
    Unverifiable,
}

impl fmt::Display for TechnologyVersionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unknown => "Unknown",
            Self::InventoryOnly => "Inventory only",
            Self::NotChecked => "Not checked",
            Self::Current => "Current",
            Self::OutdatedPatch => "Outdated (patch)",
            Self::OutdatedMinor => "Outdated (minor)",
            Self::OutdatedMajor => "Outdated (major)",
            Self::NewerThanLatest => "Newer than latest",
            Self::Prerelease => "Prerelease",
            Self::Unverifiable => "Unverifiable",
        })
    }
}

#[derive(Debug, Clone)]
pub struct DetectedFileType {
    pub file_type: TechnologyFileType,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
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
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProductLayer {
    Protocol,
    Server,
    Proxy,
    Cdn,
    Cloud,
    Framework,
    Runtime,
    Cms,
    Ecommerce,
}

impl fmt::Display for ProductLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Protocol => "Protocol",
            Self::Server => "Server",
            Self::Proxy => "Proxy",
            Self::Cdn => "CDN",
            Self::Cloud => "Cloud",
            Self::Framework => "Framework",
            Self::Runtime => "Runtime",
            Self::Cms => "CMS",
            Self::Ecommerce => "E-commerce",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WebSurfaceType {
    Api,
    Login,
    Admin,
    Cart,
    Checkout,
}

impl fmt::Display for WebSurfaceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Api => "API",
            Self::Login => "Login",
            Self::Admin => "Admin",
            Self::Cart => "Cart",
            Self::Checkout => "Checkout",
        })
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tls12 => "TLS 1.2",
            Self::Tls13 => "TLS 1.3",
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProductDetection {
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
}

#[derive(Debug, Clone)]
pub struct TlsObservation {
    pub requested_version: TlsVersion,
    pub supported: bool,
    pub verified: bool,
    pub unverified: bool,
    pub negotiated_version: Option<String>,
    pub alpn: Option<String>,
    pub cipher: Option<String>,
    pub validation_error: Option<String>,
    pub hostname_valid: Option<bool>,
    pub certificate_expired: Option<bool>,
    pub certificate_not_yet_valid: Option<bool>,
    pub certificates: Vec<CertificateTrace>,
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
    pub tls_unverified: bool,
    pub redirect_location: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaScriptVersionStatus {
    Unknown,
    NotChecked,
    Current,
    OutdatedPatch,
    OutdatedMinor,
    OutdatedMajor,
    NewerThanLatest,
    Prerelease,
    Unverifiable,
}

impl fmt::Display for JavaScriptVersionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unknown => "Unknown",
            Self::NotChecked => "Not checked",
            Self::Current => "Current",
            Self::OutdatedPatch => "Outdated (patch)",
            Self::OutdatedMinor => "Outdated (minor)",
            Self::OutdatedMajor => "Outdated (major)",
            Self::NewerThanLatest => "Newer than newest stable",
            Self::Prerelease => "Prerelease",
            Self::Unverifiable => "Unverifiable",
        })
    }
}

#[derive(Debug, Clone)]
pub struct JavaScriptLibrary {
    pub name: String,
    pub npm_package: Option<String>,
    pub installed_version: Option<String>,
    pub latest_version: Option<String>,
    pub status: JavaScriptVersionStatus,
    pub evidence: Vec<String>,
    pub check_error: Option<String>,
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

#[derive(Debug, Clone)]
pub struct ExposureFinding {
    pub title: String,
    pub description: String,
    pub ip: IpAddr,
    pub port: u16,
    pub evidence: Vec<String>,
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
    pub has_password: bool,
    pub enqueued: bool,
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
    pub state: PortState,
    pub connect_duration_ms: f64,
    pub service: ServiceKind,
    pub service_confidence: Confidence,
    pub products: Vec<ProductDetection>,
    pub web_technologies: Vec<WebTechnologyDetection>,
    pub evidence: Vec<String>,
    pub banner: Vec<u8>,
    pub tls: Vec<TlsObservation>,
    pub http: Vec<HttpObservation>,
    pub observed_web_surfaces: Vec<ObservedWebSurface>,
    pub javascript_sources: Vec<JavaScriptSource>,
    pub technology_components: Vec<TechnologyComponent>,
    pub findings: Vec<ExposureFinding>,
    pub diagnostics: Vec<DiagnosticTrace>,
    pub error: Option<String>,
    javascript_candidates: Vec<String>,
}

impl EndpointScan {
    fn new(ip: IpAddr, port: u16) -> Self {
        Self {
            ip,
            port,
            state: PortState::Error,
            connect_duration_ms: 0.0,
            service: ServiceKind::Unknown,
            service_confidence: Confidence::None,
            products: Vec::new(),
            web_technologies: Vec::new(),
            evidence: Vec::new(),
            banner: Vec::new(),
            tls: Vec::new(),
            http: Vec::new(),
            observed_web_surfaces: Vec::new(),
            javascript_sources: Vec::new(),
            technology_components: Vec::new(),
            findings: Vec::new(),
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
pub struct ExposureScanReport {
    pub request: ExposureScanRequest,
    pub hostname: String,
    pub supplied_port: Option<u16>,
    pub resolved_addresses: Vec<IpAddr>,
    pub ignored_addresses: Vec<IgnoredAddress>,
    pub warnings: Vec<String>,
    pub endpoints: Vec<EndpointScan>,
    pub findings: Vec<ExposureFinding>,
    pub crawl_observed_web_surfaces: Vec<CrawlObservedWebSurface>,
    pub crawl_origins: Vec<CrawlOrigin>,
    pub crawled_resources: Vec<CrawledResource>,
    pub crawl_forms: Vec<CrawlFormAction>,
    pub crawl_external_indicators: Vec<CrawlExternalIndicator>,
    pub crawl_skipped_urls: Vec<CrawlSkippedUrl>,
    pub timings: ExposureScanTimings,
    pub status: ExposureScanStatus,
    pub error: Option<String>,
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
    CrawlProgress {
        origin: String,
        queued: usize,
        completed: usize,
        current_url: String,
    },
    Completed(ExposureScanReport),
}

#[derive(Debug)]
struct ParsedTarget {
    hostname: String,
    supplied_port: Option<u16>,
    seed_url: Option<Url>,
}

fn parse_target(input: &str) -> Result<ParsedTarget, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Target is empty".to_owned());
    }
    let literal = input.trim_matches(['[', ']']);
    if literal.parse::<IpAddr>().is_ok() {
        return Ok(ParsedTarget {
            hostname: literal.to_owned(),
            supplied_port: None,
            seed_url: None,
        });
    }
    let url = if input.contains("://") {
        Url::parse(input).map_err(|error| format!("Invalid target: {error}"))?
    } else {
        Url::parse(&format!("scan://{input}"))
            .map_err(|error| format!("Invalid target: {error}"))?
    };
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Authentication details are not accepted in scan targets".to_owned());
    }
    let hostname = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "Target has no hostname or IP address".to_owned())?
        .trim_matches(['[', ']'])
        .to_owned();
    let seed_url = if matches!(url.scheme(), "http" | "https") {
        Some(
            crawl::normalize_url(url.clone())
                .map_err(|error| format!("Invalid target URL: {error}"))?,
        )
    } else {
        None
    };
    Ok(ParsedTarget {
        hostname,
        supplied_port: url.port(),
        seed_url,
    })
}

pub async fn run_exposure_scan(
    request: ExposureScanRequest,
    cancel: CancellationToken,
    progress: Option<Sender<ExposureScanProgress>>,
) -> ExposureScanReport {
    run_exposure_scan_with_auth_store(request, AuthStore::shared(), cancel, progress).await
}

pub async fn run_exposure_scan_with_auth_store(
    request: ExposureScanRequest,
    auth_store: SharedAuthStore,
    cancel: CancellationToken,
    progress: Option<Sender<ExposureScanProgress>>,
) -> ExposureScanReport {
    fingerprints::ensure_initialized().await;
    let total_started = Instant::now();
    let parsed = match request
        .validate()
        .and_then(|_| parse_target(&request.diagnostic_request.url))
    {
        Ok(parsed) => parsed,
        Err(error) => {
            let report = failed_report(request, error, total_started);
            send_progress(&progress, ExposureScanProgress::Completed(report.clone()));
            return report;
        }
    };
    send_progress(
        &progress,
        ExposureScanProgress::Resolving {
            target: parsed.hostname.clone(),
        },
    );
    let mut report = ExposureScanReport {
        request: request.clone(),
        hostname: parsed.hostname.clone(),
        supplied_port: parsed.supplied_port,
        resolved_addresses: Vec::new(),
        ignored_addresses: Vec::new(),
        warnings: Vec::new(),
        endpoints: Vec::new(),
        findings: Vec::new(),
        crawl_observed_web_surfaces: Vec::new(),
        crawl_origins: Vec::new(),
        crawled_resources: Vec::new(),
        crawl_forms: Vec::new(),
        crawl_external_indicators: Vec::new(),
        crawl_skipped_urls: Vec::new(),
        timings: ExposureScanTimings::default(),
        status: ExposureScanStatus::Running,
        error: None,
    };
    let resolution_started = Instant::now();
    let mut dns = DnsTrace::default();
    let resolution = tokio::select! {
        _ = cancel.cancelled() => Err("Scan cancelled during name resolution".to_owned()),
        result = resolve_host(&parsed.hostname, &mut dns) => result,
    };
    report.timings.resolution_ms = elapsed_ms(resolution_started);
    if cancel.is_cancelled() {
        report.status = ExposureScanStatus::Cancelled;
        report.error = Some("Scan cancelled".to_owned());
        finish_report(&mut report, total_started);
        send_progress(&progress, ExposureScanProgress::Completed(report.clone()));
        return report;
    }
    if let Err(error) = resolution {
        report.status = ExposureScanStatus::Failed;
        report.error = Some(error);
        finish_report(&mut report, total_started);
        send_progress(&progress, ExposureScanProgress::Completed(report.clone()));
        return report;
    }
    let mut seen = HashSet::new();
    for address in dns.addresses {
        if !seen.insert(address) {
            continue;
        }
        if let Some(reason) = non_public_reason(address) {
            report.warnings.push(format!("Ignored {address}: {reason}"));
            report.ignored_addresses.push(IgnoredAddress {
                address,
                reason: reason.to_owned(),
            });
        } else {
            report.resolved_addresses.push(address);
        }
    }
    if report.resolved_addresses.is_empty() {
        report.status = ExposureScanStatus::Failed;
        report.error = Some("Target has no publicly routable A or AAAA address".to_owned());
        finish_report(&mut report, total_started);
        send_progress(&progress, ExposureScanProgress::Completed(report.clone()));
        return report;
    }
    let mut ports = request.ports.ports().unwrap_or_default();
    if let Some(port) = parsed.supplied_port
        && !ports.contains(&port)
    {
        ports.push(port);
        ports.sort_unstable();
    }
    let total_endpoints = report.resolved_addresses.len().saturating_mul(ports.len());
    send_progress(
        &progress,
        ExposureScanProgress::Resolved {
            public_addresses: report.resolved_addresses.clone(),
            total_endpoints,
        },
    );
    let scan_started = Instant::now();
    let limiter = Arc::new(ConnectionRateLimiter::new(
        request.connection_starts_per_second,
    ));
    let mut pending = FuturesUnordered::new();
    let mut address_index = 0usize;
    let mut port_index = 0usize;
    let mut completed = 0usize;
    let mut scheduling_done = false;
    loop {
        while !scheduling_done && !cancel.is_cancelled() && pending.len() < request.concurrency {
            if address_index >= report.resolved_addresses.len() {
                scheduling_done = true;
                break;
            }
            let ip = report.resolved_addresses[address_index];
            let port = ports[port_index];
            let hostname = parsed.hostname.clone();
            let scan_request = request.clone();
            let endpoint_cancel = cancel.clone();
            let endpoint_limiter = limiter.clone();
            pending.push(async move {
                let scan = ScanContext {
                    hostname: &hostname,
                    request: &scan_request,
                    cancel: &endpoint_cancel,
                    limiter: &endpoint_limiter,
                };
                scan_endpoint(ProbeContext { ip, port, scan }).await
            });
            port_index += 1;
            if port_index == ports.len() {
                port_index = 0;
                address_index += 1;
            }
        }
        if pending.is_empty() {
            break;
        }
        if let Some(endpoint) = pending.next().await {
            completed += 1;
            send_progress(
                &progress,
                ExposureScanProgress::EndpointCompleted {
                    completed,
                    total: total_endpoints,
                    endpoint: endpoint.clone(),
                },
            );
            report.endpoints.push(endpoint);
        }
        if cancel.is_cancelled() {
            scheduling_done = true;
        }
    }
    report.endpoints.sort_by(|left, right| {
        left.ip
            .to_string()
            .cmp(&right.ip.to_string())
            .then(left.port.cmp(&right.port))
    });
    if !cancel.is_cancelled() {
        run_endpoint_diagnostics(
            &mut report.endpoints,
            &request,
            &parsed.hostname,
            auth_store,
            &cancel,
            limiter.clone(),
        )
        .await;
    }
    if request.security_operations && !cancel.is_cancelled() {
        let crawl = crawl::run(
            &request,
            &parsed.hostname,
            parsed.seed_url.as_ref(),
            &report.endpoints,
            &cancel,
            &progress,
        )
        .await;
        for (ip, port, source) in &crawl.javascript_candidates {
            if let Some(endpoint) = report
                .endpoints
                .iter_mut()
                .find(|endpoint| endpoint.ip == *ip && endpoint.port == *port)
                && !endpoint.javascript_candidates.contains(source)
            {
                endpoint.javascript_candidates.push(source.clone());
            }
        }
        for resource in &crawl.technology_resources {
            if resource.detected_file_types.iter().any(|detected| {
                matches!(
                    detected.file_type,
                    TechnologyFileType::JavaScript
                        | TechnologyFileType::Jsx
                        | TechnologyFileType::TypeScript
                        | TechnologyFileType::Tsx
                )
            }) && let Some(endpoint) = report
                .endpoints
                .iter_mut()
                .find(|endpoint| endpoint.ip == resource.ip && endpoint.port == resource.port)
                && !endpoint.javascript_candidates.contains(&resource.fetch_url)
            {
                endpoint
                    .javascript_candidates
                    .push(resource.fetch_url.clone());
            }
        }
        let mut enrichment = javascript::EnrichmentState::new();
        let javascript = javascript::analyze(
            &mut report.endpoints,
            &request,
            &cancel,
            limiter.as_ref(),
            &mut enrichment,
        )
        .await;
        report.warnings.extend(javascript.warnings);
        report.warnings.extend(fingerprints::detect(
            &mut report.endpoints,
            &crawl.technology_resources,
            &javascript.captured_responses,
        ));
        reconcile_web_server_products(&mut report.endpoints);
        let technology = technology::analyze(
            &mut report.endpoints,
            &crawl.technology_resources,
            &request,
            &cancel,
            limiter.as_ref(),
            &mut enrichment,
        )
        .await;
        report.warnings.extend(technology.warnings);
        report.findings.extend(crawl.findings);
        report.findings.extend(technology.findings);
        report.crawl_observed_web_surfaces = crawl.observed_web_surfaces;
        report.crawl_origins = crawl.origins;
        report.crawled_resources = crawl.resources;
        report.crawl_forms = crawl.forms;
        report.crawl_external_indicators = crawl.external_indicators;
        report.crawl_skipped_urls = crawl.skipped_urls;
    } else if !cancel.is_cancelled() {
        report
            .warnings
            .extend(fingerprints::detect(&mut report.endpoints, &[], &[]));
        reconcile_web_server_products(&mut report.endpoints);
    }
    report.timings.scan_ms = elapsed_ms(scan_started);
    report.status = if cancel.is_cancelled() {
        ExposureScanStatus::Cancelled
    } else {
        ExposureScanStatus::Completed
    };
    if cancel.is_cancelled() {
        report.error = Some("Scan cancelled".to_owned());
    }
    finish_report(&mut report, total_started);
    send_progress(&progress, ExposureScanProgress::Completed(report.clone()));
    report
}

async fn run_endpoint_diagnostics(
    endpoints: &mut [EndpointScan],
    request: &ExposureScanRequest,
    hostname: &str,
    auth_store: SharedAuthStore,
    cancel: &CancellationToken,
    limiter: Arc<ConnectionRateLimiter>,
) {
    let jobs = endpoints
        .iter()
        .enumerate()
        .filter_map(|(index, endpoint)| {
            diagnostic_scheme(endpoint).map(|scheme| (index, endpoint.ip, endpoint.port, scheme))
        })
        .collect::<Vec<_>>();
    let mut pending = FuturesUnordered::new();
    let mut next = 0usize;
    loop {
        while next < jobs.len() && pending.len() < request.concurrency && !cancel.is_cancelled() {
            let (index, ip, port, scheme) = jobs[next];
            next += 1;
            let diagnostic_request =
                endpoint_diagnostic_request(&request.diagnostic_request, hostname, scheme, port);
            let auth_store = auth_store.clone();
            let cancel = cancel.clone();
            let limiter = limiter.clone();
            pending.push(async move {
                let traces = run_diagnostic_session_for_exposure(
                    1,
                    diagnostic_request,
                    auth_store,
                    cancel,
                    ip,
                    limiter,
                )
                .await;
                (index, traces)
            });
        }
        let Some((index, traces)) = pending.next().await else {
            break;
        };
        endpoints[index].diagnostics = traces;
        if cancel.is_cancelled() {
            break;
        }
    }
}

fn diagnostic_scheme(endpoint: &EndpointScan) -> Option<&'static str> {
    if endpoint
        .http
        .iter()
        .any(|observation| observation.url.starts_with("https://"))
    {
        Some("https")
    } else if endpoint
        .http
        .iter()
        .any(|observation| observation.url.starts_with("http://"))
    {
        Some("http")
    } else {
        None
    }
}

fn endpoint_diagnostic_request(
    configured: &DiagnosticRequest,
    hostname: &str,
    scheme: &str,
    port: u16,
) -> DiagnosticRequest {
    let mut request = configured.clone();
    let literal_ip = configured
        .url
        .trim()
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .is_ok();
    let fallback_url = || {
        let host = if hostname.contains(':') {
            format!("[{hostname}]")
        } else {
            hostname.to_owned()
        };
        Url::parse(&format!("https://{host}/"))
    };
    let parsed_url = if literal_ip {
        fallback_url()
    } else {
        Url::parse(&normalize_url_input(&configured.url)).or_else(|_| fallback_url())
    };
    if let Ok(mut url) = parsed_url {
        let _ = url.set_scheme(scheme);
        let url_hostname = if hostname.contains(':') {
            format!("[{hostname}]")
        } else {
            hostname.to_owned()
        };
        let _ = url.set_host(Some(&url_hostname));
        let _ = url.set_port(Some(port));
        request.url = url.to_string();
    }
    request
}

fn failed_report(
    request: ExposureScanRequest,
    error: String,
    started: Instant,
) -> ExposureScanReport {
    ExposureScanReport {
        request,
        hostname: String::new(),
        supplied_port: None,
        resolved_addresses: Vec::new(),
        ignored_addresses: Vec::new(),
        warnings: Vec::new(),
        endpoints: Vec::new(),
        findings: Vec::new(),
        crawl_observed_web_surfaces: Vec::new(),
        crawl_origins: Vec::new(),
        crawled_resources: Vec::new(),
        crawl_forms: Vec::new(),
        crawl_external_indicators: Vec::new(),
        crawl_skipped_urls: Vec::new(),
        timings: ExposureScanTimings {
            total_ms: elapsed_ms(started),
            ..Default::default()
        },
        status: ExposureScanStatus::Failed,
        error: Some(error),
    }
}

fn finish_report(report: &mut ExposureScanReport, started: Instant) {
    let crawl_findings = std::mem::take(&mut report.findings);
    let mut findings =
        build_security_summary(&report.endpoints, report.request.security_operations)
            .into_iter()
            .map(|finding| (security_summary_finding_key(&finding), finding))
            .collect::<BTreeMap<_, _>>();
    for finding in crawl_findings {
        add_security_summary_finding(&mut findings, finding);
    }
    report.findings = findings.into_values().collect();
    report.timings.total_ms = elapsed_ms(started);
}

fn build_security_summary(
    endpoints: &[EndpointScan],
    include_csp_warnings: bool,
) -> Vec<ExposureFinding> {
    let mut findings = BTreeMap::new();
    for endpoint in endpoints {
        for finding in &endpoint.findings {
            add_security_summary_finding(&mut findings, finding.clone());
        }
        if include_csp_warnings {
            for response in &endpoint.http {
                for policy in header_values(response, "content-security-policy") {
                    add_csp_findings(&mut findings, endpoint.ip, endpoint.port, policy);
                }
            }
            add_cookie_findings(&mut findings, endpoint);
            add_url_credential_findings(&mut findings, endpoint);
            add_web_storage_findings(&mut findings, endpoint);
        }
    }
    findings.into_values().collect()
}

#[derive(Clone, PartialEq, Eq)]
struct CookieSecurityAttributes {
    secure: bool,
    http_only: bool,
    same_site: Option<SameSite>,
}

fn add_cookie_findings(findings: &mut SecuritySummaryFindings, endpoint: &EndpointScan) {
    let mut jar = EndpointCookieJar::default();
    let mut records = Vec::new();
    let mut continuity = HashMap::<CookieKey, usize>::new();
    for response in &endpoint.http {
        let Ok(url) = Url::parse(&response.url) else {
            continue;
        };
        let sent = if matches!(response.method.as_str(), "GET" | "HEAD") {
            jar.eligible(&url)
        } else {
            Vec::new()
        };
        let mut continued = HashSet::new();
        for header in header_values(response, "set-cookie") {
            let Some(cookie) = parse_set_cookie(&url, header) else {
                continue;
            };
            if !cookie.deletion
                && sent.iter().any(|sent| sent.key == cookie.key)
                && continued.insert(cookie.key.clone())
            {
                *continuity.entry(cookie.key.clone()).or_default() += 1;
            }
            jar.store(cookie.clone());
            records.push((cookie, safe_source_url(&url)));
        }
    }

    let sensitive_keys = records
        .iter()
        .filter(|(cookie, _)| {
            recognized_sensitive_cookie(&cookie.key.name)
                || is_structured_credential(&cookie.value)
                || continuity.get(&cookie.key).copied().unwrap_or_default() >= 2
        })
        .map(|(cookie, _)| cookie.key.clone())
        .collect::<HashSet<_>>();
    let mut previous = HashMap::<CookieKey, CookieSecurityAttributes>::new();
    for (cookie, source) in records {
        if cookie.deletion {
            continue;
        }
        let name = safe_evidence_name(&cookie.key.name);
        let sensitive = sensitive_keys.contains(&cookie.key);
        if sensitive && !cookie.secure {
            add_operations_finding(
                findings,
                endpoint,
                "Security-sensitive cookie lacks Secure",
                "A security-sensitive cookie can be sent without requiring encrypted transport",
                format!("Cookie '{name}' issued by {source} omits Secure"),
            );
        }
        if sensitive && http_only_applies(&cookie.key.name) && !cookie.http_only {
            add_operations_finding(
                findings,
                endpoint,
                "Security-sensitive cookie lacks HttpOnly",
                "A security-sensitive cookie is accessible to client-side scripts",
                format!("Cookie '{name}' issued by {source} omits HttpOnly"),
            );
        }
        if sensitive && cookie.same_site.is_none() {
            add_operations_finding(
                findings,
                endpoint,
                "Security-sensitive cookie lacks SameSite",
                "A security-sensitive cookie has no explicit SameSite restriction",
                format!("Cookie '{name}' issued by {source} omits SameSite"),
            );
        }
        if cookie.same_site == Some(SameSite::None) && !cookie.secure {
            add_operations_finding(
                findings,
                endpoint,
                "SameSite=None cookie lacks Secure",
                "A cookie declares SameSite=None without the required Secure attribute",
                format!("Cookie '{name}' issued by {source}; value withheld"),
            );
        }
        if cookie.key.name.starts_with("__Secure-")
            && (!cookie.secure || cookie.source_scheme != "https")
        {
            add_operations_finding(
                findings,
                endpoint,
                "Invalid __Secure- cookie prefix requirements",
                "A __Secure- cookie was not issued over HTTPS with the Secure attribute",
                format!("Cookie '{name}' issued by {source}"),
            );
        }
        if cookie.key.name.starts_with("__Host-")
            && (!cookie.secure
                || cookie.source_scheme != "https"
                || cookie.domain_attribute
                || cookie.key.path != "/")
        {
            add_operations_finding(
                findings,
                endpoint,
                "Invalid __Host- cookie prefix requirements",
                "A __Host- cookie did not meet HTTPS, Secure, host-only, and Path=/ requirements",
                format!("Cookie '{name}' issued by {source}"),
            );
        }
        if sensitive && cookie.source_scheme == "http" {
            add_operations_finding(
                findings,
                endpoint,
                "Security-sensitive cookie issued over cleartext HTTP",
                "A security-sensitive cookie was issued without transport encryption",
                format!("Cookie '{name}' issued by {source}; value withheld"),
            );
        }
        let attributes = CookieSecurityAttributes {
            secure: cookie.secure,
            http_only: cookie.http_only,
            same_site: cookie.same_site,
        };
        if sensitive
            && let Some(prior) = previous.insert(cookie.key.clone(), attributes.clone())
            && prior != attributes
        {
            let mut changed = Vec::new();
            if prior.secure != attributes.secure {
                changed.push("Secure");
            }
            if prior.http_only != attributes.http_only {
                changed.push("HttpOnly");
            }
            if prior.same_site != attributes.same_site {
                changed.push("SameSite");
            }
            add_operations_finding(
                findings,
                endpoint,
                "Cookie security attributes conflict across reissues",
                "The same security-sensitive cookie was reissued with different security attributes",
                format!(
                    "Cookie '{name}' changed {} at {source}; values withheld",
                    changed.join(", ")
                ),
            );
        }
    }
}

fn add_url_credential_findings(findings: &mut SecuritySummaryFindings, endpoint: &EndpointScan) {
    let mut seen = HashSet::new();
    for response in &endpoint.http {
        let Ok(url) = Url::parse(&response.url) else {
            continue;
        };
        inspect_credential_url(findings, endpoint, &url, &mut seen);
        if let Some(location) = response.redirect_location.as_deref()
            && let Ok(location) = url.join(location)
        {
            inspect_credential_url(findings, endpoint, &location, &mut seen);
        }
    }
}

fn inspect_credential_url(
    findings: &mut SecuritySummaryFindings,
    endpoint: &EndpointScan,
    url: &Url,
    seen: &mut HashSet<(String, String)>,
) {
    for (name, value) in url.query_pairs() {
        if session_parameter_name(&name) && is_credential_shaped(&value) {
            let source = safe_source_url(url);
            let name = safe_evidence_name(&name);
            if seen.insert((source.clone(), name.clone())) {
                add_operations_finding(
                    findings,
                    endpoint,
                    "Session or token identifier exposed in a URL",
                    "A credential-shaped session or token identifier appears in a URL query parameter",
                    format!("Parameter '{name}' appears in {source}; value withheld"),
                );
            }
        }
    }
}

fn add_web_storage_findings(findings: &mut SecuritySummaryFindings, endpoint: &EndpointScan) {
    let documents = endpoint
        .http
        .iter()
        .filter(|response| response_is_html(response))
        .filter_map(|response| Url::parse(&response.url).ok().map(|url| (response, url)))
        .collect::<Vec<_>>();
    let mut reported = HashSet::new();
    for (response, url) in &documents {
        let source = safe_source_url(url);
        let text = String::from_utf8_lossy(&response.body);
        for script in inline_script_blocks(&text) {
            report_storage_writes(findings, endpoint, &source, script, &mut reported);
        }
    }
    for response in endpoint
        .http
        .iter()
        .filter(|response| response_is_javascript(response))
    {
        let Ok(url) = Url::parse(&response.url) else {
            continue;
        };
        if !documents
            .iter()
            .any(|(_, document_url)| same_origin(document_url, &url))
        {
            continue;
        }
        let source = safe_source_url(&url);
        let text = String::from_utf8_lossy(&response.body);
        report_storage_writes(findings, endpoint, &source, &text, &mut reported);
    }
}

fn report_storage_writes(
    findings: &mut SecuritySummaryFindings,
    endpoint: &EndpointScan,
    source: &str,
    script: &str,
    reported: &mut HashSet<(String, String, String)>,
) {
    for write in storage_writes(script) {
        let key = safe_evidence_name(&write.key);
        if !reported.insert((write.storage.to_owned(), key.clone(), source.to_owned())) {
            continue;
        }
        add_operations_finding(
            findings,
            endpoint,
            &format!("Authentication data written to {}", write.storage),
            &format!(
                "Client-side code directly writes authentication or session data to {}",
                write.storage
            ),
            format!("Key '{key}' written by {source}; stored value withheld"),
        );
    }
}

fn add_operations_finding(
    findings: &mut SecuritySummaryFindings,
    endpoint: &EndpointScan,
    title: &str,
    description: &str,
    evidence: String,
) {
    add_security_summary_finding(
        findings,
        ExposureFinding {
            title: title.to_owned(),
            description: description.to_owned(),
            ip: endpoint.ip,
            port: endpoint.port,
            evidence: vec![evidence],
        },
    );
}

fn recognized_sensitive_cookie(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "session"
            | "sessionid"
            | "session_id"
            | "sid"
            | "jsessionid"
            | "phpsessid"
            | "asp.net_sessionid"
            | ".aspnetcore.cookies"
            | "connect.sid"
            | "laravel_session"
            | "ci_session"
            | "rack.session"
            | "auth"
            | "auth_token"
            | "authorization"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "jwt"
            | "jwt_token"
            | "remember_token"
            | "csrftoken"
            | "csrf_token"
            | "xsrf-token"
            | "next-auth.session-token"
            | "authjs.session-token"
    ) || lower.starts_with("aspsessionid")
        || lower.starts_with("wordpress_logged_in_")
        || lower.starts_with("wordpress_sec_")
        || lower.starts_with("wp_woocommerce_session_")
        || lower.starts_with("__secure-next-auth.session-token")
        || lower.starts_with("__secure-authjs.session-token")
}

fn http_only_applies(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "csrftoken" | "csrf_token" | "xsrf-token"
    )
}

fn session_parameter_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "sid"
            | "session"
            | "sessionid"
            | "session_id"
            | "jsessionid"
            | "phpsessid"
            | "token"
            | "access_token"
            | "auth_token"
            | "id_token"
            | "jwt"
            | "ticket"
            | "sso_token"
    )
}

fn is_structured_credential(value: &str) -> bool {
    let value = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value);
    let segments = value.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return false;
    }
    let decode = |segment: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(segment))
            .ok()
    };
    let Some(header) = decode(segments[0]) else {
        return false;
    };
    let Some(payload) = decode(segments[1]) else {
        return false;
    };
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header) else {
        return false;
    };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        return false;
    };
    header.get("alg").and_then(|value| value.as_str()).is_some()
        && payload.as_object().is_some_and(|payload| {
            ["sub", "iss", "aud", "exp", "iat", "nbf", "jti"]
                .iter()
                .any(|claim| payload.contains_key(*claim))
        })
}

fn is_credential_shaped(value: &str) -> bool {
    let value = value.trim();
    if is_structured_credential(value) {
        return true;
    }
    let value = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value);
    if !(24..=2048).contains(&value.len())
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=' | b'%')
        })
    {
        return false;
    }
    let unique = value.bytes().collect::<HashSet<_>>().len();
    let has_letter = value.bytes().any(|byte| byte.is_ascii_alphabetic());
    let has_digit = value.bytes().any(|byte| byte.is_ascii_digit());
    unique >= 10 && has_letter && has_digit
}

fn safe_source_url(url: &Url) -> String {
    let Some(host) = url.host_str() else {
        return "URL withheld".to_owned();
    };
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    format!("{}://{}{port}{}", url.scheme(), url_host(host), url.path())
}

fn safe_evidence_name(value: &str) -> String {
    let mut output = value
        .chars()
        .filter(|character| !character.is_control())
        .take(80)
        .collect::<String>();
    if value.chars().count() > 80 {
        output.push('…');
    }
    output
}

fn response_is_html(response: &HttpObservation) -> bool {
    header_values(response, "content-type")
        .any(|value| value.to_ascii_lowercase().contains("text/html"))
}

fn response_is_javascript(response: &HttpObservation) -> bool {
    header_values(response, "content-type").any(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("javascript") || value.contains("ecmascript")
    }) || Url::parse(&response.url)
        .ok()
        .is_some_and(|url| url.path().to_ascii_lowercase().ends_with(".js"))
}

fn inline_script_blocks(document: &str) -> Vec<&str> {
    let lower = document.to_ascii_lowercase();
    let mut scripts = Vec::new();
    let mut position = 0usize;
    while let Some(relative_start) = lower[position..].find("<script") {
        let start = position + relative_start;
        let Some(relative_open_end) = lower[start..].find('>') else {
            break;
        };
        let open_end = start + relative_open_end + 1;
        let Some(relative_close) = lower[open_end..].find("</script") else {
            break;
        };
        let close = open_end + relative_close;
        if html_attribute(&document[start..open_end], "src").is_none() {
            scripts.push(&document[open_end..close]);
        }
        position = close + "</script".len();
    }
    scripts
}

#[derive(Clone)]
enum ScriptToken {
    Identifier(String),
    Text(String),
    Punctuation(char),
}

struct StorageWrite {
    storage: &'static str,
    key: String,
}

fn storage_writes(script: &str) -> Vec<StorageWrite> {
    let tokens = tokenize_script(script);
    let mut writes = Vec::new();
    for index in 0..tokens.len() {
        let storage = match tokens.get(index) {
            Some(ScriptToken::Identifier(name)) if name == "localStorage" => "localStorage",
            Some(ScriptToken::Identifier(name)) if name == "sessionStorage" => "sessionStorage",
            _ => continue,
        };
        if token_punctuation(&tokens, index + 1, '.')
            && token_identifier(&tokens, index + 2) == Some("setItem")
            && token_punctuation(&tokens, index + 3, '(')
            && let Some(key) = token_text(&tokens, index + 4)
            && token_punctuation(&tokens, index + 5, ',')
        {
            let sensitive_value = token_text(&tokens, index + 6).is_some_and(is_credential_shaped);
            if storage_key_sensitive(key) || sensitive_value {
                writes.push(StorageWrite {
                    storage,
                    key: key.to_owned(),
                });
            }
            continue;
        }
        let property_key = if token_punctuation(&tokens, index + 1, '.') {
            token_identifier(&tokens, index + 2).map(str::to_owned)
        } else if token_punctuation(&tokens, index + 1, '[')
            && token_punctuation(&tokens, index + 3, ']')
        {
            token_text(&tokens, index + 2).map(str::to_owned)
        } else {
            None
        };
        let assignment_index = if token_punctuation(&tokens, index + 1, '.') {
            index + 3
        } else {
            index + 4
        };
        let Some(key) = property_key else {
            continue;
        };
        if token_punctuation(&tokens, assignment_index, '=')
            && !token_punctuation(&tokens, assignment_index + 1, '=')
        {
            let sensitive_value =
                token_text(&tokens, assignment_index + 1).is_some_and(is_credential_shaped);
            if storage_key_sensitive(&key) || sensitive_value {
                writes.push(StorageWrite { storage, key });
            }
        }
    }
    writes
}

fn tokenize_script(script: &str) -> Vec<ScriptToken> {
    let bytes = script.as_bytes();
    let mut tokens = Vec::new();
    let mut position = 0usize;
    while position < bytes.len() {
        if bytes[position].is_ascii_whitespace() {
            position += 1;
            continue;
        }
        if bytes[position..].starts_with(b"//") {
            position += 2;
            while position < bytes.len() && !matches!(bytes[position], b'\r' | b'\n') {
                position += 1;
            }
            continue;
        }
        if bytes[position..].starts_with(b"/*") {
            position += 2;
            while position + 1 < bytes.len() && !bytes[position..].starts_with(b"*/") {
                position += 1;
            }
            position = (position + 2).min(bytes.len());
            continue;
        }
        let byte = bytes[position];
        if matches!(byte, b'\'' | b'"' | b'`') {
            let quote = byte;
            position += 1;
            let mut value = String::new();
            let mut complete = false;
            while position < bytes.len() {
                let byte = bytes[position];
                if byte == b'\\' && position + 1 < bytes.len() {
                    value.push(bytes[position + 1] as char);
                    position += 2;
                } else if byte == quote {
                    position += 1;
                    complete = true;
                    break;
                } else {
                    value.push(byte as char);
                    position += 1;
                }
            }
            if complete {
                tokens.push(ScriptToken::Text(value));
            }
            continue;
        }
        if byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$') {
            let start = position;
            position += 1;
            while position < bytes.len()
                && (bytes[position].is_ascii_alphanumeric()
                    || matches!(bytes[position], b'_' | b'$'))
            {
                position += 1;
            }
            tokens.push(ScriptToken::Identifier(
                String::from_utf8_lossy(&bytes[start..position]).into_owned(),
            ));
            continue;
        }
        tokens.push(ScriptToken::Punctuation(byte as char));
        position += 1;
    }
    tokens
}

fn token_punctuation(tokens: &[ScriptToken], index: usize, expected: char) -> bool {
    matches!(tokens.get(index), Some(ScriptToken::Punctuation(value)) if *value == expected)
}

fn token_identifier(tokens: &[ScriptToken], index: usize) -> Option<&str> {
    match tokens.get(index) {
        Some(ScriptToken::Identifier(value)) => Some(value),
        _ => None,
    }
}

fn token_text(tokens: &[ScriptToken], index: usize) -> Option<&str> {
    match tokens.get(index) {
        Some(ScriptToken::Text(value)) => Some(value),
        _ => None,
    }
}

fn storage_key_sensitive(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "auth"
            | "authentication"
            | "authorization"
            | "credential"
            | "credentials"
            | "jwt"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "authtoken"
            | "bearertoken"
            | "session"
            | "sessionid"
            | "sessiontoken"
    ) || normalized.ends_with("authtoken")
        || normalized.ends_with("accesstoken")
        || normalized.ends_with("refreshtoken")
        || normalized.ends_with("sessiontoken")
        || normalized.ends_with("sessionid")
}

type SecuritySummaryFindings = BTreeMap<(Option<IpAddr>, Option<u16>, String), ExposureFinding>;

fn security_summary_finding_key(
    finding: &ExposureFinding,
) -> (Option<IpAddr>, Option<u16>, String) {
    if finding.title == "Browser security headers are missing"
        || finding.title == "Session-like cookie attributes are missing"
        || finding.title.starts_with("Content-Security-Policy ")
    {
        (None, None, finding.title.clone())
    } else {
        (Some(finding.ip), Some(finding.port), finding.title.clone())
    }
}

fn add_security_summary_finding(
    findings: &mut SecuritySummaryFindings,
    mut finding: ExposureFinding,
) {
    let retain_first_only = finding.title == "Session-like cookie attributes are missing";
    if retain_first_only {
        finding.evidence.truncate(1);
    }
    let key = security_summary_finding_key(&finding);
    if let Some(existing) = findings.get_mut(&key) {
        if retain_first_only || (existing.ip, existing.port) != (finding.ip, finding.port) {
            return;
        }
        existing.evidence.extend(finding.evidence);
        existing.evidence.sort();
        existing.evidence.dedup();
    } else {
        findings.insert(key, finding);
    }
}

fn add_csp_findings(findings: &mut SecuritySummaryFindings, ip: IpAddr, port: u16, policy: &str) {
    let mut default_sources = None;
    let mut script_sources = None;
    let mut script_element_sources = None;
    let mut script_attribute_sources = None;
    for directive in policy.split(';') {
        let mut parts = directive.split_ascii_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let sources = parts.collect::<Vec<_>>();
        match name.to_ascii_lowercase().as_str() {
            "default-src" if default_sources.is_none() => default_sources = Some(sources),
            "script-src" if script_sources.is_none() => script_sources = Some(sources),
            "script-src-elem" if script_element_sources.is_none() => {
                script_element_sources = Some(sources)
            }
            "script-src-attr" if script_attribute_sources.is_none() => {
                script_attribute_sources = Some(sources)
            }
            _ => {}
        }
    }
    let base_sources = script_sources.as_deref().or(default_sources.as_deref());
    let element_sources = script_element_sources.as_deref().or(base_sources);
    let attribute_sources = script_attribute_sources.as_deref().or(base_sources);
    if element_sources
        .is_some_and(|sources| sources.iter().any(|source| is_remote_script_source(source)))
    {
        add_security_summary_finding(
            findings,
            ExposureFinding {
                ip,
                port,
                title: "Content-Security-Policy permits remote script sources".to_owned(),
                description: "The policy allows scripts to load from remote sources".to_owned(),
                evidence: vec![format!("Content-Security-Policy: {policy}")],
            },
        );
    }
    if element_sources
        .into_iter()
        .chain(attribute_sources)
        .flatten()
        .any(|source| source.eq_ignore_ascii_case("'unsafe-inline'"))
    {
        add_security_summary_finding(
            findings,
            ExposureFinding {
                ip,
                port,
                title: "Content-Security-Policy permits inline script execution".to_owned(),
                description: "The policy allows inline script execution".to_owned(),
                evidence: vec![format!("Content-Security-Policy: {policy}")],
            },
        );
    }
    if base_sources.is_some_and(|sources| {
        sources
            .iter()
            .any(|source| source.eq_ignore_ascii_case("'unsafe-eval'"))
    }) {
        add_security_summary_finding(
            findings,
            ExposureFinding {
                ip,
                port,
                title: "Content-Security-Policy permits eval-style script execution".to_owned(),
                description: "The policy allows eval-style script execution".to_owned(),
                evidence: vec![format!("Content-Security-Policy: {policy}")],
            },
        );
    }
}

fn is_remote_script_source(source: &str) -> bool {
    let source = source.trim_end_matches(',').to_ascii_lowercase();
    !source.is_empty()
        && !source.starts_with('\'')
        && !matches!(
            source.as_str(),
            "none" | "self" | "data:" | "blob:" | "filesystem:"
        )
}

fn send_progress(progress: &Option<Sender<ExposureScanProgress>>, event: ExposureScanProgress) {
    if let Some(progress) = progress {
        let _ = progress.send(event);
    }
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

pub(crate) fn non_public_reason(address: IpAddr) -> Option<&'static str> {
    match address {
        IpAddr::V4(ip) => non_public_v4_reason(ip),
        IpAddr::V6(ip) => non_public_v6_reason(ip),
    }
}

fn non_public_v4_reason(ip: Ipv4Addr) -> Option<&'static str> {
    let octets = ip.octets();
    if ip.is_unspecified() || octets[0] == 0 {
        Some("unspecified or reserved address")
    } else if ip.is_loopback() {
        Some("loopback address")
    } else if ip.is_private() {
        Some("private address")
    } else if ip.is_link_local() {
        Some("link-local address")
    } else if ip.is_multicast() {
        Some("multicast address")
    } else if ip.is_documentation() {
        Some("documentation address")
    } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        Some("carrier-grade NAT address")
    } else if (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
    {
        Some("special-purpose address")
    } else if octets[0] >= 240 || ip == Ipv4Addr::BROADCAST {
        Some("reserved address")
    } else {
        None
    }
}

fn non_public_v6_reason(ip: Ipv6Addr) -> Option<&'static str> {
    let segments = ip.segments();
    if ip.is_unspecified() {
        Some("unspecified address")
    } else if ip.is_loopback() {
        Some("loopback address")
    } else if ip.is_multicast() {
        Some("multicast address")
    } else if (segments[0] & 0xfe00) == 0xfc00 {
        Some("unique-local address")
    } else if (segments[0] & 0xffc0) == 0xfe80 {
        Some("link-local address")
    } else if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        Some("documentation address")
    } else if ip.to_ipv4_mapped().is_some() {
        Some("IPv4-mapped address")
    } else if segments[0] & 0xe000 != 0x2000 {
        Some("non-global unicast address")
    } else {
        None
    }
}

pub(crate) struct ConnectionRateLimiter {
    interval: Duration,
    next: AsyncMutex<tokio::time::Instant>,
}

#[derive(Clone, Copy)]
struct ScanContext<'a> {
    hostname: &'a str,
    request: &'a ExposureScanRequest,
    cancel: &'a CancellationToken,
    limiter: &'a ConnectionRateLimiter,
}

#[derive(Clone, Copy)]
struct ProbeContext<'a> {
    ip: IpAddr,
    port: u16,
    scan: ScanContext<'a>,
}

impl ProbeContext<'_> {
    fn with_port(self, port: u16) -> Self {
        Self { port, ..self }
    }
}

impl ConnectionRateLimiter {
    pub(crate) fn new(per_second: u32) -> Self {
        Self {
            interval: Duration::from_secs_f64(1.0 / f64::from(per_second)),
            next: AsyncMutex::new(tokio::time::Instant::now()),
        }
    }

    pub(crate) async fn wait(&self, cancel: &CancellationToken) -> Result<(), ()> {
        let scheduled = {
            let mut next = self.next.lock().await;
            let now = tokio::time::Instant::now();
            let scheduled = (*next).max(now);
            *next = scheduled + self.interval;
            scheduled
        };
        tokio::select! {
            _ = cancel.cancelled() => Err(()),
            _ = tokio::time::sleep_until(scheduled) => Ok(()),
        }
    }
}

async fn limited_connect(context: ProbeContext<'_>) -> TcpCandidate {
    if context
        .scan
        .limiter
        .wait(context.scan.cancel)
        .await
        .is_err()
    {
        let mut candidate = connect_tcp_endpoint(
            context.ip,
            context.port,
            Duration::from_nanos(1),
            context.scan.cancel,
        )
        .await;
        candidate.stream = None;
        return candidate;
    }
    connect_tcp_endpoint(
        context.ip,
        context.port,
        context.scan.request.connection_timeout,
        context.scan.cancel,
    )
    .await
}

async fn scan_endpoint(context: ProbeContext<'_>) -> EndpointScan {
    let mut endpoint = EndpointScan::new(context.ip, context.port);
    let mut candidate = limited_connect(context).await;
    endpoint.connect_duration_ms = candidate.attempt.duration_ms;
    endpoint.state = classify_port_state(&candidate);
    endpoint.error = candidate.attempt.error.clone();
    if endpoint.state != PortState::Open {
        return endpoint;
    }
    let mut stream = candidate.stream.take().unwrap();
    endpoint.banner = capture_banner(
        &mut stream,
        context.scan.request.probe_timeout,
        context.scan.cancel,
    )
    .await;
    if !endpoint.banner.is_empty() {
        endpoint.evidence.push(format!(
            "Server-initiated banner: {}",
            escaped_evidence(&endpoint.banner)
        ));
    }
    detect_banner(&mut endpoint);
    run_guided_probe(&mut endpoint, context).await;
    if context.scan.cancel.is_cancelled() {
        endpoint.evidence.push("Probing cancelled".to_owned());
        return endpoint;
    }
    let should_probe_tls =
        TLS_PORTS.contains(&context.port) || endpoint.service == ServiceKind::Unknown;
    if should_probe_tls {
        for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
            let observation = probe_tls_version(context, version).await;
            endpoint.tls.push(observation);
        }
        if endpoint.tls.iter().any(|tls| tls.supported) && endpoint.service == ServiceKind::Unknown
        {
            endpoint.service = ServiceKind::Tls;
            endpoint.service_confidence = Confidence::High;
            endpoint
                .evidence
                .push("A TLS handshake completed successfully".to_owned());
        }
        add_tls_findings(&mut endpoint);
    }
    let tls_http = endpoint
        .tls
        .iter()
        .any(|tls| tls.supported && matches!(tls.alpn.as_deref(), Some("h2") | Some("http/1.1")));
    let unknown_before_http =
        endpoint.service == ServiceKind::Unknown || endpoint.service == ServiceKind::Tls;
    if HTTPS_PORTS.contains(&context.port)
        || tls_http
        || (unknown_before_http && endpoint.tls.iter().any(|v| v.supported))
    {
        audit_http(&mut endpoint, "https", context).await;
    }
    if endpoint.http.is_empty()
        && (HTTP_PORTS.contains(&context.port)
            || endpoint.service == ServiceKind::Unknown
            || (HTTPS_PORTS.contains(&context.port) && !endpoint.tls.iter().any(|v| v.supported)))
    {
        audit_http(&mut endpoint, "http", context).await;
    }
    apply_product_rules(&mut endpoint);
    record_observed_web_surfaces(&mut endpoint);
    apply_conventional_service_association(&mut endpoint);
    endpoint
}

fn apply_conventional_service_association(endpoint: &mut EndpointScan) {
    if endpoint.service == ServiceKind::Unknown
        && let Some(name) = conventional_service_name(endpoint.port)
    {
        endpoint.service_confidence = Confidence::Low;
        endpoint.evidence.push(format!(
            "Conventional port association suggests {name}; service was not confirmed"
        ));
    }
}

fn classify_port_state(candidate: &TcpCandidate) -> PortState {
    match candidate.attempt.outcome {
        ConnectionOutcome::Succeeded => PortState::Open,
        ConnectionOutcome::TimedOut => PortState::FilteredOrNoResponse,
        ConnectionOutcome::Cancelled => PortState::Cancelled,
        ConnectionOutcome::Failed => {
            let refused_code = matches!(candidate.attempt.os_error, Some(61 | 111 | 10061));
            let refused_text = candidate
                .attempt
                .error
                .as_deref()
                .is_some_and(|error| error.to_ascii_lowercase().contains("refused"));
            if refused_code || refused_text {
                PortState::Closed
            } else {
                PortState::Error
            }
        }
    }
}

async fn capture_banner(
    stream: &mut TcpStream,
    probe_timeout: Duration,
    cancel: &CancellationToken,
) -> Vec<u8> {
    let timeout = probe_timeout.min(Duration::from_millis(500));
    let mut bytes = vec![0u8; MAX_BANNER_BYTES];
    let read = tokio::select! {
        _ = cancel.cancelled() => return Vec::new(),
        result = tokio::time::timeout(timeout, stream.read(&mut bytes)) => result,
    };
    match read {
        Ok(Ok(length)) if length > 0 => {
            bytes.truncate(length);
            bytes
        }
        _ => Vec::new(),
    }
}

fn detect_banner(endpoint: &mut EndpointScan) {
    let banner = String::from_utf8_lossy(&endpoint.banner).into_owned();
    let lower = banner.to_ascii_lowercase();
    if banner.starts_with("SSH-") {
        set_service(
            endpoint,
            ServiceKind::Ssh,
            Confidence::High,
            "SSH identification banner",
        );
        if let Some(token) = banner
            .split('-')
            .nth(2)
            .and_then(|part| part.split_whitespace().next())
        {
            let (name, version) = split_name_version(token);
            add_product(
                endpoint,
                &name,
                ProductLayer::Protocol,
                version,
                Confidence::Medium,
                format!("SSH banner reports {token}"),
            );
        }
    } else if lower.starts_with("220") && lower.contains("ftp") {
        set_service(
            endpoint,
            ServiceKind::Ftp,
            Confidence::High,
            "FTP greeting banner",
        );
    } else if lower.starts_with("220") && (lower.contains("smtp") || lower.contains("esmtp")) {
        set_service(
            endpoint,
            ServiceKind::Smtp,
            Confidence::High,
            "SMTP greeting banner",
        );
    } else if lower.starts_with("+ok") {
        set_service(
            endpoint,
            ServiceKind::Pop3,
            Confidence::High,
            "POP3 greeting banner",
        );
    } else if lower.starts_with('*') && (lower.contains("imap") || lower.contains("capability")) {
        set_service(
            endpoint,
            ServiceKind::Imap,
            Confidence::High,
            "IMAP greeting banner",
        );
    } else if endpoint.banner.first() == Some(&10)
        || mysql_banner_version(&endpoint.banner).is_some()
    {
        set_service(
            endpoint,
            ServiceKind::Mysql,
            Confidence::High,
            "MySQL handshake packet",
        );
        if let Some(version) = mysql_banner_version(&endpoint.banner) {
            add_product(
                endpoint,
                "MySQL",
                ProductLayer::Protocol,
                Some(version.clone()),
                Confidence::Medium,
                format!("MySQL handshake reports version {version}"),
            );
        }
    } else if endpoint.banner.starts_with(b"RFB ") {
        set_service(
            endpoint,
            ServiceKind::Vnc,
            Confidence::High,
            "VNC RFB protocol banner",
        );
        let version = banner
            .strip_prefix("RFB ")
            .map(str::trim)
            .filter(|version| !version.is_empty())
            .map(str::to_owned);
        add_product(
            endpoint,
            "VNC",
            ProductLayer::Protocol,
            version,
            Confidence::Medium,
            format!("RFB banner: {}", banner.trim()),
        );
    } else if banner.starts_with("@RSYNCD:") {
        set_service(
            endpoint,
            ServiceKind::Rsync,
            Confidence::High,
            "rsync daemon protocol banner",
        );
        let version = banner
            .strip_prefix("@RSYNCD:")
            .and_then(|value| value.split_whitespace().next())
            .filter(|version| version.chars().any(|character| character.is_ascii_digit()))
            .map(str::to_owned);
        add_product(
            endpoint,
            "rsync",
            ProductLayer::Protocol,
            version,
            Confidence::Medium,
            format!("rsync banner: {}", banner.trim()),
        );
    } else if lower.starts_with("http/1.") {
        set_service(
            endpoint,
            ServiceKind::Http,
            Confidence::High,
            "HTTP status line banner",
        );
    }
}

fn mysql_banner_version(bytes: &[u8]) -> Option<String> {
    let offset = if bytes.first() == Some(&10) {
        1
    } else if bytes.len() > 5 && bytes[4] == 10 {
        5
    } else {
        return None;
    };
    let end = bytes[offset..].iter().position(|byte| *byte == 0)? + offset;
    let version = String::from_utf8_lossy(&bytes[offset..end])
        .trim()
        .to_owned();
    (!version.is_empty()).then_some(version)
}

fn split_name_version(token: &str) -> (String, Option<String>) {
    if let Some((name, version)) = token.split_once('_').or_else(|| token.split_once('/')) {
        (
            name.to_owned(),
            (!version.is_empty()).then(|| version.to_owned()),
        )
    } else {
        (token.to_owned(), None)
    }
}

fn set_service(
    endpoint: &mut EndpointScan,
    kind: ServiceKind,
    confidence: Confidence,
    evidence: &str,
) {
    if confidence >= endpoint.service_confidence {
        endpoint.service = kind;
        endpoint.service_confidence = confidence;
    }
    if !endpoint.evidence.iter().any(|item| item == evidence) {
        endpoint.evidence.push(evidence.to_owned());
    }
}

fn add_product(
    endpoint: &mut EndpointScan,
    name: &str,
    layer: ProductLayer,
    version: Option<String>,
    confidence: Confidence,
    evidence: String,
) {
    if let Some(product) = endpoint
        .products
        .iter_mut()
        .find(|product| product.name.eq_ignore_ascii_case(name))
    {
        product.confidence = product.confidence.max(confidence);
        if product.version.is_none() {
            product.version = version;
        }
        if !product.evidence.contains(&evidence) {
            product.evidence.push(evidence);
        }
    } else {
        endpoint.products.push(ProductDetection {
            name: name.to_owned(),
            layer,
            version,
            confidence,
            evidence: vec![evidence],
        });
    }
}

fn escaped_evidence(bytes: &[u8]) -> String {
    let mut output = String::new();
    for &byte in bytes.iter().take(512) {
        if byte.is_ascii_graphic() || byte == b' ' {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "\\x{byte:02X}");
        }
    }
    if bytes.len() > 512 {
        output.push_str("...");
    }
    output
}

async fn run_guided_probe(endpoint: &mut EndpointScan, context: ProbeContext<'_>) {
    let payload = guided_probe_payload(endpoint.port, context.scan.hostname);
    let Some(payload) = payload else {
        return;
    };
    let response = tcp_probe(context, &payload).await;
    if response.is_empty() {
        return;
    }
    detect_guided_response(endpoint, &response);
    endpoint.evidence.push(format!(
        "Guided probe response: {}",
        escaped_evidence(&response)
    ));
}

fn guided_probe_payload(port: u16, hostname: &str) -> Option<Vec<u8>> {
    match port {
        21 => Some(b"SYST\r\n".to_vec()),
        25 | 587 => Some(b"EHLO scanner.invalid\r\n".to_vec()),
        102 => Some(vec![
            3, 0, 0, 22, 17, 224, 0, 0, 0, 1, 0, 193, 2, 1, 0, 194, 2, 1, 2, 192, 1, 10,
        ]),
        110 => Some(b"CAPA\r\n".to_vec()),
        143 => Some(b"a001 CAPABILITY\r\n".to_vec()),
        502 => Some(vec![0, 1, 0, 0, 0, 5, 255, 43, 14, 1, 0]),
        2181 => Some(b"ruok".to_vec()),
        2404 => Some(vec![104, 4, 67, 0, 0, 0]),
        3389 => Some(vec![
            3, 0, 0, 19, 14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0,
        ]),
        4369 => Some(vec![0, 1, b'n']),
        4840 => Some(opc_ua_hello()),
        5432 => Some(vec![0, 0, 0, 8, 4, 210, 22, 47]),
        6379 => Some(b"PING\r\n".to_vec()),
        8009 => Some(vec![18, 52, 0, 1, 10]),
        9042 => Some(vec![4, 0, 0, 0, 5, 0, 0, 0, 0]),
        9418 => Some(git_probe(hostname)),
        9600 => Some(vec![
            b'F', b'I', b'N', b'S', 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        11211 => Some(b"version\r\n".to_vec()),
        44818 => Some(vec![
            99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        _ => None,
    }
}

fn opc_ua_hello() -> Vec<u8> {
    let endpoint_url = b"opc.tcp://scanner.invalid:4840";
    let message_length = 32 + endpoint_url.len();
    let mut payload = Vec::with_capacity(message_length);
    payload.extend_from_slice(b"HELF");
    payload.extend_from_slice(&(message_length as u32).to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&65_535u32.to_le_bytes());
    payload.extend_from_slice(&65_535u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&(endpoint_url.len() as u32).to_le_bytes());
    payload.extend_from_slice(endpoint_url);
    payload
}

fn git_probe(hostname: &str) -> Vec<u8> {
    let command = format!("git-upload-pack /nancy-exposure-probe\0host={hostname}\0");
    format!("{:04x}{command}", command.len() + 4).into_bytes()
}

fn detect_guided_response(endpoint: &mut EndpointScan, response: &[u8]) {
    let text = String::from_utf8_lossy(response);
    let lower = text.to_ascii_lowercase();
    match endpoint.port {
        21 if lower.starts_with("2") || lower.contains("ftp") => {
            set_service(
                endpoint,
                ServiceKind::Ftp,
                Confidence::High,
                "FTP command response",
            );
        }
        25 | 587 if lower.starts_with("220") || lower.starts_with("250") => {
            set_service(
                endpoint,
                ServiceKind::Smtp,
                Confidence::High,
                "SMTP EHLO response",
            );
        }
        110 if lower.starts_with("+ok") => {
            set_service(
                endpoint,
                ServiceKind::Pop3,
                Confidence::High,
                "POP3 CAPA response",
            );
        }
        143 if lower.starts_with('*') || lower.contains("a001 ok") => {
            set_service(
                endpoint,
                ServiceKind::Imap,
                Confidence::High,
                "IMAP CAPABILITY response",
            );
        }
        102 if response.len() >= 7
            && response.starts_with(&[3, 0])
            && response[5] & 0xf0 == 0xd0 =>
        {
            set_service(
                endpoint,
                ServiceKind::IsoOnTcp,
                Confidence::High,
                "ISO-on-TCP COTP connection confirmation",
            );
        }
        502 if response.len() >= 9
            && response.starts_with(&[0, 1, 0, 0])
            && matches!(response[7], 43 | 171) =>
        {
            set_service(
                endpoint,
                ServiceKind::Modbus,
                Confidence::High,
                "Modbus/TCP device-identification response",
            );
            add_product(
                endpoint,
                "Modbus",
                ProductLayer::Protocol,
                None,
                Confidence::Medium,
                "Modbus function 43 response framing".to_owned(),
            );
        }
        2181 if lower.trim() == "imok" || lower.contains("zookeeper") => {
            set_service(
                endpoint,
                ServiceKind::ZooKeeper,
                Confidence::High,
                "ZooKeeper four-letter-word response",
            );
            add_product(
                endpoint,
                "ZooKeeper",
                ProductLayer::Protocol,
                None,
                Confidence::Medium,
                format!("ZooKeeper ruok response: {}", escaped_evidence(response)),
            );
        }
        2404 if response.starts_with(&[104, 4, 131, 0, 0, 0]) => {
            set_service(
                endpoint,
                ServiceKind::Iec104,
                Confidence::High,
                "IEC 60870-5-104 TESTFR confirmation",
            );
            add_product(
                endpoint,
                "IEC 60870-5-104",
                ProductLayer::Protocol,
                None,
                Confidence::Medium,
                "IEC 60870-5-104 link test response".to_owned(),
            );
        }
        5432 if matches!(response.first(), Some(b'S' | b'N')) => {
            set_service(
                endpoint,
                ServiceKind::PostgreSql,
                Confidence::High,
                "PostgreSQL SSLRequest response",
            );
            add_product(
                endpoint,
                "PostgreSQL",
                ProductLayer::Protocol,
                None,
                Confidence::Medium,
                "PostgreSQL SSL negotiation behavior".to_owned(),
            );
        }
        6379 if lower.starts_with("+pong") || lower.starts_with("-noauth") => {
            set_service(
                endpoint,
                ServiceKind::Redis,
                Confidence::High,
                "Redis PING response",
            );
            add_product(
                endpoint,
                "Redis",
                ProductLayer::Protocol,
                None,
                Confidence::Medium,
                format!("Redis protocol response: {}", escaped_evidence(response)),
            );
        }
        4369 if response.len() >= 4
            && u32::from_be_bytes([response[0], response[1], response[2], response[3]]) == 4369 =>
        {
            set_service(
                endpoint,
                ServiceKind::ErlangEpmd,
                Confidence::High,
                "Erlang EPMD names response",
            );
            add_product(
                endpoint,
                "Erlang EPMD",
                ProductLayer::Protocol,
                None,
                Confidence::Medium,
                "EPMD returned its registered-name response".to_owned(),
            );
        }
        4840 if response.starts_with(b"ACKF") || response.starts_with(b"ERRF") => {
            set_service(
                endpoint,
                ServiceKind::OpcUa,
                Confidence::High,
                "OPC UA TCP acknowledgement",
            );
            add_product(
                endpoint,
                "OPC UA",
                ProductLayer::Protocol,
                None,
                Confidence::Medium,
                format!(
                    "OPC UA response header: {}",
                    escaped_evidence(&response[..4])
                ),
            );
        }
        8009 if response.starts_with(&[65, 66, 0, 1, 9]) => {
            set_service(
                endpoint,
                ServiceKind::Ajp,
                Confidence::High,
                "AJP CPONG response",
            );
            add_product(
                endpoint,
                "AJP",
                ProductLayer::Protocol,
                None,
                Confidence::Medium,
                "AJP connector answered a CPING request".to_owned(),
            );
        }
        9042 if response.len() >= 9 && response[0] & 0x80 != 0 && response[4] == 6 => {
            set_service(
                endpoint,
                ServiceKind::Cassandra,
                Confidence::High,
                "Cassandra native SUPPORTED response",
            );
            add_product(
                endpoint,
                "Cassandra",
                ProductLayer::Protocol,
                None,
                Confidence::Medium,
                "Cassandra native protocol answered OPTIONS".to_owned(),
            );
        }
        9418 if lower.contains("err ") && lower.contains("repository") => {
            set_service(
                endpoint,
                ServiceKind::Git,
                Confidence::High,
                "Git daemon protocol error response",
            );
            add_product(
                endpoint,
                "Git daemon",
                ProductLayer::Protocol,
                None,
                Confidence::Medium,
                "Git upload-pack request received a repository error".to_owned(),
            );
        }
        9600 if response.len() >= 16 && response.starts_with(b"FINS") && response[11] == 1 => {
            set_service(
                endpoint,
                ServiceKind::OmronFins,
                Confidence::High,
                "Omron FINS/TCP node-address response",
            );
            add_product(
                endpoint,
                "Omron FINS",
                ProductLayer::Protocol,
                None,
                Confidence::Medium,
                "FINS/TCP handshake response".to_owned(),
            );
        }
        11211 if lower.starts_with("version ") => {
            let version = text
                .split_whitespace()
                .nth(1)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            set_service(
                endpoint,
                ServiceKind::Memcached,
                Confidence::High,
                "Memcached version response",
            );
            add_product(
                endpoint,
                "Memcached",
                ProductLayer::Protocol,
                version,
                Confidence::High,
                format!("Memcached response: {}", escaped_evidence(response)),
            );
        }
        44818 if response.len() >= 24 && response.starts_with(&[99, 0]) => {
            set_service(
                endpoint,
                ServiceKind::EtherNetIp,
                Confidence::High,
                "EtherNet/IP ListIdentity response",
            );
            add_product(
                endpoint,
                "EtherNet/IP",
                ProductLayer::Protocol,
                None,
                Confidence::Medium,
                "EtherNet/IP encapsulation service answered ListIdentity".to_owned(),
            );
        }
        3389 if response.starts_with(&[3, 0]) => {
            set_service(
                endpoint,
                ServiceKind::Rdp,
                Confidence::High,
                "RDP negotiation response",
            );
        }
        _ => {}
    }
}

async fn tcp_probe(context: ProbeContext<'_>, payload: &[u8]) -> Vec<u8> {
    let mut candidate = limited_connect(context).await;
    let Some(mut stream) = candidate.stream.take() else {
        return Vec::new();
    };
    let operation = async {
        let mut initial = vec![0u8; MAX_BANNER_BYTES];
        let initial_length =
            tokio::time::timeout(Duration::from_millis(250), stream.read(&mut initial))
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(0);
        stream.write_all(payload).await?;
        stream.flush().await?;
        let mut response = vec![0u8; MAX_BANNER_BYTES];
        let response_length = stream.read(&mut response).await?;
        initial.truncate(initial_length);
        response.truncate(response_length);
        initial.extend(response);
        Ok::<_, std::io::Error>(initial)
    };
    tokio::select! {
        _ = context.scan.cancel.cancelled() => Vec::new(),
        result = tokio::time::timeout(context.scan.request.probe_timeout, operation) => {
            result.ok().and_then(Result::ok).unwrap_or_default()
        }
    }
}

async fn probe_tls_version(context: ProbeContext<'_>, version: TlsVersion) -> TlsObservation {
    let options = TlsHandshakeOptions {
        version: Some(version),
        permissive: false,
        offer_http2: true,
    };
    match tls_handshake(context, options).await {
        Ok(success) => TlsObservation::from_trace(
            version,
            context.scan.hostname,
            TlsObservationState::Verified,
            success.trace,
            None,
            None,
        ),
        Err(invalid) if invalid.trace.validation_error.is_some() => {
            let validation_error = invalid.trace.validation_error.clone();
            let invalid_certificates = invalid.trace.certificates;
            let permissive = TlsHandshakeOptions {
                permissive: true,
                ..options
            };
            match tls_handshake(context, permissive).await {
                Ok(mut success) => {
                    if !invalid_certificates.is_empty() {
                        success.trace.certificates = invalid_certificates;
                    }
                    TlsObservation::from_trace(
                        version,
                        context.scan.hostname,
                        TlsObservationState::Unverified,
                        success.trace,
                        validation_error,
                        None,
                    )
                }
                Err(mut fallback) => {
                    if !invalid_certificates.is_empty() {
                        fallback.trace.certificates = invalid_certificates;
                    }
                    TlsObservation::from_trace(
                        version,
                        context.scan.hostname,
                        TlsObservationState::Unsupported,
                        fallback.trace,
                        validation_error,
                        Some(format!(
                            "Validated handshake failed: {}; permissive retry failed: {}",
                            invalid.error, fallback.error
                        )),
                    )
                }
            }
        }
        Err(failure) => TlsObservation::from_trace(
            version,
            context.scan.hostname,
            TlsObservationState::Unsupported,
            failure.trace,
            None,
            Some(failure.error),
        ),
    }
}

impl TlsObservation {
    fn from_trace(
        requested_version: TlsVersion,
        hostname: &str,
        state: TlsObservationState,
        trace: TlsTrace,
        validation_error: Option<String>,
        error: Option<String>,
    ) -> Self {
        let (supported, verified, unverified) = match state {
            TlsObservationState::Verified => (true, true, false),
            TlsObservationState::Unverified => (true, false, true),
            TlsObservationState::Unsupported => (false, false, false),
        };
        let hostname_valid = trace
            .certificates
            .first()
            .and_then(|certificate| certificate_hostname_valid(certificate, hostname));
        let certificate_expired = trace.certificates.first().and_then(certificate_is_expired);
        let certificate_not_yet_valid = trace
            .certificates
            .first()
            .and_then(certificate_is_not_yet_valid);
        Self {
            requested_version,
            supported,
            verified,
            unverified,
            negotiated_version: supported.then_some(trace.version).flatten(),
            alpn: supported.then_some(trace.alpn).flatten(),
            cipher: supported.then_some(trace.cipher_suite).flatten(),
            validation_error: validation_error.or(trace.validation_error),
            hostname_valid,
            certificate_expired,
            certificate_not_yet_valid,
            certificates: trace.certificates,
            error,
        }
    }
}

#[derive(Clone, Copy)]
enum TlsObservationState {
    Verified,
    Unverified,
    Unsupported,
}

#[derive(Clone, Copy)]
struct TlsHandshakeOptions {
    version: Option<TlsVersion>,
    permissive: bool,
    offer_http2: bool,
}

struct TlsHandshakeSuccess {
    stream: TlsStream<TcpStream>,
    trace: TlsTrace,
}

struct TlsHandshakeFailure {
    error: String,
    trace: TlsTrace,
}

async fn tls_handshake(
    context: ProbeContext<'_>,
    options: TlsHandshakeOptions,
) -> Result<TlsHandshakeSuccess, Box<TlsHandshakeFailure>> {
    let capture = Arc::new(Mutex::new(CertificateCapture::default()));
    let mut candidate = limited_connect(context).await;
    let Some(stream) = candidate.stream.take() else {
        return Err(Box::new(TlsHandshakeFailure {
            error: candidate
                .attempt
                .error
                .unwrap_or_else(|| "TCP connection did not open".to_owned()),
            trace: tls_trace_from_capture(context.scan.hostname, &capture),
        }));
    };
    let config = match make_exposure_tls_config(
        options.version.map(|version| version == TlsVersion::Tls13),
        options.permissive,
        options.offer_http2,
        capture.clone(),
    ) {
        Ok(config) => config,
        Err(error) => {
            return Err(Box::new(TlsHandshakeFailure {
                error,
                trace: tls_trace_from_capture(context.scan.hostname, &capture),
            }));
        }
    };
    let server_name = match ServerName::try_from(context.scan.hostname.to_owned()) {
        Ok(server_name) => server_name,
        Err(error) => {
            return Err(Box::new(TlsHandshakeFailure {
                error: format!("Invalid TLS server name: {error}"),
                trace: tls_trace_from_capture(context.scan.hostname, &capture),
            }));
        }
    };
    let operation = TlsConnector::from(config).connect(server_name, stream);
    let result = tokio::select! {
        _ = context.scan.cancel.cancelled() => {
            return Err(Box::new(TlsHandshakeFailure {
                error: "Scan cancelled".to_owned(),
                trace: tls_trace_from_capture(context.scan.hostname, &capture),
            }));
        }
        result = tokio::time::timeout(context.scan.request.probe_timeout, operation) => result,
    };
    match result {
        Ok(Ok(stream)) => {
            let mut trace = tls_trace_from_stream(context.scan.hostname, &stream, &capture);
            if options.permissive {
                trace.validation = Some("Unverified scan-only connection".to_owned());
            }
            Ok(TlsHandshakeSuccess { stream, trace })
        }
        Ok(Err(error)) => Err(Box::new(TlsHandshakeFailure {
            error: error.to_string(),
            trace: tls_trace_from_capture(context.scan.hostname, &capture),
        })),
        Err(_) => Err(Box::new(TlsHandshakeFailure {
            error: options.version.map_or_else(
                || "TLS handshake timed out".to_owned(),
                |version| format!("{version} handshake timed out"),
            ),
            trace: tls_trace_from_capture(context.scan.hostname, &capture),
        })),
    }
}

fn add_tls_findings(endpoint: &mut EndpointScan) {
    let errors = endpoint
        .tls
        .iter()
        .filter(|tls| tls.supported && tls.unverified)
        .filter_map(|tls| {
            tls.validation_error
                .as_ref()
                .map(|error| format!("{}: {error}", tls.requested_version))
        })
        .collect::<Vec<_>>();
    let expired = endpoint
        .tls
        .iter()
        .any(|tls| tls.certificate_expired == Some(true));
    let hostname_mismatch = endpoint
        .tls
        .iter()
        .any(|tls| tls.hostname_valid == Some(false));
    let not_yet_valid = endpoint
        .tls
        .iter()
        .any(|tls| tls.certificate_not_yet_valid == Some(true));
    if expired {
        let evidence = endpoint
            .tls
            .iter()
            .flat_map(|tls| tls.certificates.first())
            .map(|certificate| format!("Leaf certificate expired after {}", certificate.not_after))
            .take(1)
            .collect();
        endpoint.findings.push(finding(
            endpoint,
            "Expired TLS certificate",
            "The leaf certificate validity period has ended",
            evidence,
        ));
    }
    if hostname_mismatch {
        endpoint.findings.push(finding(
            endpoint,
            "TLS certificate hostname mismatch",
            "The leaf certificate subject alternative names do not match the requested hostname",
            endpoint
                .tls
                .iter()
                .flat_map(|tls| tls.certificates.first())
                .map(|certificate| {
                    format!(
                        "Certificate subject alternative names: {}",
                        certificate.subject_alt_names.join(", ")
                    )
                })
                .take(1)
                .collect(),
        ));
    }
    if not_yet_valid {
        endpoint.findings.push(finding(
            endpoint,
            "TLS certificate is not yet valid",
            "The leaf certificate validity period has not started",
            endpoint
                .tls
                .iter()
                .flat_map(|tls| tls.certificates.first())
                .map(|certificate| {
                    format!("Leaf certificate is valid from {}", certificate.not_before)
                })
                .take(1)
                .collect(),
        ));
    }
    if !errors.is_empty() && !expired && !hostname_mismatch && !not_yet_valid {
        endpoint.findings.push(ExposureFinding {
            title: "Invalid TLS certificate".to_owned(),
            description: "Normal certificate validation failed; further inspection used a clearly marked permissive scan-only connection".to_owned(),
            ip: endpoint.ip,
            port: endpoint.port,
            evidence: errors,
        });
    }
}

fn certificate_is_expired(certificate: &CertificateTrace) -> Option<bool> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    certificate.not_after_unix.map(|not_after| now > not_after)
}

fn certificate_is_not_yet_valid(certificate: &CertificateTrace) -> Option<bool> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    certificate
        .not_before_unix
        .map(|not_before| now < not_before)
}

fn certificate_hostname_valid(certificate: &CertificateTrace, hostname: &str) -> Option<bool> {
    let names = certificate
        .subject_alt_names
        .iter()
        .filter_map(|name| {
            name.strip_prefix("DNS: ")
                .or_else(|| name.strip_prefix("IP: "))
        })
        .collect::<Vec<_>>();
    if names.is_empty() {
        return None;
    }
    Some(
        names
            .into_iter()
            .any(|name| hostname_matches(name, hostname)),
    )
}

fn hostname_matches(pattern: &str, hostname: &str) -> bool {
    if pattern.eq_ignore_ascii_case(hostname) {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let Some(prefix) = hostname
        .to_ascii_lowercase()
        .strip_suffix(&format!(".{}", suffix.to_ascii_lowercase()))
        .map(str::to_owned)
    else {
        return false;
    };
    !prefix.is_empty() && !prefix.contains('.')
}

fn conventional_service_name(port: u16) -> Option<&'static str> {
    curated_tcp_port_metadata(port).map(|metadata| metadata.service_name)
}

enum ScanIo {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for ScanIo {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for ScanIo {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

async fn audit_http(endpoint: &mut EndpointScan, scheme: &str, context: ProbeContext<'_>) {
    let cookie_jar = context
        .scan
        .request
        .security_operations
        .then(|| Mutex::new(EndpointCookieJar::default()));
    let cookie_jar = cookie_jar.as_ref();
    let head = match request_http_chain_with_cookies(context, scheme, "HEAD", "/", &[], cookie_jar)
        .await
    {
        Ok(observations) if !observations.is_empty() => observations,
        _ => return,
    };
    set_service(
        endpoint,
        if scheme == "https" {
            ServiceKind::Https
        } else {
            ServiceKind::Http
        },
        Confidence::High,
        "Valid HTTP response status and headers",
    );
    let initial_head = head.first().cloned();
    endpoint.http.extend(head);
    let root_get = request_http_chain_with_limit_and_cookies(
        context,
        scheme,
        "GET",
        "/",
        &[],
        MAX_ROOT_HTML_BYTES,
        cookie_jar,
    )
    .await
    .unwrap_or_default();
    let initial_get = root_get.first().cloned();
    let final_root = root_get.last().cloned();
    if context.scan.request.security_operations
        && let Some(root) = final_root.as_ref()
    {
        endpoint.javascript_candidates = javascript::discover_sources(root);
    }
    endpoint.http.extend(root_get);
    if context.scan.request.security_operations {
        let continuity =
            request_http_chain_with_cookies(context, scheme, "GET", "/", &[], cookie_jar)
                .await
                .unwrap_or_default();
        endpoint.http.extend(continuity);
    }
    if scheme == "http" {
        let redirects_to_https = initial_head
            .as_ref()
            .into_iter()
            .chain(initial_get.as_ref())
            .any(|observation| {
                observation
                    .redirect_location
                    .as_deref()
                    .is_some_and(|location| {
                        redirect_is_https_for_host(
                            &observation.url,
                            location,
                            context.scan.hostname,
                        )
                    })
            });
        if !redirects_to_https {
            endpoint.findings.push(finding(
                endpoint,
                "Cleartext HTTP does not redirect to HTTPS",
                "The root HTTP response did not direct the client to HTTPS",
                initial_head
                    .as_ref()
                    .map(|item| format!("HEAD / returned {}", item.status))
                    .into_iter()
                    .collect(),
            ));
        }
    }
    if let Some(root) = final_root.as_ref() {
        let final_scheme = Url::parse(&root.url)
            .ok()
            .map(|url| url.scheme().to_owned())
            .unwrap_or_else(|| scheme.to_owned());
        add_missing_header_finding(endpoint, root, &final_scheme);
    }
    let random = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let baseline_path = format!("/nancy-exposure-not-found-{random:x}");
    let baseline_chain =
        request_http_chain_with_cookies(context, scheme, "GET", &baseline_path, &[], cookie_jar)
            .await
            .unwrap_or_default();
    let baseline = baseline_chain.last().cloned();
    endpoint.http.extend(baseline_chain);
    audit_web_visibility(
        endpoint,
        final_root.as_ref(),
        baseline.as_ref(),
        context,
        cookie_jar,
    )
    .await;
    let options = request_http_chain_with_cookies(context, scheme, "OPTIONS", "/", &[], cookie_jar)
        .await
        .unwrap_or_default();
    endpoint.http.extend(options);
    let trace = request_http_chain_with_cookies(context, scheme, "TRACE", "/", &[], cookie_jar)
        .await
        .unwrap_or_default();
    if let Some(response) = trace.last()
        && (200..300).contains(&response.status)
        && (String::from_utf8_lossy(&response.body)
            .to_ascii_uppercase()
            .contains("TRACE /")
            || header_values(response, "content-type")
                .any(|value| value.to_ascii_lowercase().contains("message/http")))
    {
        endpoint.findings.push(finding(
            endpoint,
            "HTTP TRACE is enabled",
            "The server accepted TRACE and returned trace content",
            vec![format!("TRACE / returned {}", response.status)],
        ));
    }
    endpoint.http.extend(trace);
    let synthetic_origin = "https://nancy-exposure.invalid";
    let cors_get = request_http_chain_with_cookies(
        context,
        scheme,
        "GET",
        "/",
        &[("Origin", synthetic_origin)],
        cookie_jar,
    )
    .await
    .unwrap_or_default();
    let cors_preflight = request_http_chain_with_cookies(
        context,
        scheme,
        "OPTIONS",
        "/",
        &[
            ("Origin", synthetic_origin),
            ("Access-Control-Request-Method", "PUT"),
            (
                "Access-Control-Request-Headers",
                "Authorization, X-Nancy-Probe",
            ),
        ],
        cookie_jar,
    )
    .await
    .unwrap_or_default();
    let reflected = cors_get
        .iter()
        .chain(cors_preflight.iter())
        .find(|response| cors_reflects_credentials(response, synthetic_origin));
    if let Some(response) = reflected {
        endpoint.findings.push(finding(
            endpoint,
            "Arbitrary CORS origin reflected with credentials",
            "The server reflected a synthetic origin while allowing credentials",
            vec![
                format!("{} returned {}", response.method, response.status),
                format!("Access-Control-Allow-Origin: {synthetic_origin}"),
                "Access-Control-Allow-Credentials: true".to_owned(),
            ],
        ));
    }
    endpoint.http.extend(cors_get);
    endpoint.http.extend(cors_preflight);
    for path in SENSITIVE_PATHS {
        if context.scan.cancel.is_cancelled() {
            break;
        }
        let chain = request_http_chain_with_cookies(context, scheme, "GET", path, &[], cookie_jar)
            .await
            .unwrap_or_default();
        if let Some(response) = chain.last() {
            if matches!(response.status, 401 | 403) {
                endpoint.evidence.push(format!(
                    "Protected endpoint evidence: {path} returned {}",
                    response.status
                ));
            } else if (200..300).contains(&response.status)
                && !baseline.as_ref().is_some_and(|baseline| {
                    looks_like_soft_404(baseline, response, &baseline_path, path)
                })
                && let Some((title, description, signature)) = sensitive_signature(path, response)
            {
                endpoint.findings.push(finding(
                    endpoint,
                    title,
                    description,
                    vec![
                        format!("GET {path} returned {}", response.status),
                        signature,
                    ],
                ));
            }
        }
        endpoint.http.extend(chain);
    }
    audit_management_http(endpoint, scheme, context, cookie_jar).await;
    let mut cleartext_challenges = endpoint
        .http
        .iter()
        .filter(|response| response.url.starts_with("http://"))
        .flat_map(|response| {
            header_values(response, "www-authenticate").map(|value| {
                format!(
                    "{} {}: WWW-Authenticate: {value}",
                    response.method, response.url
                )
            })
        })
        .collect::<Vec<_>>();
    cleartext_challenges.sort();
    cleartext_challenges.dedup();
    if !cleartext_challenges.is_empty() {
        endpoint.findings.push(finding(
            endpoint,
            "Authentication offered over cleartext HTTP",
            "The service advertises an authentication challenge without transport encryption",
            cleartext_challenges,
        ));
    }
}

async fn audit_web_visibility(
    endpoint: &mut EndpointScan,
    root: Option<&HttpObservation>,
    _baseline: Option<&HttpObservation>,
    context: ProbeContext<'_>,
    cookie_jar: Option<&Mutex<EndpointCookieJar>>,
) {
    let Some(root) = root.filter(|response| (200..300).contains(&response.status)) else {
        return;
    };
    let Ok(base) = Url::parse(&root.url) else {
        return;
    };
    let Some(port) = base.port_or_known_default() else {
        return;
    };
    if port != endpoint.port {
        return;
    }
    let scheme = base.scheme().to_owned();
    let web_context = context.with_port(port);
    for path in same_origin_asset_paths(root, &base)
        .into_iter()
        .take(MAX_WEB_ASSET_REQUESTS)
    {
        if context.scan.cancel.is_cancelled() {
            return;
        }
        let chain =
            request_http_chain_with_cookies(web_context, &scheme, "GET", &path, &[], cookie_jar)
                .await
                .unwrap_or_default();
        endpoint.http.extend(chain);
    }

    let mut requested = HashSet::new();
    let mut discovery_count = 0usize;
    for path in [
        "/wp-json/",
        "/wp-json/wc/store/v1/",
        "/rest/V1/store/storeConfigs",
        "/cart.js",
        "/api/storefront/store-context",
        "/Security/login",
        "/index.php?route=account/login",
        "/products",
        "/cart",
        "/checkout",
    ] {
        fetch_web_discovery_path(
            endpoint,
            web_context,
            &scheme,
            path,
            &mut requested,
            &mut discovery_count,
            cookie_jar,
        )
        .await;
    }

    let hints = web_platform_hints(endpoint.http.iter());
    let mut targeted = Vec::new();
    if hints.contains("WordPress") {
        targeted.extend(["/wp-login.php", "/wp-admin/"]);
    }
    if hints.contains("WooCommerce") {
        targeted.extend(["/cart/", "/checkout/"]);
    }
    if hints.contains("Magento") {
        targeted.extend([
            "/customer/account/login/",
            "/admin/",
            "/checkout/cart/",
            "/checkout/",
        ]);
    }
    if hints.contains("Shopify") {
        targeted.extend(["/account/login", "/collections/all"]);
    }
    if hints.contains("Silverstripe") {
        targeted.extend(["/admin/"]);
    }
    if hints.contains("BigCommerce") {
        targeted.extend(["/login.php", "/cart.php"]);
    }
    if hints.contains("PrestaShop") {
        targeted.extend(["/login", "/order"]);
    }
    if hints.contains("OpenCart") {
        targeted.extend([
            "/index.php?route=checkout/cart",
            "/index.php?route=checkout/checkout",
        ]);
    }
    for path in targeted {
        if discovery_count >= MAX_WEB_DISCOVERY_REQUESTS || context.scan.cancel.is_cancelled() {
            break;
        }
        fetch_web_discovery_path(
            endpoint,
            web_context,
            &scheme,
            path,
            &mut requested,
            &mut discovery_count,
            cookie_jar,
        )
        .await;
    }
}

async fn fetch_web_discovery_path(
    endpoint: &mut EndpointScan,
    context: ProbeContext<'_>,
    scheme: &str,
    path: &str,
    requested: &mut HashSet<String>,
    count: &mut usize,
    cookie_jar: Option<&Mutex<EndpointCookieJar>>,
) {
    if *count >= MAX_WEB_DISCOVERY_REQUESTS || !requested.insert(path.to_owned()) {
        return;
    }
    *count += 1;
    let chain = request_http_chain_with_cookies(context, scheme, "GET", path, &[], cookie_jar)
        .await
        .unwrap_or_default();
    endpoint.http.extend(chain);
}

fn same_origin_asset_paths(root: &HttpObservation, base: &Url) -> Vec<String> {
    let text = String::from_utf8_lossy(&root.body);
    let lower = text.to_ascii_lowercase();
    let mut position = 0usize;
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    while position < lower.len() && paths.len() < MAX_WEB_ASSET_REQUESTS {
        let script = lower[position..]
            .find("<script")
            .map(|index| position + index);
        let link = lower[position..]
            .find("<link")
            .map(|index| position + index);
        let Some(start) = (match (script, link) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(index), None) | (None, Some(index)) => Some(index),
            (None, None) => None,
        }) else {
            break;
        };
        let Some(relative_end) = lower[start..].find('>') else {
            break;
        };
        let end = start + relative_end + 1;
        let tag = &text[start..end];
        let tag_lower = &lower[start..end];
        let reference = if tag_lower.starts_with("<script") {
            html_attribute(tag, "src")
        } else if html_attribute(tag, "rel").is_some_and(|rel| {
            let rel = rel.to_ascii_lowercase();
            rel.split_ascii_whitespace()
                .any(|item| matches!(item, "stylesheet" | "manifest"))
        }) {
            html_attribute(tag, "href")
        } else {
            None
        };
        if let Some(reference) = reference
            && let Ok(url) = base.join(&reference.replace("&amp;", "&"))
            && same_origin(base, &url)
        {
            let path = match url.query() {
                Some(query) => format!("{}?{query}", url.path()),
                None => url.path().to_owned(),
            };
            if seen.insert(path.clone()) {
                paths.push(path);
            }
        }
        position = end;
    }
    paths
}

fn html_attribute(tag: &str, attribute: &str) -> Option<String> {
    let bytes = tag.as_bytes();
    let lower = tag.to_ascii_lowercase();
    let lower_bytes = lower.as_bytes();
    let name = attribute.as_bytes();
    let mut position = 0usize;
    while position + name.len() <= bytes.len() {
        let relative = lower[position..].find(attribute)?;
        let start = position + relative;
        let before_ok = start == 0
            || lower_bytes[start - 1].is_ascii_whitespace()
            || lower_bytes[start - 1] == b'<';
        let mut cursor = start + name.len();
        let after_ok = cursor == bytes.len()
            || lower_bytes[cursor].is_ascii_whitespace()
            || lower_bytes[cursor] == b'=';
        if !before_ok || !after_ok {
            position = cursor;
            continue;
        }
        while cursor < bytes.len() && lower_bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            position = cursor;
            continue;
        }
        cursor += 1;
        while cursor < bytes.len() && lower_bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let quote = *bytes.get(cursor)?;
        if matches!(quote, b'\'' | b'"') {
            cursor += 1;
            let end = bytes[cursor..].iter().position(|byte| *byte == quote)? + cursor;
            return Some(tag[cursor..end].to_owned());
        }
        let end = bytes[cursor..]
            .iter()
            .position(|byte| byte.is_ascii_whitespace() || *byte == b'>')
            .unwrap_or(bytes.len() - cursor)
            + cursor;
        return (end > cursor).then(|| tag[cursor..end].to_owned());
    }
    None
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme().eq_ignore_ascii_case(right.scheme())
        && left
            .host_str()
            .zip(right.host_str())
            .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
        && left.port_or_known_default() == right.port_or_known_default()
}

fn web_platform_hints<'a>(
    responses: impl Iterator<Item = &'a HttpObservation>,
) -> HashSet<&'static str> {
    let mut hints = HashSet::new();
    for response in responses {
        let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
        let headers = response
            .headers
            .iter()
            .map(|(name, value)| {
                format!(
                    "{}:{}",
                    name.to_ascii_lowercase(),
                    value.to_ascii_lowercase()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        if body.contains("wp-content")
            || body.contains("wp-includes")
            || body.contains("wordpress")
            || headers.contains("wp-json")
        {
            hints.insert("WordPress");
        }
        if body.contains("woocommerce") || headers.contains("woocommerce") {
            hints.insert("WooCommerce");
        }
        if body.contains("magento_")
            || body.contains("mage/")
            || body.contains("/static/version")
            || headers.contains("magento")
            || headers.contains("private_content_version")
        {
            hints.insert("Magento");
        }
        if body.contains("shopify")
            || body.contains("cdn.shopify.com")
            || body.contains("/cdn/shop/")
            || headers.contains("shopify")
        {
            hints.insert("Shopify");
        }
        if body.contains("silverstripe") || headers.contains("silverstripe") {
            hints.insert("Silverstripe");
        }
        if body.contains("bigcommerce")
            || body.contains("stencil-utils")
            || headers.contains("bigcommerce")
            || headers.contains("fornax_anonymousid")
        {
            hints.insert("BigCommerce");
        }
        if body.contains("prestashop") || headers.contains("prestashop") {
            hints.insert("PrestaShop");
        }
        if body.contains("opencart")
            || body.contains("catalog/view/theme")
            || headers.contains("ocsessid")
        {
            hints.insert("OpenCart");
        }
    }
    hints
}

async fn audit_management_http(
    endpoint: &mut EndpointScan,
    scheme: &str,
    context: ProbeContext<'_>,
    cookie_jar: Option<&Mutex<EndpointCookieJar>>,
) {
    let Some(path) = management_probe_path(context.port) else {
        return;
    };
    if context.scan.cancel.is_cancelled() {
        return;
    }
    let chain = request_http_chain_with_cookies(context, scheme, "GET", path, &[], cookie_jar)
        .await
        .unwrap_or_default();
    if let Some(response) = chain.last()
        && (200..300).contains(&response.status)
        && let Some(detection) = management_detection(context.port, path, response, endpoint)
    {
        set_service(
            endpoint,
            if scheme == "https" {
                ServiceKind::Https
            } else {
                ServiceKind::Http
            },
            Confidence::High,
            detection.service_evidence,
        );
        add_product(
            endpoint,
            detection.product,
            ProductLayer::Server,
            detection.version,
            Confidence::High,
            detection.product_evidence.to_owned(),
        );
        endpoint.findings.push(finding(
            endpoint,
            detection.title,
            detection.description,
            vec![
                format!(
                    "GET {path} returned {} without authentication",
                    response.status
                ),
                detection.product_evidence.to_owned(),
            ],
        ));
    } else if let Some(response) = chain.last()
        && matches!(response.status, 401 | 403)
    {
        endpoint.evidence.push(format!(
            "Protected management endpoint evidence: {path} returned {}",
            response.status
        ));
    }
    endpoint.http.extend(chain);
}

fn management_probe_path(port: u16) -> Option<&'static str> {
    match port {
        2375 | 2376 => Some("/version"),
        2379 | 2380 => Some("/version"),
        5984 => Some("/_all_dbs"),
        6443 => Some("/api"),
        8086 => Some("/query?q=SHOW%20DATABASES"),
        8089 => Some("/services/server/info?output_mode=json"),
        8500 => Some("/v1/agent/self"),
        9200 => Some("/_cluster/health"),
        10250 | 10255 => Some("/pods"),
        _ => None,
    }
}

struct ManagementDetection {
    product: &'static str,
    version: Option<String>,
    title: &'static str,
    description: &'static str,
    service_evidence: &'static str,
    product_evidence: &'static str,
}

fn management_detection(
    port: u16,
    path: &str,
    response: &HttpObservation,
    endpoint: &EndpointScan,
) -> Option<ManagementDetection> {
    let json = serde_json::from_slice::<serde_json::Value>(&response.body).ok()?;
    match (port, path) {
        (2375 | 2376, "/version")
            if json.get("ApiVersion").is_some() && json.get("Version").is_some() =>
        {
            Some(ManagementDetection {
                product: "Docker Engine",
                version: json_string(&json, "Version"),
                title: "Unauthenticated Docker Engine API",
                description: "The Docker Engine API returned management information without authentication; write access was not tested",
                service_evidence: "Docker Engine API JSON response",
                product_evidence: "Docker /version response contains Version and ApiVersion",
            })
        }
        (2379 | 2380, "/version")
            if json.get("etcdserver").is_some() && json.get("etcdcluster").is_some() =>
        {
            Some(ManagementDetection {
                product: "etcd",
                version: json_string(&json, "etcdserver"),
                title: "Unauthenticated etcd API information",
                description: "The etcd API disclosed server and cluster information without authentication",
                service_evidence: "etcd version API JSON response",
                product_evidence: "etcd /version response contains etcdserver and etcdcluster",
            })
        }
        (5984, "/_all_dbs")
            if json.is_array() && endpoint_has_json_key_value(endpoint, "couchdb", "Welcome") =>
        {
            Some(ManagementDetection {
                product: "CouchDB",
                version: endpoint_json_string(endpoint, "version"),
                title: "Unauthenticated CouchDB database enumeration",
                description: "CouchDB returned its database list without authentication",
                service_evidence: "CouchDB database-list API response",
                product_evidence: "CouchDB welcome signature and successful /_all_dbs response",
            })
        }
        (6443, "/api")
            if json.get("kind").and_then(|value| value.as_str()) == Some("APIVersions")
                && json.get("versions").is_some() =>
        {
            Some(ManagementDetection {
                product: "Kubernetes API",
                version: None,
                title: "Unauthenticated Kubernetes API discovery",
                description: "The Kubernetes API returned discovery information without authentication",
                service_evidence: "Kubernetes API discovery JSON response",
                product_evidence: "Kubernetes /api response identifies APIVersions",
            })
        }
        (8086, "/query?q=SHOW%20DATABASES") if influx_database_list(&json) => {
            Some(ManagementDetection {
                product: "InfluxDB",
                version: None,
                title: "Unauthenticated InfluxDB database enumeration",
                description: "InfluxDB returned its database list without authentication",
                service_evidence: "InfluxDB query API JSON response",
                product_evidence: "InfluxDB SHOW DATABASES returned a database series",
            })
        }
        (8089, "/services/server/info?output_mode=json")
            if json.get("entry").is_some() && json.get("generator").is_some() =>
        {
            Some(ManagementDetection {
                product: "Splunk",
                version: None,
                title: "Unauthenticated Splunk management information",
                description: "The Splunk management API returned server information without authentication",
                service_evidence: "Splunk management API JSON response",
                product_evidence: "Splunk server-info response contains entry and generator fields",
            })
        }
        (8500, "/v1/agent/self")
            if json.get("Config").is_some() && json.get("Member").is_some() =>
        {
            Some(ManagementDetection {
                product: "Consul",
                version: None,
                title: "Unauthenticated Consul agent information",
                description: "The Consul API returned agent configuration and membership information without authentication",
                service_evidence: "Consul agent API JSON response",
                product_evidence: "Consul /v1/agent/self response contains Config and Member",
            })
        }
        (9200, "/_cluster/health")
            if json.get("cluster_name").is_some()
                && json.get("status").is_some()
                && json.get("number_of_nodes").is_some() =>
        {
            Some(ManagementDetection {
                product: "Elasticsearch",
                version: endpoint_nested_json_string(endpoint, &["version", "number"]),
                title: "Unauthenticated Elasticsearch cluster information",
                description: "Elasticsearch returned cluster health information without authentication",
                service_evidence: "Elasticsearch cluster-health JSON response",
                product_evidence: "Elasticsearch /_cluster/health response contains cluster status and node count",
            })
        }
        (10250 | 10255, "/pods")
            if json.get("kind").and_then(|value| value.as_str()) == Some("PodList")
                && json.get("items").is_some() =>
        {
            Some(ManagementDetection {
                product: "Kubelet",
                version: None,
                title: "Unauthenticated Kubelet pod information",
                description: "The Kubelet API returned pod information without authentication",
                service_evidence: "Kubelet PodList JSON response",
                product_evidence: "Kubelet /pods response identifies a PodList",
            })
        }
        _ => None,
    }
}

fn json_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_owned)
}

fn endpoint_json_string(endpoint: &EndpointScan, key: &str) -> Option<String> {
    endpoint.http.iter().find_map(|response| {
        serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|json| json_string(&json, key))
    })
}

fn endpoint_nested_json_string(endpoint: &EndpointScan, keys: &[&str]) -> Option<String> {
    endpoint.http.iter().find_map(|response| {
        let json = serde_json::from_slice::<serde_json::Value>(&response.body).ok()?;
        keys.iter()
            .try_fold(&json, |value, key| value.get(*key))?
            .as_str()
            .map(str::to_owned)
    })
}

fn endpoint_has_json_key_value(endpoint: &EndpointScan, key: &str, expected: &str) -> bool {
    endpoint.http.iter().any(|response| {
        serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|json| json.get(key)?.as_str().map(str::to_owned))
            .is_some_and(|value| value.eq_ignore_ascii_case(expected))
    })
}

fn influx_database_list(json: &serde_json::Value) -> bool {
    json.get("results")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|result| result.get("series")?.as_array())
        .flatten()
        .any(|series| series.get("name").and_then(|value| value.as_str()) == Some("databases"))
}

fn finding(
    endpoint: &EndpointScan,
    title: &str,
    description: &str,
    evidence: Vec<String>,
) -> ExposureFinding {
    ExposureFinding {
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        evidence,
    }
}

fn add_missing_header_finding(endpoint: &mut EndpointScan, root: &HttpObservation, scheme: &str) {
    if !(200..300).contains(&root.status) {
        return;
    }
    let content_type = header_values(root, "content-type")
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.contains("text/html") {
        return;
    }
    let mut missing = Vec::new();
    if scheme == "https"
        && header_values(root, "strict-transport-security")
            .next()
            .is_none()
    {
        missing.push("Strict-Transport-Security");
    }
    if header_values(root, "content-security-policy")
        .next()
        .is_none()
    {
        missing.push("Content-Security-Policy");
    }
    if header_values(root, "x-content-type-options")
        .next()
        .is_none()
    {
        missing.push("X-Content-Type-Options");
    }
    if header_values(root, "referrer-policy").next().is_none() {
        missing.push("Referrer-Policy");
    }
    if missing.is_empty() {
        return;
    }
    endpoint.findings.push(finding(
        endpoint,
        "Browser security headers are missing",
        "The HTML document response omits applicable browser hardening headers",
        vec![format!("Missing: {}", missing.join(", "))],
    ));
}

fn redirect_is_https_for_host(base: &str, location: &str, hostname: &str) -> bool {
    Url::parse(base)
        .ok()
        .and_then(|base| base.join(location).ok())
        .is_some_and(|target| {
            target.scheme() == "https"
                && target
                    .host_str()
                    .is_some_and(|host| host.eq_ignore_ascii_case(hostname))
        })
}

fn cors_reflects_credentials(response: &HttpObservation, origin: &str) -> bool {
    header_values(response, "access-control-allow-origin")
        .any(|value| value.trim().eq_ignore_ascii_case(origin))
        && header_values(response, "access-control-allow-credentials")
            .any(|value| value.trim().eq_ignore_ascii_case("true"))
}

fn header_values<'a>(
    response: &'a HttpObservation,
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    response
        .headers
        .iter()
        .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

pub(super) fn looks_like_soft_404(
    baseline: &HttpObservation,
    candidate: &HttpObservation,
    baseline_path: &str,
    candidate_path: &str,
) -> bool {
    if baseline.status != candidate.status {
        return false;
    }
    if normalize_soft_redirect(baseline, baseline_path)
        != normalize_soft_redirect(candidate, candidate_path)
    {
        return false;
    }
    let baseline = normalize_soft_body(&baseline.body, baseline_path);
    let candidate = normalize_soft_body(&candidate.body, candidate_path);
    if baseline == candidate {
        return true;
    }
    let max_len = baseline.len().max(candidate.len());
    if max_len == 0 {
        return true;
    }
    let common = baseline
        .bytes()
        .zip(candidate.bytes())
        .filter(|(left, right)| left == right)
        .count();
    common * 100 / max_len >= 95
}

fn normalize_soft_redirect(response: &HttpObservation, request_path: &str) -> Option<String> {
    let location = response.redirect_location.as_deref()?;
    let source = Url::parse(&response.url).ok()?;
    let mut target = source.join(location).ok()?;
    if target.path().eq_ignore_ascii_case(request_path) {
        target.set_path("/{path}");
    }
    let pairs = target
        .query_pairs()
        .map(|(name, value)| {
            let value = value.replace(request_path, "{path}");
            (name.into_owned(), value)
        })
        .collect::<Vec<_>>();
    target.set_query(None);
    if !pairs.is_empty() {
        target.query_pairs_mut().extend_pairs(pairs);
    }
    Some(target.to_string().to_ascii_lowercase())
}

fn normalize_soft_body(body: &[u8], path: &str) -> String {
    String::from_utf8_lossy(body)
        .to_ascii_lowercase()
        .replace(&path.to_ascii_lowercase(), "{path}")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn sensitive_signature(
    path: &str,
    response: &HttpObservation,
) -> Option<(&'static str, &'static str, String)> {
    let text = String::from_utf8_lossy(&response.body);
    let lower = text.to_ascii_lowercase();
    let content_type = header_values(response, "content-type")
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match path {
        "/.git/HEAD" if lower.trim_start().starts_with("ref: refs/heads/") => Some((
            "Exposed Git repository metadata",
            "The Git HEAD reference is publicly readable",
            text.lines()
                .next()
                .unwrap_or_default()
                .chars()
                .take(160)
                .collect(),
        )),
        "/.env"
            if text.lines().any(|line| {
                let upper = line.trim().to_ascii_uppercase();
                upper.contains('=')
                    && ["APP_", "DB_", "DATABASE_", "SECRET", "PASSWORD", "AWS_"]
                        .iter()
                        .any(|prefix| upper.starts_with(prefix))
            }) =>
        {
            Some((
                "Exposed environment configuration",
                "A dotenv-style configuration containing sensitive key names is publicly readable",
                "Dotenv key/value signature detected; values withheld".to_owned(),
            ))
        }
        "/server-status" if lower.contains("apache server status") => Some((
            "Exposed server status endpoint",
            "Apache runtime status is publicly readable",
            "Apache Server Status marker detected".to_owned(),
        )),
        "/server-info"
            if lower.contains("apache server information") || lower.contains("server settings") =>
        {
            Some((
                "Exposed server information endpoint",
                "Server configuration information is publicly readable",
                "Apache server information marker detected".to_owned(),
            ))
        }
        "/phpinfo.php" if lower.contains("phpinfo()") && lower.contains("php version") => Some((
            "Exposed PHP information page",
            "The PHP runtime configuration page is publicly readable",
            "phpinfo() and PHP Version markers detected".to_owned(),
        )),
        "/metrics"
            if lower.contains("# help ")
                || lower.contains("# type ")
                || content_type.contains("openmetrics") =>
        {
            Some((
                "Exposed metrics endpoint",
                "Application or infrastructure metrics are publicly readable",
                "Prometheus/OpenMetrics content signature detected".to_owned(),
            ))
        }
        "/actuator" | "/actuator/health"
            if lower.contains("\"status\"")
                && (lower.contains("\"up\"") || lower.contains("_links")) =>
        {
            Some((
                "Exposed Spring Actuator endpoint",
                "A Spring Actuator management response is publicly readable",
                "Spring Actuator JSON signature detected".to_owned(),
            ))
        }
        "/openapi.json" | "/api-docs"
            if lower.contains("\"openapi\"") || lower.contains("\"swagger\"") =>
        {
            Some((
                "Exposed API specification",
                "An OpenAPI or Swagger specification is publicly readable",
                "OpenAPI/Swagger document signature detected".to_owned(),
            ))
        }
        "/swagger" | "/swagger/index.html"
            if lower.contains("swagger ui")
                || lower.contains("swagger-ui")
                || lower.contains("openapi") =>
        {
            Some((
                "Exposed API documentation",
                "Interactive or rendered API documentation is publicly reachable",
                "Swagger/OpenAPI UI signature detected".to_owned(),
            ))
        }
        "/debug"
            if lower.contains("debug toolbar")
                || lower.contains("stack trace")
                || lower.contains("traceback (most recent call last)") =>
        {
            Some((
                "Exposed debug endpoint",
                "A response containing diagnostic or stack-trace markers is publicly readable",
                "Debug or stack-trace signature detected".to_owned(),
            ))
        }
        _ => None,
    }
}

async fn request_http_chain(
    context: ProbeContext<'_>,
    initial_scheme: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<Vec<HttpObservation>, String> {
    request_http_chain_with_limit(
        context,
        initial_scheme,
        method,
        path,
        extra_headers,
        MAX_HTTP_BODY_BYTES,
    )
    .await
}

async fn request_http_chain_with_limit(
    context: ProbeContext<'_>,
    initial_scheme: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body_limit: usize,
) -> Result<Vec<HttpObservation>, String> {
    request_http_chain_options(
        context,
        initial_scheme,
        method,
        path,
        extra_headers,
        body_limit,
        None,
    )
    .await
}

async fn request_http_chain_with_cookies(
    context: ProbeContext<'_>,
    initial_scheme: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    cookie_jar: Option<&Mutex<EndpointCookieJar>>,
) -> Result<Vec<HttpObservation>, String> {
    if cookie_jar.is_none() {
        return request_http_chain(context, initial_scheme, method, path, extra_headers).await;
    }
    request_http_chain_options(
        context,
        initial_scheme,
        method,
        path,
        extra_headers,
        MAX_HTTP_BODY_BYTES,
        cookie_jar,
    )
    .await
}

async fn request_http_chain_with_limit_and_cookies(
    context: ProbeContext<'_>,
    initial_scheme: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body_limit: usize,
    cookie_jar: Option<&Mutex<EndpointCookieJar>>,
) -> Result<Vec<HttpObservation>, String> {
    if cookie_jar.is_none() {
        return request_http_chain_with_limit(
            context,
            initial_scheme,
            method,
            path,
            extra_headers,
            body_limit,
        )
        .await;
    }
    request_http_chain_options(
        context,
        initial_scheme,
        method,
        path,
        extra_headers,
        body_limit,
        cookie_jar,
    )
    .await
}

async fn request_http_chain_options(
    context: ProbeContext<'_>,
    initial_scheme: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body_limit: usize,
    cookie_jar: Option<&Mutex<EndpointCookieJar>>,
) -> Result<Vec<HttpObservation>, String> {
    let mut url = Url::parse(&format!(
        "{}://{}:{}{}",
        initial_scheme,
        url_host(context.scan.hostname),
        context.port,
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    ))
    .map_err(|error| error.to_string())?;
    let mut observations = Vec::new();
    for redirect_count in 0..=3 {
        if context.scan.cancel.is_cancelled() {
            return Err("Scan cancelled".to_owned());
        }
        let scheme = url.scheme().to_owned();
        if !matches!(scheme.as_str(), "http" | "https") {
            break;
        }
        let port = url
            .port_or_known_default()
            .ok_or_else(|| "Redirect URL has no usable port".to_owned())?;
        let request_path = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };
        let cookie_header = if matches!(method, "GET" | "HEAD") {
            cookie_jar.and_then(|jar| jar.lock().ok()?.cookie_header(&url))
        } else {
            None
        };
        let request = match (cookie_header.as_deref(), body_limit == MAX_HTTP_BODY_BYTES) {
            (None, true) => {
                single_http_request(
                    context.with_port(port),
                    &scheme,
                    method,
                    &request_path,
                    extra_headers,
                )
                .await
            }
            (None, false) => {
                single_http_request_with_limit(
                    context.with_port(port),
                    &scheme,
                    method,
                    &request_path,
                    extra_headers,
                    body_limit,
                )
                .await
            }
            (Some(cookie_header), _) => {
                single_http_request_with_cookie(
                    context.with_port(port),
                    &scheme,
                    method,
                    &request_path,
                    extra_headers,
                    body_limit,
                    Some(cookie_header),
                )
                .await
            }
        };
        let mut response = match request {
            Ok(response) => response,
            Err(_) if !observations.is_empty() => break,
            Err(error) => return Err(error),
        };
        response.url = url.to_string();
        if let Some(jar) = cookie_jar
            && let Ok(mut jar) = jar.lock()
        {
            jar.observe_response(&url, &response);
        }
        let location = response.redirect_location.clone();
        observations.push(response);
        let Some(location) = location else {
            break;
        };
        if redirect_count == 3 {
            break;
        }
        let next = match url.join(&location) {
            Ok(next) => next,
            Err(_) => break,
        };
        let same_host = next
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case(context.scan.hostname));
        if !same_host || !matches!(next.scheme(), "http" | "https") {
            break;
        }
        url = next;
    }
    Ok(observations)
}

async fn single_http_request(
    context: ProbeContext<'_>,
    scheme: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<HttpObservation, String> {
    single_http_request_with_limit(
        context,
        scheme,
        method,
        path,
        extra_headers,
        MAX_HTTP_BODY_BYTES,
    )
    .await
}

async fn single_http_request_with_limit(
    context: ProbeContext<'_>,
    scheme: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body_limit: usize,
) -> Result<HttpObservation, String> {
    single_http_request_with_cookie(
        context,
        scheme,
        method,
        path,
        extra_headers,
        body_limit,
        None,
    )
    .await
}

async fn single_http_request_with_cookie(
    context: ProbeContext<'_>,
    scheme: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body_limit: usize,
    cookie_header: Option<&str>,
) -> Result<HttpObservation, String> {
    let operation = async {
        let (mut stream, tls_unverified) = connect_http_stream(context, scheme).await?;
        let host_header = host_header(context.scan.hostname, context.port, scheme);
        let mut request_bytes = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: nancywebdebug-exposure/{}\r\nAccept: */*\r\nConnection: close\r\n",
            env!("CARGO_PKG_VERSION")
        );
        for (name, value) in extra_headers {
            request_bytes.push_str(name);
            request_bytes.push_str(": ");
            request_bytes.push_str(value);
            request_bytes.push_str("\r\n");
        }
        if let Some(cookie_header) = cookie_header {
            request_bytes.push_str("Cookie: ");
            request_bytes.push_str(cookie_header);
            request_bytes.push_str("\r\n");
        }
        request_bytes.push_str("\r\n");
        stream
            .write_all(request_bytes.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        stream.flush().await.map_err(|error| error.to_string())?;
        let bytes = read_http_response(&mut stream, method, body_limit).await?;
        parse_http_response(method, bytes, tls_unverified, body_limit)
    };
    tokio::select! {
        _ = context.scan.cancel.cancelled() => Err("Scan cancelled".to_owned()),
        result = tokio::time::timeout(context.scan.request.probe_timeout, operation) => {
            result.map_err(|_| "HTTP probe timed out".to_owned())?
        }
    }
}

async fn connect_http_stream(
    context: ProbeContext<'_>,
    scheme: &str,
) -> Result<(ScanIo, bool), String> {
    if scheme == "http" {
        let mut candidate = limited_connect(context).await;
        return candidate
            .stream
            .take()
            .map(|stream| (ScanIo::Plain(stream), false))
            .ok_or_else(|| {
                candidate
                    .attempt
                    .error
                    .unwrap_or_else(|| "TCP connection failed".to_owned())
            });
    }
    let verified = TlsHandshakeOptions {
        version: None,
        permissive: false,
        offer_http2: false,
    };
    match tls_handshake(context, verified).await {
        Ok(success) => Ok((ScanIo::Tls(Box::new(success.stream)), false)),
        Err(failure) => {
            if failure.trace.validation_error.is_none() {
                return Err(failure.error);
            }
            let validated_error = failure.error;
            let permissive = TlsHandshakeOptions {
                permissive: true,
                ..verified
            };
            tls_handshake(context, permissive)
                .await
                .map(|success| (ScanIo::Tls(Box::new(success.stream)), true))
                .map_err(|fallback| {
                    format!(
                        "Validated TLS failed: {validated_error}; permissive retry failed: {}",
                        fallback.error
                    )
                })
        }
    }
}

async fn read_http_response(
    stream: &mut ScanIo,
    method: &str,
    body_limit: usize,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut header_end = None;
    loop {
        let read_timeout = if header_end.is_some() {
            Duration::from_millis(500)
        } else {
            Duration::from_secs(5)
        };
        let read = tokio::time::timeout(read_timeout, stream.read(&mut buffer)).await;
        let length = match read {
            Ok(Ok(length)) => length,
            Ok(Err(error)) => return Err(error.to_string()),
            Err(_) if header_end.is_some() => break,
            Err(_) => return Err("HTTP response headers timed out".to_owned()),
        };
        if length == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..length]);
        if header_end.is_none() {
            header_end = find_header_end(&bytes);
            if header_end.is_none() && bytes.len() > MAX_HTTP_HEADER_BYTES {
                return Err("HTTP response headers exceed 64 KiB".to_owned());
            }
        }
        if let Some(end) = header_end {
            if method.eq_ignore_ascii_case("HEAD") {
                bytes.truncate(end);
                break;
            }
            let header_text = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
            let body_length = bytes.len().saturating_sub(end);
            if let Some(content_length) = parse_content_length(&header_text)
                && body_length >= content_length.min(body_limit + 1)
            {
                break;
            }
            if header_text.contains("transfer-encoding: chunked")
                && bytes[end..].windows(5).any(|window| window == b"0\r\n\r\n")
            {
                break;
            }
            if body_length > body_limit {
                break;
            }
        }
    }
    Ok(bytes)
}

fn parse_http_response(
    method: &str,
    bytes: Vec<u8>,
    tls_unverified: bool,
    body_limit: usize,
) -> Result<HttpObservation, String> {
    let header_end = find_header_end(&bytes).ok_or_else(|| "Incomplete HTTP headers".to_owned())?;
    let header_text = String::from_utf8_lossy(&bytes[..header_end]);
    let mut lines = header_text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "Missing HTTP status line".to_owned())?;
    let mut status_parts = status_line.trim_end_matches('\r').splitn(3, ' ');
    let protocol = status_parts.next().unwrap_or_default();
    if !protocol.starts_with("HTTP/") {
        return Err("Response does not contain an HTTP status line".to_owned());
    }
    let status = status_parts
        .next()
        .ok_or_else(|| "HTTP status code is missing".to_owned())?
        .parse::<u16>()
        .map_err(|_| "HTTP status code is invalid".to_owned())?;
    let reason = status_parts.next().unwrap_or_default().trim().to_owned();
    let headers = lines
        .filter_map(|line| line.trim_end_matches('\r').split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect::<Vec<_>>();
    let mut body = if method.eq_ignore_ascii_case("HEAD") {
        Vec::new()
    } else {
        bytes[header_end..].to_vec()
    };
    if headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    }) {
        body = decode_chunked(&body, body_limit).unwrap_or(body);
    }
    let body_truncated = body.len() > body_limit;
    body.truncate(body_limit);
    let redirect_location = if matches!(status, 301 | 302 | 303 | 307 | 308) {
        headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, value)| value.clone())
    } else {
        None
    };
    Ok(HttpObservation {
        method: method.to_owned(),
        url: String::new(),
        status,
        reason,
        headers,
        body,
        body_truncated,
        tls_unverified,
        redirect_location,
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| index + 2)
        })
}

fn parse_content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

fn decode_chunked(bytes: &[u8], body_limit: usize) -> Option<Vec<u8>> {
    let mut position = 0usize;
    let mut output = Vec::new();
    loop {
        let line_end = bytes[position..]
            .windows(2)
            .position(|window| window == b"\r\n")?
            + position;
        let size_text = std::str::from_utf8(&bytes[position..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        position = line_end + 2;
        if size == 0 {
            return Some(output);
        }
        let end = position.checked_add(size)?;
        if end + 2 > bytes.len() {
            return None;
        }
        output.extend_from_slice(&bytes[position..end]);
        if output.len() > body_limit {
            return Some(output);
        }
        position = end + 2;
    }
}

fn url_host(hostname: &str) -> String {
    if hostname.parse::<Ipv6Addr>().is_ok() {
        format!("[{hostname}]")
    } else {
        hostname.to_owned()
    }
}

fn host_header(hostname: &str, port: u16, scheme: &str) -> String {
    let hostname = url_host(hostname);
    if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
        hostname
    } else {
        format!("{hostname}:{port}")
    }
}

#[derive(Clone)]
struct ProductSignal {
    source: String,
    evidence: String,
    kind: ProductSignalKind,
    version: Option<String>,
}

#[derive(Clone, Copy)]
enum ProductSignalKind {
    Validated,
    CatalogHigh,
    StrongExplicit,
    Strong,
    Indirect,
}

fn apply_product_rules(endpoint: &mut EndpointScan) {
    let mut signals: HashMap<(&'static str, ProductLayer), Vec<ProductSignal>> = HashMap::new();
    let web_detections = detect_web_servers(
        endpoint.http.iter().flat_map(|response| {
            response
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
        }),
        &endpoint
            .http
            .iter()
            .flat_map(|response| response.body.iter().copied())
            .collect::<Vec<_>>(),
    );
    for detection in web_detections {
        let layer = match detection.role {
            WebProductRole::Server => ProductLayer::Server,
            WebProductRole::Proxy => ProductLayer::Proxy,
        };
        let kind = match detection.confidence {
            FingerprintConfidence::High => ProductSignalKind::CatalogHigh,
            FingerprintConfidence::Medium => ProductSignalKind::StrongExplicit,
        };
        for evidence in detection.evidence {
            record_product_signal(
                &mut signals,
                detection.product,
                layer,
                format!("web-server:{}", detection.identifier),
                evidence,
                kind,
                detection.version.clone(),
            );
        }
    }
    for response in &endpoint.http {
        for (name, value) in &response.headers {
            let header = name.to_ascii_lowercase();
            let lower = value.to_ascii_lowercase();
            if header == "server" {
                for (needle, product, layer) in [
                    ("cloudflare", "Cloudflare", ProductLayer::Cdn),
                    ("gws", "Google Frontend", ProductLayer::Cloud),
                    ("google frontend", "Google Frontend", ProductLayer::Cloud),
                ] {
                    if lower.contains(needle) {
                        record_product_signal(
                            &mut signals,
                            product,
                            layer,
                            "header:server".to_owned(),
                            format!("Server: {value}"),
                            ProductSignalKind::StrongExplicit,
                            extract_version(value, needle),
                        );
                    }
                }
                if lower.contains("amazons3") || lower.contains("amazon") {
                    record_product_signal(
                        &mut signals,
                        "AWS",
                        ProductLayer::Cloud,
                        "header:server".to_owned(),
                        format!("Server: {value}"),
                        ProductSignalKind::StrongExplicit,
                        extract_version(value, "amazon"),
                    );
                }
            }
            if header == "x-powered-by" {
                for (needle, product, layer) in [
                    ("express", "Express", ProductLayer::Framework),
                    ("asp.net", "ASP.NET", ProductLayer::Framework),
                    ("php", "PHP", ProductLayer::Runtime),
                ] {
                    if lower.contains(needle) {
                        record_product_signal(
                            &mut signals,
                            product,
                            layer,
                            "header:x-powered-by".to_owned(),
                            format!("X-Powered-By: {value}"),
                            ProductSignalKind::StrongExplicit,
                            extract_version(value, needle),
                        );
                    }
                }
            }
            if matches!(header.as_str(), "cf-cache-status" | "cf-request-id") {
                record_product_signal(
                    &mut signals,
                    "Cloudflare",
                    ProductLayer::Cdn,
                    format!("header:{header}"),
                    format!("{name}: {value}"),
                    ProductSignalKind::Strong,
                    None,
                );
            }
            if header.starts_with("x-amz-") || header.starts_with("x-amzn-") {
                record_product_signal(
                    &mut signals,
                    "AWS",
                    ProductLayer::Cloud,
                    format!("header:{header}"),
                    format!("{name}: {value}"),
                    ProductSignalKind::Strong,
                    None,
                );
            }
            if header.starts_with("x-azure-")
                || header.starts_with("x-ms-")
                || (header == "set-cookie" && lower.contains("arraffinity"))
            {
                record_product_signal(
                    &mut signals,
                    "Azure",
                    ProductLayer::Cloud,
                    format!("header:{header}"),
                    format!("{name}: {value}"),
                    ProductSignalKind::Strong,
                    None,
                );
            }
            if matches!(
                header.as_str(),
                "x-cloud-trace-context" | "x-goog-generation"
            ) {
                record_product_signal(
                    &mut signals,
                    "Google Frontend",
                    ProductLayer::Cloud,
                    format!("header:{header}"),
                    format!("{name}: {value}"),
                    ProductSignalKind::Strong,
                    None,
                );
            }
            if header == "x-varnish" || (header == "via" && lower.contains("varnish")) {
                record_product_signal(
                    &mut signals,
                    "Varnish",
                    ProductLayer::Proxy,
                    format!("header:{header}"),
                    format!("{name}: {value}"),
                    ProductSignalKind::Strong,
                    None,
                );
            }
            if header == "set-cookie" && lower.contains("jsessionid") {
                record_product_signal(
                    &mut signals,
                    "Apache Tomcat",
                    ProductLayer::Server,
                    "cookie:jsessionid".to_owned(),
                    "JSESSIONID cookie".to_owned(),
                    ProductSignalKind::Indirect,
                    None,
                );
                record_product_signal(
                    &mut signals,
                    "Spring",
                    ProductLayer::Framework,
                    "cookie:jsessionid".to_owned(),
                    "JSESSIONID cookie".to_owned(),
                    ProductSignalKind::Indirect,
                    None,
                );
            }
        }
        let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
        if body.contains("whitelabel error page") || body.contains("spring boot") {
            record_product_signal(
                &mut signals,
                "Spring",
                ProductLayer::Framework,
                "body:spring-marker".to_owned(),
                "Spring page marker".to_owned(),
                ProductSignalKind::Indirect,
                None,
            );
        }
        if body.contains("apache tomcat") {
            record_product_signal(
                &mut signals,
                "Apache Tomcat",
                ProductLayer::Server,
                "body:tomcat-marker".to_owned(),
                "Apache Tomcat page marker".to_owned(),
                ProductSignalKind::Indirect,
                None,
            );
        }
    }
    for tls in &endpoint.tls {
        for certificate in &tls.certificates {
            let identity =
                format!("{} {}", certificate.subject, certificate.issuer).to_ascii_lowercase();
            for (needle, product, layer) in [
                ("cloudflare", "Cloudflare", ProductLayer::Cdn),
                ("amazon", "AWS", ProductLayer::Cloud),
                ("microsoft", "Azure", ProductLayer::Cloud),
                ("google", "Google Frontend", ProductLayer::Cloud),
            ] {
                if identity.contains(needle) {
                    record_product_signal(
                        &mut signals,
                        product,
                        layer,
                        "tls:certificate-identity".to_owned(),
                        format!("TLS certificate subject/issuer contains {needle}"),
                        ProductSignalKind::Indirect,
                        None,
                    );
                }
            }
        }
    }
    record_web_product_signals(endpoint, &mut signals);
    for ((name, layer), mut product_signals) in signals {
        product_signals.sort_by(|left, right| left.evidence.cmp(&right.evidence));
        product_signals.dedup_by(|left, right| left.evidence == right.evidence);
        let strong_count = product_signals
            .iter()
            .filter(|signal| {
                matches!(
                    signal.kind,
                    ProductSignalKind::Validated
                        | ProductSignalKind::CatalogHigh
                        | ProductSignalKind::StrongExplicit
                        | ProductSignalKind::Strong
                )
            })
            .map(|signal| signal.source.as_str())
            .collect::<HashSet<_>>()
            .len();
        let explicit = product_signals
            .iter()
            .any(|signal| matches!(signal.kind, ProductSignalKind::StrongExplicit));
        let validated = product_signals.iter().any(|signal| {
            matches!(
                signal.kind,
                ProductSignalKind::Validated | ProductSignalKind::CatalogHigh
            )
        });
        let confidence = if validated || strong_count >= 2 {
            Confidence::High
        } else if explicit {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        let version = product_signals
            .iter()
            .find_map(|signal| signal.version.clone());
        let evidence = product_signals
            .into_iter()
            .map(|signal| signal.evidence)
            .collect::<Vec<_>>();
        for item in evidence {
            add_product(endpoint, name, layer, version.clone(), confidence, item);
        }
    }
    if matches!(endpoint.service, ServiceKind::Http | ServiceKind::Https)
        && endpoint.products.is_empty()
    {
        endpoint
            .evidence
            .push("HTTP service confirmed; product undisclosed".to_owned());
    }
}

fn reconcile_web_server_products(endpoints: &mut [EndpointScan]) {
    for endpoint in endpoints {
        let detections = detect_web_servers(
            endpoint.http.iter().flat_map(|response| {
                response
                    .headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str()))
            }),
            &endpoint
                .http
                .iter()
                .flat_map(|response| response.body.iter().copied())
                .collect::<Vec<_>>(),
        );
        for detection in detections {
            let layer = match detection.role {
                WebProductRole::Server => ProductLayer::Server,
                WebProductRole::Proxy => ProductLayer::Proxy,
            };
            if let Some(product) = endpoint.products.iter_mut().find(|product| {
                product.layer == layer && product.name.eq_ignore_ascii_case(detection.product)
            }) {
                product.name = detection.product.to_owned();
                product.version = detection.version;
                product.confidence = product.confidence.max(match detection.confidence {
                    FingerprintConfidence::High => Confidence::High,
                    FingerprintConfidence::Medium => Confidence::Medium,
                });
                product.evidence.extend(detection.evidence);
                product.evidence.sort();
                product.evidence.dedup();
            }
        }
    }
}

fn record_web_product_signals(
    endpoint: &EndpointScan,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    let mut generic = HashMap::<&'static str, String>::new();
    let baselines = endpoint
        .http
        .iter()
        .filter(|response| response.url.contains("/nancy-exposure-not-found-"))
        .cloned()
        .collect::<Vec<_>>();
    for response in &endpoint.http {
        if !response_on_endpoint_port(response, endpoint.port)
            || (!((200..300).contains(&response.status)) && !matches!(response.status, 401 | 403))
            || response.url.contains("/nancy-exposure-not-found-")
            || response_is_soft_404(response, &baselines)
        {
            continue;
        }
        let body = String::from_utf8_lossy(&response.body);
        let lower = body.to_ascii_lowercase();
        let generator = html_generator(&body);
        let generator_lower = generator
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let path = response_path_query(response);
        for generator in html_generators(&body) {
            record_known_generator_signal(&generator, signals);
        }
        record_vendor_header_signals(response, signals);

        if generator_lower.contains("wordpress") {
            record_product_signal(
                signals,
                "WordPress",
                ProductLayer::Cms,
                "wordpress:generator".to_owned(),
                format!(
                    "Generator metadata: {}",
                    generator.as_deref().unwrap_or_default()
                ),
                ProductSignalKind::StrongExplicit,
                generator
                    .as_deref()
                    .and_then(|value| extract_version(value, "WordPress")),
            );
        }
        for (needle, source, evidence) in [
            (
                "wp-content/",
                "wordpress:content-path",
                "WordPress wp-content asset path",
            ),
            (
                "wp-includes/",
                "wordpress:includes-path",
                "WordPress wp-includes asset path",
            ),
            (
                "api.w.org",
                "wordpress:api-link",
                "WordPress REST API link relation",
            ),
        ] {
            if lower.contains(needle) {
                record_product_signal(
                    signals,
                    "WordPress",
                    ProductLayer::Cms,
                    source.to_owned(),
                    evidence.to_owned(),
                    ProductSignalKind::Strong,
                    None,
                );
            }
        }
        if response.headers.iter().any(|(name, value)| {
            (name.eq_ignore_ascii_case("link") && value.to_ascii_lowercase().contains("wp-json"))
                || (name.eq_ignore_ascii_case("x-pingback")
                    && value.to_ascii_lowercase().contains("xmlrpc.php"))
        }) {
            record_product_signal(
                signals,
                "WordPress",
                ProductLayer::Cms,
                "wordpress:header".to_owned(),
                "WordPress REST or XML-RPC response header".to_owned(),
                ProductSignalKind::StrongExplicit,
                None,
            );
        }
        if cookie_contains(response, "wordpress_") || cookie_contains(response, "wp-settings-") {
            record_product_signal(
                signals,
                "WordPress",
                ProductLayer::Cms,
                "wordpress:cookie".to_owned(),
                "WordPress cookie name".to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        }
        if wordpress_api_response(response, &path) {
            record_product_signal(
                signals,
                "WordPress",
                ProductLayer::Cms,
                "wordpress:validated-api".to_owned(),
                format!("Validated WordPress REST API response at {}", response.url),
                ProductSignalKind::Validated,
                None,
            );
        }

        if generator_lower.contains("woocommerce") {
            record_product_signal(
                signals,
                "WooCommerce",
                ProductLayer::Ecommerce,
                "woocommerce:generator".to_owned(),
                format!(
                    "Generator metadata: {}",
                    generator.as_deref().unwrap_or_default()
                ),
                ProductSignalKind::StrongExplicit,
                generator
                    .as_deref()
                    .and_then(|value| extract_version(value, "WooCommerce")),
            );
        }
        for (needle, source, evidence) in [
            (
                "/plugins/woocommerce/",
                "woocommerce:assets",
                "WooCommerce plugin asset path",
            ),
            (
                "class=\"woocommerce",
                "woocommerce:class",
                "WooCommerce HTML class",
            ),
            (
                "wc-cart-fragments",
                "woocommerce:cart-script",
                "WooCommerce cart-fragments script",
            ),
            (
                "wc_add_to_cart_params",
                "woocommerce:global",
                "WooCommerce storefront JavaScript global",
            ),
        ] {
            if lower.contains(needle) {
                record_product_signal(
                    signals,
                    "WooCommerce",
                    ProductLayer::Ecommerce,
                    source.to_owned(),
                    evidence.to_owned(),
                    ProductSignalKind::Strong,
                    None,
                );
            }
        }
        if cookie_contains(response, "woocommerce_")
            || cookie_contains(response, "woocommerce_cart_hash")
            || cookie_contains(response, "wp_woocommerce_session_")
        {
            record_product_signal(
                signals,
                "WooCommerce",
                ProductLayer::Ecommerce,
                "woocommerce:cookie".to_owned(),
                "WooCommerce cart or session cookie".to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        }
        if woocommerce_api_response(response, &path) {
            record_product_signal(
                signals,
                "WooCommerce",
                ProductLayer::Ecommerce,
                "woocommerce:validated-api".to_owned(),
                format!(
                    "Validated WooCommerce Store API response at {}",
                    response.url
                ),
                ProductSignalKind::Validated,
                None,
            );
        }

        record_magento_signals(
            response,
            &lower,
            generator.as_deref(),
            &generator_lower,
            &path,
            signals,
        );
        record_shopify_signals(
            response,
            &lower,
            generator.as_deref(),
            &generator_lower,
            &path,
            signals,
        );
        record_other_store_signals(
            response,
            &lower,
            generator.as_deref(),
            &generator_lower,
            &path,
            signals,
        );

        if is_storefront_document(response) {
            collect_generic_commerce_signals(&lower, &mut generic);
        }
    }
    let has_product = generic.contains_key("product") || generic.contains_key("offer");
    let has_transaction = generic.contains_key("checkout") || generic.contains_key("payment");
    if generic.len() >= 3 && has_product && generic.contains_key("cart") && has_transaction {
        let mut evidence = generic.into_iter().collect::<Vec<_>>();
        evidence.sort_by_key(|(category, _)| *category);
        for (category, item) in evidence {
            record_product_signal(
                signals,
                "Generic commerce",
                ProductLayer::Ecommerce,
                format!("commerce:{category}"),
                item,
                ProductSignalKind::Indirect,
                None,
            );
        }
    }
}

fn record_magento_signals(
    response: &HttpObservation,
    lower: &str,
    generator: Option<&str>,
    generator_lower: &str,
    path: &str,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    if generator_lower.contains("magento") || generator_lower.contains("adobe commerce") {
        let product = if generator_lower.contains("adobe commerce") {
            "Adobe Commerce"
        } else {
            "Magento"
        };
        record_product_signal(
            signals,
            product,
            ProductLayer::Ecommerce,
            "magento:generator".to_owned(),
            format!("Generator metadata: {}", generator.unwrap_or_default()),
            ProductSignalKind::StrongExplicit,
            generator.and_then(|value| {
                extract_version(value, "Magento")
                    .or_else(|| extract_version(value, "Adobe Commerce"))
            }),
        );
    }
    for (needle, source, evidence) in [
        ("magento_", "magento:module", "Magento module marker"),
        ("/mage/", "magento:mage-asset", "Magento mage asset path"),
        (
            "/static/version",
            "magento:versioned-asset",
            "Magento static version asset path",
        ),
        (
            "mage/cookies",
            "magento:javascript",
            "Magento mage JavaScript module",
        ),
    ] {
        if lower.contains(needle) {
            record_product_signal(
                signals,
                "Magento",
                ProductLayer::Ecommerce,
                source.to_owned(),
                evidence.to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        }
    }
    if response
        .headers
        .iter()
        .any(|(name, _)| name.to_ascii_lowercase().starts_with("x-magento-"))
    {
        record_product_signal(
            signals,
            "Magento",
            ProductLayer::Ecommerce,
            "magento:header".to_owned(),
            "Magento-specific response header".to_owned(),
            ProductSignalKind::StrongExplicit,
            None,
        );
    }
    if cookie_contains(response, "private_content_version")
        || cookie_contains(response, "mage-cache-")
        || cookie_contains(response, "form_key")
    {
        record_product_signal(
            signals,
            "Magento",
            ProductLayer::Ecommerce,
            "magento:cookie".to_owned(),
            "Magento storefront cookie".to_owned(),
            ProductSignalKind::Strong,
            None,
        );
    }
    if magento_api_response(response, path) {
        record_product_signal(
            signals,
            "Magento",
            ProductLayer::Ecommerce,
            "magento:validated-api".to_owned(),
            format!(
                "Validated Magento store configuration API at {}",
                response.url
            ),
            ProductSignalKind::Validated,
            None,
        );
    }
}

fn record_shopify_signals(
    response: &HttpObservation,
    lower: &str,
    generator: Option<&str>,
    generator_lower: &str,
    path: &str,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    if generator_lower.contains("shopify") {
        record_product_signal(
            signals,
            "Shopify",
            ProductLayer::Ecommerce,
            "shopify:generator".to_owned(),
            format!("Generator metadata: {}", generator.unwrap_or_default()),
            ProductSignalKind::StrongExplicit,
            generator.and_then(|value| extract_version(value, "Shopify")),
        );
    }
    for (needle, source, evidence) in [
        ("cdn.shopify.com", "shopify:cdn", "Shopify CDN asset URL"),
        (
            "/cdn/shop/",
            "shopify:asset-path",
            "Shopify /cdn/shop asset path",
        ),
        (
            "shopify.theme",
            "shopify:global-theme",
            "Shopify.theme JavaScript global",
        ),
        (
            "shopify.routes",
            "shopify:global-routes",
            "Shopify.routes JavaScript global",
        ),
        (
            "shopify-section",
            "shopify:section-markup",
            "Shopify product or collection section markup",
        ),
        (
            "data-shopify",
            "shopify:data-markup",
            "Shopify data attribute markup",
        ),
    ] {
        if lower.contains(needle) {
            record_product_signal(
                signals,
                "Shopify",
                ProductLayer::Ecommerce,
                source.to_owned(),
                evidence.to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        }
    }
    if response.headers.iter().any(|(name, _)| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "x-shopid" | "x-shopify-stage" | "x-shopify-shop-api-call-limit"
        )
    }) {
        record_product_signal(
            signals,
            "Shopify",
            ProductLayer::Ecommerce,
            "shopify:header".to_owned(),
            "Shopify-specific response header".to_owned(),
            ProductSignalKind::StrongExplicit,
            None,
        );
    }
    if cookie_contains(response, "_shopify_") || cookie_contains(response, "_shopify_y") {
        record_product_signal(
            signals,
            "Shopify",
            ProductLayer::Ecommerce,
            "shopify:cookie".to_owned(),
            "Shopify storefront cookie".to_owned(),
            ProductSignalKind::Strong,
            None,
        );
    }
    if shopify_cart_response(response, path) {
        record_product_signal(
            signals,
            "Shopify",
            ProductLayer::Ecommerce,
            "shopify:validated-cart-api".to_owned(),
            format!("Validated Shopify cart API response at {}", response.url),
            ProductSignalKind::Validated,
            None,
        );
    }
}

fn record_other_store_signals(
    response: &HttpObservation,
    lower: &str,
    generator: Option<&str>,
    generator_lower: &str,
    path: &str,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    for (needle, product, layer) in [
        ("sulu", "Sulu", ProductLayer::Cms),
        ("silverstripe", "Silverstripe", ProductLayer::Cms),
        ("bigcommerce", "BigCommerce", ProductLayer::Ecommerce),
        ("prestashop", "PrestaShop", ProductLayer::Ecommerce),
        ("opencart", "OpenCart", ProductLayer::Ecommerce),
    ] {
        if generator_lower.contains(needle) {
            record_product_signal(
                signals,
                product,
                layer,
                format!("{needle}:generator"),
                format!("Generator metadata: {}", generator.unwrap_or_default()),
                ProductSignalKind::StrongExplicit,
                generator.and_then(|value| extract_version(value, product)),
            );
        }
    }
    for (needle, product, layer, source, evidence) in [
        (
            "/resources/vendor/silverstripe/",
            "Silverstripe",
            ProductLayer::Cms,
            "silverstripe:resource",
            "Silverstripe vendor resource path",
        ),
        (
            "silverstripe.security",
            "Silverstripe",
            ProductLayer::Cms,
            "silverstripe:global",
            "Silverstripe client-side marker",
        ),
        (
            "stencil-utils",
            "BigCommerce",
            ProductLayer::Ecommerce,
            "bigcommerce:stencil",
            "BigCommerce Stencil asset",
        ),
        (
            "cdn11.bigcommerce.com",
            "BigCommerce",
            ProductLayer::Ecommerce,
            "bigcommerce:cdn",
            "BigCommerce CDN asset URL",
        ),
        (
            "stencilbootstrap",
            "BigCommerce",
            ProductLayer::Ecommerce,
            "bigcommerce:global",
            "BigCommerce Stencil JavaScript global",
        ),
        (
            "window.prestashop",
            "PrestaShop",
            ProductLayer::Ecommerce,
            "prestashop:global",
            "PrestaShop JavaScript global",
        ),
        (
            "prestashop.modules",
            "PrestaShop",
            ProductLayer::Ecommerce,
            "prestashop:module",
            "PrestaShop module marker",
        ),
        (
            "/modules/ps_",
            "PrestaShop",
            ProductLayer::Ecommerce,
            "prestashop:module-path",
            "PrestaShop module asset path",
        ),
        (
            "/themes/classic/assets/",
            "PrestaShop",
            ProductLayer::Ecommerce,
            "prestashop:theme-path",
            "PrestaShop classic-theme asset path",
        ),
        (
            "catalog/view/theme/",
            "OpenCart",
            ProductLayer::Ecommerce,
            "opencart:theme",
            "OpenCart theme asset path",
        ),
        (
            "route=common/home",
            "OpenCart",
            ProductLayer::Ecommerce,
            "opencart:route",
            "OpenCart storefront route",
        ),
    ] {
        if lower.contains(needle) {
            record_product_signal(
                signals,
                product,
                layer,
                source.to_owned(),
                evidence.to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        }
    }
    for (header, product, layer) in [
        ("x-silverstripe-cache", "Silverstripe", ProductLayer::Cms),
        (
            "x-bigcommerce-stencil-profiler",
            "BigCommerce",
            ProductLayer::Ecommerce,
        ),
        ("x-bc-store-hash", "BigCommerce", ProductLayer::Ecommerce),
    ] {
        if response
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(header))
        {
            record_product_signal(
                signals,
                product,
                layer,
                format!("header:{header}"),
                format!("{header} response header"),
                ProductSignalKind::StrongExplicit,
                None,
            );
        }
    }
    for (needle, product, source, evidence) in [
        (
            "fornax_anonymousid",
            "BigCommerce",
            "bigcommerce:cookie",
            "BigCommerce Fornax cookie",
        ),
        (
            "shop_session_token",
            "BigCommerce",
            "bigcommerce:session-cookie",
            "BigCommerce shop session cookie",
        ),
        (
            "prestashop-",
            "PrestaShop",
            "prestashop:cookie",
            "PrestaShop cookie name",
        ),
        (
            "ocsessid",
            "OpenCart",
            "opencart:cookie",
            "OpenCart session cookie",
        ),
    ] {
        if cookie_contains(response, needle) {
            record_product_signal(
                signals,
                product,
                ProductLayer::Ecommerce,
                source.to_owned(),
                evidence.to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        }
    }
    if silverstripe_login_response(response, path) {
        record_product_signal(
            signals,
            "Silverstripe",
            ProductLayer::Cms,
            "silverstripe:validated-login".to_owned(),
            format!("Validated Silverstripe login response at {}", response.url),
            ProductSignalKind::Validated,
            None,
        );
    }
    if bigcommerce_api_response(response, path) {
        record_product_signal(
            signals,
            "BigCommerce",
            ProductLayer::Ecommerce,
            "bigcommerce:validated-api".to_owned(),
            format!("Validated BigCommerce Storefront API at {}", response.url),
            ProductSignalKind::Validated,
            None,
        );
    }
    if opencart_login_response(response, path) {
        record_product_signal(
            signals,
            "OpenCart",
            ProductLayer::Ecommerce,
            "opencart:validated-login".to_owned(),
            format!("Validated OpenCart account login page at {}", response.url),
            ProductSignalKind::Validated,
            None,
        );
    }
}

fn record_known_generator_signal(
    generator: &str,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    let lower = generator.to_ascii_lowercase();
    let (needle, product, layer) = if lower.contains("woocommerce") {
        ("woocommerce", "WooCommerce", ProductLayer::Ecommerce)
    } else if lower.contains("wordpress") {
        ("wordpress", "WordPress", ProductLayer::Cms)
    } else if lower.contains("adobe commerce") {
        ("adobe commerce", "Adobe Commerce", ProductLayer::Ecommerce)
    } else if lower.contains("magento") {
        ("magento", "Magento", ProductLayer::Ecommerce)
    } else if lower.contains("shopify") {
        ("shopify", "Shopify", ProductLayer::Ecommerce)
    } else if lower.contains("sulu") {
        ("sulu", "Sulu", ProductLayer::Cms)
    } else if lower.contains("silverstripe") {
        ("silverstripe", "Silverstripe", ProductLayer::Cms)
    } else if lower.contains("bigcommerce") {
        ("bigcommerce", "BigCommerce", ProductLayer::Ecommerce)
    } else if lower.contains("prestashop") {
        ("prestashop", "PrestaShop", ProductLayer::Ecommerce)
    } else if lower.contains("opencart") {
        ("opencart", "OpenCart", ProductLayer::Ecommerce)
    } else {
        return;
    };
    record_product_signal(
        signals,
        product,
        layer,
        format!("{needle}:generator"),
        format!("Generator metadata: {generator}"),
        ProductSignalKind::StrongExplicit,
        extract_version(generator, product),
    );
}

fn record_vendor_header_signals(
    response: &HttpObservation,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    for (name, value) in &response.headers {
        let header = name.to_ascii_lowercase();
        let value = value.to_ascii_lowercase();
        for (needle, product, layer, prefix) in [
            ("sulu", "Sulu", ProductLayer::Cms, "x-sulu-"),
            ("wordpress", "WordPress", ProductLayer::Cms, "x-wordpress-"),
            (
                "woocommerce",
                "WooCommerce",
                ProductLayer::Ecommerce,
                "x-wc-",
            ),
            (
                "prestashop",
                "PrestaShop",
                ProductLayer::Ecommerce,
                "x-prestashop-",
            ),
            (
                "opencart",
                "OpenCart",
                ProductLayer::Ecommerce,
                "x-opencart-",
            ),
        ] {
            let named = header.starts_with(prefix);
            let valued = matches!(
                header.as_str(),
                "x-powered-by" | "x-generator" | "x-platform"
            ) && value.contains(needle);
            if named || valued {
                record_product_signal(
                    signals,
                    product,
                    layer,
                    format!("{needle}:vendor-header"),
                    format!("Vendor-specific {name} response header"),
                    ProductSignalKind::StrongExplicit,
                    valued.then(|| extract_version(&value, needle)).flatten(),
                );
            }
        }
    }
}

fn html_generator(body: &str) -> Option<String> {
    html_generators(body).into_iter().next()
}

fn html_generators(body: &str) -> Vec<String> {
    let lower = body.to_ascii_lowercase();
    let mut position = 0usize;
    let mut generators = Vec::new();
    while let Some(relative) = lower[position..].find("<meta") {
        let start = position + relative;
        let Some(relative_end) = lower[start..].find('>') else {
            break;
        };
        let end = relative_end + start + 1;
        let tag = &body[start..end];
        if html_attribute(tag, "name").is_some_and(|value| value.eq_ignore_ascii_case("generator"))
            && let Some(content) = html_attribute(tag, "content")
        {
            generators.push(content);
        }
        position = end;
    }
    generators
}

fn cookie_contains(response: &HttpObservation, needle: &str) -> bool {
    header_values(response, "set-cookie").any(|value| {
        value
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    })
}

fn response_path_query(response: &HttpObservation) -> String {
    Url::parse(&response.url)
        .ok()
        .map(|url| match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        })
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn response_on_endpoint_port(response: &HttpObservation, endpoint_port: u16) -> bool {
    Url::parse(&response.url)
        .ok()
        .and_then(|url| url.port_or_known_default())
        == Some(endpoint_port)
}

fn successful_json(response: &HttpObservation) -> Option<serde_json::Value> {
    (200..300)
        .contains(&response.status)
        .then(|| serde_json::from_slice(&response.body).ok())
        .flatten()
}

fn wordpress_api_response(response: &HttpObservation, path: &str) -> bool {
    if path.trim_end_matches('/') != "/wp-json" {
        return false;
    }
    successful_json(response).is_some_and(|json| {
        json.get("namespaces").is_some()
            || json.get("routes").is_some()
            || json.to_string().to_ascii_lowercase().contains("wp/v2")
    })
}

fn woocommerce_api_response(response: &HttpObservation, path: &str) -> bool {
    path.starts_with("/wp-json/wc/store/v1")
        && successful_json(response).is_some_and(|json| {
            json.get("routes").is_some()
                || json.get("namespace").is_some()
                || json.to_string().to_ascii_lowercase().contains("wc/store")
        })
}

fn magento_api_response(response: &HttpObservation, path: &str) -> bool {
    path == "/rest/v1/store/storeconfigs"
        && successful_json(response).is_some_and(|json| {
            let text = json.to_string().to_ascii_lowercase();
            text.contains("base_url")
                && (text.contains("website_id") || text.contains("store_name"))
        })
}

fn shopify_cart_response(response: &HttpObservation, path: &str) -> bool {
    path == "/cart.js"
        && successful_json(response).is_some_and(|json| {
            json.get("items").is_some()
                && json.get("item_count").is_some()
                && json.get("token").is_some()
        })
}

fn bigcommerce_api_response(response: &HttpObservation, path: &str) -> bool {
    path == "/api/storefront/store-context"
        && successful_json(response).is_some_and(|json| {
            let text = json.to_string().to_ascii_lowercase();
            text.contains("storehash") || text.contains("store_hash") || text.contains("storeid")
        })
}

fn silverstripe_login_response(response: &HttpObservation, path: &str) -> bool {
    path.trim_end_matches('/') == "/security/login"
        && (200..300).contains(&response.status)
        && login_page_evidence(response).is_some()
        && String::from_utf8_lossy(&response.body)
            .to_ascii_lowercase()
            .contains("silverstripe")
}

fn opencart_login_response(response: &HttpObservation, path: &str) -> bool {
    path.contains("route=account/login")
        && (200..300).contains(&response.status)
        && login_page_evidence(response).is_some()
        && (String::from_utf8_lossy(&response.body)
            .to_ascii_lowercase()
            .contains("opencart")
            || String::from_utf8_lossy(&response.body)
                .to_ascii_lowercase()
                .contains("route=account/forgotten"))
}

fn is_storefront_document(response: &HttpObservation) -> bool {
    if !(200..300).contains(&response.status) || response.body.is_empty() {
        return false;
    }
    let path = response_path_query(response);
    matches!(path.as_str(), "/" | "/products" | "/products/")
        && header_values(response, "content-type")
            .any(|value| value.to_ascii_lowercase().contains("html"))
}

fn collect_generic_commerce_signals(lower: &str, signals: &mut HashMap<&'static str, String>) {
    if lower.contains("schema.org/product")
        || lower.contains("\"@type\":\"product\"")
        || lower.contains("\"@type\": \"product\"")
        || lower.contains("class=\"product-price")
        || lower.contains("class='product-price")
    {
        signals.insert(
            "product",
            "Product structured data or product-price markup".to_owned(),
        );
    }
    if lower.contains("schema.org/offer")
        || lower.contains("\"@type\":\"offer\"")
        || lower.contains("\"pricecurrency\"")
        || lower.contains("itemprop=\"price\"")
    {
        signals.insert("offer", "Offer or price structured data".to_owned());
    }
    if lower.contains("add-to-cart")
        || lower.contains("add_to_cart")
        || lower.contains("href=\"/cart")
        || lower.contains("href='/cart")
        || lower.contains("cart-count")
    {
        signals.insert("cart", "Cart control or cart route markup".to_owned());
    }
    if lower.contains("href=\"/checkout")
        || lower.contains("href='/checkout")
        || lower.contains("checkout-button")
        || lower.contains("begin-checkout")
    {
        signals.insert(
            "checkout",
            "Checkout control or checkout route markup".to_owned(),
        );
    }
    if lower.contains("js.stripe.com")
        || lower.contains("paypal.com/sdk/js")
        || lower.contains("klarna")
        || lower.contains("afterpay")
        || lower.contains("adyen")
    {
        signals.insert("payment", "Third-party payment client script".to_owned());
    }
}

fn record_observed_web_surfaces(endpoint: &mut EndpointScan) {
    let technologies = endpoint
        .products
        .iter()
        .filter(|product| matches!(product.layer, ProductLayer::Cms | ProductLayer::Ecommerce))
        .map(|product| product.name.clone())
        .collect::<HashSet<_>>();
    if technologies.is_empty() {
        return;
    }
    let baselines = endpoint
        .http
        .iter()
        .filter(|response| response.url.contains("/nancy-exposure-not-found-"))
        .cloned()
        .collect::<Vec<_>>();
    let responses = endpoint.http.clone();
    for response in &responses {
        if !response.method.eq_ignore_ascii_case("GET")
            || !response_on_endpoint_port(response, endpoint.port)
            || (!((200..300).contains(&response.status)) && !matches!(response.status, 401 | 403))
        {
            continue;
        }
        if response_is_soft_404(response, &baselines) {
            continue;
        }
        let path = response_path_query(response);
        let mut candidates = Vec::new();
        if wordpress_api_response(response, &path) && technologies.contains("WordPress") {
            candidates.push((
                "WordPress",
                WebSurfaceType::Api,
                Confidence::High,
                "Validated WordPress REST API response".to_owned(),
            ));
        }
        if woocommerce_api_response(response, &path) && technologies.contains("WooCommerce") {
            candidates.push((
                "WooCommerce",
                WebSurfaceType::Api,
                Confidence::High,
                "Validated WooCommerce Store API response".to_owned(),
            ));
        }
        if magento_api_response(response, &path)
            && (technologies.contains("Magento") || technologies.contains("Adobe Commerce"))
        {
            let technology = if technologies.contains("Adobe Commerce") {
                "Adobe Commerce"
            } else {
                "Magento"
            };
            candidates.push((
                technology,
                WebSurfaceType::Api,
                Confidence::High,
                "Validated Magento store configuration API response".to_owned(),
            ));
        }
        if shopify_cart_response(response, &path) && technologies.contains("Shopify") {
            candidates.push((
                "Shopify",
                WebSurfaceType::Cart,
                Confidence::High,
                "Validated Shopify cart API response".to_owned(),
            ));
        }
        if bigcommerce_api_response(response, &path) && technologies.contains("BigCommerce") {
            candidates.push((
                "BigCommerce",
                WebSurfaceType::Api,
                Confidence::High,
                "Validated BigCommerce Storefront API response".to_owned(),
            ));
        }

        for technology in &technologies {
            let classified = classify_platform_surface(technology, &path);
            let Some(surface_type) = classified else {
                continue;
            };
            if candidates.iter().any(|(candidate, kind, _, _)| {
                candidate.eq_ignore_ascii_case(technology) && *kind == surface_type
            }) {
                continue;
            }
            let evidence = match surface_type {
                WebSurfaceType::Login => login_page_evidence(response),
                WebSurfaceType::Admin => admin_page_evidence(response),
                WebSurfaceType::Cart => cart_page_evidence(response),
                WebSurfaceType::Checkout => checkout_page_evidence(response),
                WebSurfaceType::Api => None,
            };
            if let Some(evidence) = evidence {
                candidates.push((
                    technology.as_str(),
                    surface_type,
                    Confidence::Medium,
                    evidence,
                ));
            }
        }
        for (technology, surface_type, confidence, evidence) in candidates {
            add_web_surface(
                endpoint,
                technology,
                response,
                surface_type,
                confidence,
                vec![
                    format!("GET {} returned {}", response.url, response.status),
                    evidence,
                ],
            );
        }
    }
}

fn classify_platform_surface(technology: &str, path: &str) -> Option<WebSurfaceType> {
    let bare_path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    match technology {
        "WordPress" if bare_path == "/wp-login.php" => Some(WebSurfaceType::Login),
        "WordPress" if bare_path == "/wp-admin" => Some(WebSurfaceType::Admin),
        "WooCommerce" if matches!(bare_path, "/cart" | "/basket") => Some(WebSurfaceType::Cart),
        "WooCommerce" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
        "Magento" | "Adobe Commerce" if bare_path == "/customer/account/login" => {
            Some(WebSurfaceType::Login)
        }
        "Magento" | "Adobe Commerce" if bare_path == "/admin" => Some(WebSurfaceType::Admin),
        "Magento" | "Adobe Commerce" if bare_path == "/checkout/cart" => Some(WebSurfaceType::Cart),
        "Magento" | "Adobe Commerce" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
        "Shopify" if bare_path == "/account/login" => Some(WebSurfaceType::Login),
        "Shopify" if bare_path == "/cart" => Some(WebSurfaceType::Cart),
        "Shopify" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
        "Silverstripe" if bare_path.eq_ignore_ascii_case("/security/login") => {
            Some(WebSurfaceType::Login)
        }
        "Silverstripe" if bare_path == "/admin" => Some(WebSurfaceType::Admin),
        "BigCommerce" if bare_path == "/login.php" => Some(WebSurfaceType::Login),
        "BigCommerce" if matches!(bare_path, "/cart" | "/cart.php") => Some(WebSurfaceType::Cart),
        "BigCommerce" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
        "PrestaShop" if bare_path == "/login" => Some(WebSurfaceType::Login),
        "PrestaShop" if bare_path == "/cart" => Some(WebSurfaceType::Cart),
        "PrestaShop" if matches!(bare_path, "/checkout" | "/order") => {
            Some(WebSurfaceType::Checkout)
        }
        "OpenCart" if path.contains("route=account/login") => Some(WebSurfaceType::Login),
        "OpenCart" if path.contains("route=checkout/cart") => Some(WebSurfaceType::Cart),
        "OpenCart" if path.contains("route=checkout/checkout") => Some(WebSurfaceType::Checkout),
        "Generic commerce" if matches!(bare_path, "/cart" | "/basket") => {
            Some(WebSurfaceType::Cart)
        }
        "Generic commerce" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
        _ => None,
    }
}

fn response_is_soft_404(response: &HttpObservation, baselines: &[HttpObservation]) -> bool {
    let Ok(candidate_url) = Url::parse(&response.url) else {
        return false;
    };
    baselines.iter().any(|baseline| {
        let Ok(baseline_url) = Url::parse(&baseline.url) else {
            return false;
        };
        same_origin(&candidate_url, &baseline_url)
            && looks_like_soft_404(
                baseline,
                response,
                baseline_url.path(),
                candidate_url.path(),
            )
    })
}

fn login_page_evidence(response: &HttpObservation) -> Option<String> {
    if matches!(response.status, 401 | 403) {
        return Some("Access-controlled login route".to_owned());
    }
    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    (lower.contains("<form")
        && (lower.contains("type=\"password\"") || lower.contains("type='password'"))
        && (lower.contains("login") || lower.contains("log in") || lower.contains("sign in")))
    .then(|| "Login form with a password control".to_owned())
}

fn admin_page_evidence(response: &HttpObservation) -> Option<String> {
    if matches!(response.status, 401 | 403) {
        return Some("Access-controlled administration route".to_owned());
    }
    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    ((lower.contains("admin") || lower.contains("dashboard") || lower.contains("control panel"))
        && (lower.contains("<form") || lower.contains("navigation") || lower.contains("menu")))
    .then(|| "Administration page markers".to_owned())
}

fn cart_page_evidence(response: &HttpObservation) -> Option<String> {
    if matches!(response.status, 401 | 403) {
        return Some("Access-controlled cart route".to_owned());
    }
    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    (lower.contains("cart")
        && [
            "quantity",
            "subtotal",
            "checkout",
            "remove",
            "item_count",
            "line-item",
        ]
        .iter()
        .any(|marker| lower.contains(marker)))
    .then(|| "Cart page contains item-management or checkout markers".to_owned())
}

fn checkout_page_evidence(response: &HttpObservation) -> Option<String> {
    if matches!(response.status, 401 | 403) {
        return Some("Access-controlled checkout route".to_owned());
    }
    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    (lower.contains("checkout")
        && [
            "payment",
            "billing",
            "shipping",
            "place order",
            "order summary",
        ]
        .iter()
        .any(|marker| lower.contains(marker)))
    .then(|| "Checkout page contains order or payment markers".to_owned())
}

fn add_web_surface(
    endpoint: &mut EndpointScan,
    technology: &str,
    response: &HttpObservation,
    surface_type: WebSurfaceType,
    confidence: Confidence,
    evidence: Vec<String>,
) {
    if let Some(existing) = endpoint.observed_web_surfaces.iter_mut().find(|surface| {
        surface.technology.eq_ignore_ascii_case(technology)
            && surface.url == response.url
            && surface.surface_type == surface_type
    }) {
        existing.confidence = existing.confidence.max(confidence);
        existing.evidence.extend(evidence);
        existing.evidence.sort();
        existing.evidence.dedup();
        return;
    }
    endpoint.observed_web_surfaces.push(ObservedWebSurface {
        technology: technology.to_owned(),
        url: response.url.clone(),
        status: response.status,
        surface_type,
        confidence,
        evidence,
    });
}

fn record_product_signal(
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
    name: &'static str,
    layer: ProductLayer,
    source: String,
    evidence: String,
    kind: ProductSignalKind,
    version: Option<String>,
) {
    signals
        .entry((name, layer))
        .or_default()
        .push(ProductSignal {
            source,
            evidence,
            kind,
            version,
        });
}

fn extract_version(value: &str, product: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let index = lower.find(&product.to_ascii_lowercase())? + product.len();
    let remainder = value[index..].trim_start_matches(['/', ' ', '-', '_']);
    let version = remainder
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
        .collect::<String>();
    if version.chars().any(|character| character.is_ascii_digit()) {
        Some(version)
    } else {
        None
    }
}
