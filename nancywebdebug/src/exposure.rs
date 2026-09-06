use crate::auth::{
    self, AuthStore, LoadedClientCertificate, SharedAuthStore, resolve_client_certificate,
};
use crate::diagnostics::{
    CertificateTrace, ClientAuthObservation, ClientAuthStatus, ConnectionOutcome,
    DiagnosticRequest, DiagnosticTrace, DnsTrace, TlsTrace, normalize_url_input,
};
use crate::network::{ConnectionRateLimiter, non_public_reason};
use crate::request::{
    CertificateCapture, TcpCandidate, connect_tcp_endpoint, make_exposure_tls_config, resolve_host,
    run_diagnostic_session_for_exposure, tls_trace_from_capture, tls_trace_from_stream,
};
use crate::web_server::{FingerprintConfidence, WebProductRole, detect_web_servers};
use base64::Engine as _;
use cookie::{Cookie, SameSite};
use futures_util::stream::{FuturesUnordered, StreamExt};
use rustls::pki_types::ServerName;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;
use url::Url;

#[path = "active_web.rs"]
mod active_web;
#[path = "artifact_analysis.rs"]
mod artifact_analysis;
#[path = "asset_dns.rs"]
mod asset_dns;
#[path = "finding_assessment.rs"]
pub(crate) mod finding_assessment;
#[path = "browser_policy.rs"]
mod browser_policy;
#[path = "crawl.rs"]
mod crawl;
#[path = "endpoint_health.rs"]
pub(crate) mod endpoint_health;
#[path = "fingerprints.rs"]
pub(crate) mod fingerprints;
#[path = "javascript.rs"]
mod javascript;
#[path = "service_access.rs"]
mod service_access;
#[path = "stream_inventory.rs"]
mod stream_inventory;
#[path = "technology.rs"]
mod technology;
#[path = "technology_evidence.rs"]
pub(crate) mod technology_evidence;
#[path = "udp_scan.rs"]
mod udp_scan;

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

pub const CURATED_UDP_PORTS: &[u16] = &[
    53, 69, 123, 137, 161, 443, 500, 784, 1884, 1900, 3478, 3702, 4500, 5004, 5005, 5060, 5353,
    5683, 5684, 9000,
];

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
    (554, "RTSP", "Media signalling service"),
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
    (1935, "RTMP", "Media streaming handshake service"),
    (2049, "NFS", "Network file system service"),
    (2082, "cPanel HTTP", "Hosting panel listener association; requires response evidence"),
    (2083, "cPanel HTTPS", "TLS-backed hosting panel listener association"),
    (2086, "WHM HTTP", "Server management panel listener association; requires response evidence"),
    (2087, "WHM HTTPS", "TLS-backed server management panel listener association"),
    (2181, "ZooKeeper", "Distributed coordination service"),
    (
        2222,
        "DirectAdmin / SSH alternate",
        "Shared HTTP, HTTPS or alternate SSH listener; requires protocol evidence"
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
    (8080, "HTTP alternate", "Alternate HTTP/HTTPS web service, including ISPConfig"),
    (
        8081,
        "HTTP alternate",
        "Alternate web or management service"
    ),
    (8083, "HestiaCP", "HTTP/HTTPS hosting panel listener association"),
    (8086, "InfluxDB", "InfluxDB HTTP API"),
    (8088, "HTTP management", "Common management web service"),
    (
        8089,
        "Splunk management",
        "Common TLS-backed Splunk management API"
    ),
    (
        8090,
        "CyberPanel",
        "HTTP/HTTPS hosting panel listener association"
    ),
    (
        8291,
        "MikroTik WinBox",
        "Network device management service association"
    ),
    (
        8443,
        "HTTPS alternate",
        "Alternate HTTP/HTTPS web or management service, including Plesk"
    ),
    (8500, "Consul", "Consul HTTP API"),
    (8554, "RTSP alternate", "Media signalling service"),
    (8880, "Plesk HTTP", "HTTP/HTTPS hosting panel listener association"),
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
        "HTTP/HTTPS monitoring or management service, including Cockpit"
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
        "Webmin / Virtualmin",
        "HTTP/HTTPS administration panel listener association"
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
    80, 2082, 2086, 2222, 2375, 2379, 2380, 3000, 5000, 5601, 5984, 5985, 7001, 8000, 8008, 8080,
    8081, 8083, 8086, 8088, 8090, 8443, 8500, 8880, 8888, 9000, 9001, 9090, 9200, 10000, 10255, 15672,
];
const HTTPS_PORTS: &[u16] = &[
    443, 2083, 2087, 2222, 2376, 5986, 6443, 8080, 8083, 8089, 8090, 8443, 8880, 9090, 10000, 10250,
];
const TLS_PORTS: &[u16] = &[
    443, 465, 636, 993, 995, 2083, 2087, 2222, 2376, 3269, 5671, 5986, 6443, 8080, 8083, 8089, 8090,
    8443, 8880, 8883, 9090, 10000, 10250,
];
const NEGOTIATION_ONLY_TCP_PORTS: &[u16] = &[
    111, 139, 389, 445, 554, 636, 1883, 1935, 2049, 3268, 3269, 8554, 8883, 27017,
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
        for header in {
            let (response, name): (&crate::HttpObservation, &str) = (response, "set-cookie");
            response
                .headers
                .iter()
                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        } {
            if let Some(cookie) = parse_set_cookie(url, header) {
                ({
                    let (inlined_self, cookie): (&mut EndpointCookieJar, ParsedSetCookie) =
                        (&mut *self, cookie);
                    'inlined_store: {
                        inlined_self.remove_expired();
                        if cookie.secure && cookie.source_scheme != "https" {
                            break 'inlined_store;
                        }
                        if cookie.source_scheme != "https"
                            && inlined_self.cookies.iter().any(|existing| {
                                existing.secure
                                    && existing.key.name == cookie.key.name
                                    && existing.key.domain == cookie.key.domain
                                    && ({
                                        let (request_path, cookie_path): (&str, &str) =
                                            (&cookie.key.path, &existing.key.path);
                                        {
                                            request_path == cookie_path
                                                || request_path
                                                    .strip_prefix(cookie_path)
                                                    .is_some_and(|suffix| {
                                                        cookie_path.ends_with('/')
                                                            || suffix.starts_with('/')
                                                    })
                                        }
                                    })
                            })
                        {
                            break 'inlined_store;
                        }
                        inlined_self
                            .cookies
                            .retain(|existing| existing.key != cookie.key);
                        if !cookie.deletion {
                            inlined_self.cookies.push(StoredCookie {
                                key: cookie.key,
                                value: cookie.value,
                                host_only: cookie.host_only,
                                secure: cookie.secure,
                                expires_at: cookie.expires_at,
                            });
                        }
                    }
                });
            }
        }
    }

    fn cookie_header(&mut self, url: &Url) -> Option<String> {
        let cookies = {
            let (inlined_self, url): (&'_ mut EndpointCookieJar, &Url) = (&mut *self, url);
            let inlined_result: Vec<&'_ StoredCookie> = {
                'inlined_eligible: {
                    inlined_self.remove_expired();
                    let Some(host) = url.host_str().map(|host| host.to_ascii_lowercase()) else {
                        break 'inlined_eligible Vec::new();
                    };
                    let mut cookies = inlined_self
                        .cookies
                        .iter()
                        .filter(|cookie| {
                            (!cookie.secure || url.scheme() == "https")
                                && if cookie.host_only {
                                    host == cookie.key.domain
                                } else {
                                    {
                                        let (host, domain): (&str, &str) =
                                            (&host, &cookie.key.domain);
                                        {
                                            host.eq_ignore_ascii_case(domain)
                                                || (host.parse::<IpAddr>().is_err()
                                                    && host.strip_suffix(domain).is_some_and(
                                                        |prefix| prefix.ends_with('.'),
                                                    ))
                                        }
                                    }
                                }
                                && ({
                                    let (request_path, cookie_path): (&str, &str) =
                                        (url.path(), &cookie.key.path);
                                    {
                                        request_path == cookie_path
                                            || request_path.strip_prefix(cookie_path).is_some_and(
                                                |suffix| {
                                                    cookie_path.ends_with('/')
                                                        || suffix.starts_with('/')
                                                },
                                            )
                                    }
                                })
                        })
                        .collect::<Vec<_>>();
                    cookies.sort_by_key(|cookie| std::cmp::Reverse(cookie.key.path.len()));
                    cookies
                }
            };
            inlined_result
        };
        let mut header = String::new();
        for (index, cookie) in cookies.iter().enumerate() {
            if index > 0 {
                header.push_str("; ");
            }
            use std::fmt::Write as _;
            let _ = write!(header, "{}={}", cookie.key.name, cookie.value);
        }
        (!header.is_empty()).then_some(header)
    }

    fn remove_expired(&mut self) {
        let now = {
            let inlined_result: i64 = {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .min(i64::MAX as u64) as i64
            };
            inlined_result
        };
        self.cookies
            .retain(|cookie| cookie.expires_at.is_none_or(|expires| expires > now));
    }
}

fn parse_set_cookie(url: &Url, header: &str) -> Option<ParsedSetCookie> {
    let parsed = Cookie::parse(header).ok()?;
    let name = parsed.name().to_owned();
    let value = parsed.value().to_owned();
    if !{
        let (name,): (&str,) = (&name,);

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
    } || !({
        let (value,): (&str,) = (&value,);
        {
            value.bytes().all(
                |byte| matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e),
            )
        }
    }) {
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
            if domain.is_empty()
                || !({
                    let (host, domain): (&str, &str) = (&host, &domain);
                    {
                        host.eq_ignore_ascii_case(domain)
                            || (host.parse::<IpAddr>().is_err()
                                && host
                                    .strip_suffix(domain)
                                    .is_some_and(|prefix| prefix.ends_with('.')))
                    }
                })
            {
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
        .unwrap_or_else(|| {
            let (request_path,): (&str,) = (url.path(),);
            {
                'inlined_default_cookie_path: {
                    if !request_path.starts_with('/') || request_path.matches('/').count() <= 1 {
                        break 'inlined_default_cookie_path "/".to_owned();
                    }
                    request_path
                        .rfind('/')
                        .map(|index| request_path[..index].to_owned())
                        .filter(|path| !path.is_empty())
                        .unwrap_or_else(|| "/".to_owned())
                }
            }
        });
    let now = {
        let inlined_result: i64 = {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .min(i64::MAX as u64) as i64
        };
        inlined_result
    };
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
        source_scheme: url.scheme().to_owned(),
    })
}

#[path = "scan_models.rs"]
mod scan_models;
pub use scan_models::*;

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
    endpoint_health::scope({
let (request, auth_store, cancel, progress,): (ExposureScanRequest, SharedAuthStore, CancellationToken, Option < Sender < ExposureScanProgress > >,) = (request, auth_store, cancel, progress,);
async move {

    fingerprints::ensure_initialized().await;
    let total_started = Instant::now();
    let parsed = match request
        .validate()
        .and_then(|_| parse_target(&request.diagnostic_request.url))
    {
        Ok(parsed) => parsed,
        Err(error) => {
            let mut report = {
let (request, error, started,): (ExposureScanRequest, String, Instant,) = (request, error, total_started,);
{

    ExposureScanReport {
        request,
        hostname: String::new(),
        supplied_port: None,
        resolved_addresses: Vec::new(),
        ignored_addresses: Vec::new(),
        warnings: Vec::new(),
        endpoint_health: Vec::new(),
        endpoints: Vec::new(),
        udp_endpoints: Vec::new(),
        service_access: Vec::new(),
        discovered_assets: Vec::new(),
        discovery_coverage: crate::DiscoveryCoverage::default(),
        dns_observations: Vec::new(),
        stream_observations: Vec::new(),
        findings: Vec::new(),
        security_checks: Vec::new(),
        crawl_observed_web_surfaces: Vec::new(),
        crawl_origins: Vec::new(),
        crawled_resources: Vec::new(),
        crawl_forms: Vec::new(),
        crawl_contacts: Vec::new(),
        crawl_external_indicators: Vec::new(),
        crawl_skipped_urls: Vec::new(),
        timings: ExposureScanTimings {
            total_ms: ({

let inlined_result: f64 = {

    started.elapsed().as_secs_f64() * 1000.0

};
inlined_result
}),
            ..Default::default()
        },
        status: ExposureScanStatus::Failed,
        error: Some(error),
    }

}

};
            finalize_report(&mut report, total_started, &cancel, &progress).await;
            ({
let (progress, event,): (& Option < Sender < ExposureScanProgress > >, _,) = (&progress, || {
                ExposureScanProgress::Completed(report.clone())
            },);

    if let Some(progress) = progress {
        let _ = progress.send(event());
    }

});
            return report;
        }
    };
    if !matches!( request.web_probe_level, crate::WebProbeLevel::Active | crate::WebProbeLevel::StateChanging) {
        send_phase_progress(
            &progress,
            ExposureScanPhase::ActiveWebAssessment,
            ExposureScanPhaseState::Skipped,
            1.0,
            "Passive tier selected",
        );
    }
    if !request.security_operations {
        for phase in [
            ExposureScanPhase::Crawl,
            ExposureScanPhase::JavaScriptAnalysis,
            ExposureScanPhase::TechnologyAnalysis,
        ] {
            send_phase_progress(
                &progress,
                phase,
                ExposureScanPhaseState::Skipped,
                1.0,
                "Skipped",
            );
        }
    }
    for (enabled, phase) in [
        (request.udp_scanning, ExposureScanPhase::UdpScanning),
        (
            request.service_access_checks,
            ExposureScanPhase::ServiceAccess,
        ),
        (request.asset_discovery, ExposureScanPhase::AssetDiscovery),
        (request.dns_assessment, ExposureScanPhase::DnsAssessment),
    ] {
        if !enabled {
            send_phase_progress(
                &progress,
                phase,
                ExposureScanPhaseState::Skipped,
                1.0,
                "Skipped",
            );
        }
    }
    ({
let (progress, event,): (& Option < Sender < ExposureScanProgress > >, _,) = (&progress, || ExposureScanProgress::Resolving {
        target: parsed.hostname.clone(),
    },);

    if let Some(progress) = progress {
        let _ = progress.send(event());
    }

});
    let mut report = ExposureScanReport {
        request,
        hostname: parsed.hostname,
        supplied_port: parsed.supplied_port,
        resolved_addresses: Vec::new(),
        ignored_addresses: Vec::new(),
        warnings: Vec::new(),
        endpoint_health: Vec::new(),
        endpoints: Vec::new(),
        udp_endpoints: Vec::new(),
        service_access: Vec::new(),
        discovered_assets: Vec::new(),
        discovery_coverage: crate::DiscoveryCoverage::default(),
        dns_observations: Vec::new(),
        stream_observations: Vec::new(),
        findings: Vec::new(),
        security_checks: Vec::new(),
        crawl_observed_web_surfaces: Vec::new(),
        crawl_origins: Vec::new(),
        crawled_resources: Vec::new(),
        crawl_forms: Vec::new(),
        crawl_contacts: Vec::new(),
        crawl_external_indicators: Vec::new(),
        crawl_skipped_urls: Vec::new(),
        timings: ExposureScanTimings::default(),
        status: ExposureScanStatus::Running,
        error: None,
    };
    let client_certificate = match report
        .request
        .diagnostic_request
        .client_certificate
        .as_ref()
        .map(|profile| profile.profile_id)
    {
        Some(profile_id) => match resolve_client_certificate(
            auth_store.clone(),
            profile_id,
            &report.request.diagnostic_request.url,
        ) {
            Ok(certificate) => Some(certificate),
            Err(error) => {
                report.status = ExposureScanStatus::Failed;
                report.error = Some(error);
                finalize_report(&mut report, total_started, &cancel, &progress).await;
                ({
let (progress, event,): (& Option < Sender < ExposureScanProgress > >, _,) = (&progress, || {
                    ExposureScanProgress::Completed(report.clone())
                },);

    if let Some(progress) = progress {
        let _ = progress.send(event());
    }

});
                return report;
            }
        },
        None => None,
    };
    let crawl_auth = match report
        .request
        .diagnostic_request
        .auth
        .as_ref()
        .map(|profile| profile.profile_id)
    {
        Some(profile_id) => match auth::resolve(
            auth_store.clone(),
            profile_id,
            &report.request.diagnostic_request.url,
            report.request.diagnostic_request.timeouts.authentication,
            cancel.clone(),
        )
        .await
        {
            Ok(auth) => Some(auth),
            Err(error) => {
                report
                    .warnings
                    .push(format!("Crawl authentication unavailable: {error}"));
                None
            }
        },
        None => None,
    };
    let request = &report.request;
    let resolution_started = Instant::now();
    let mut dns = DnsTrace::default();
    let resolution = tokio::select! {
        _ = cancel.cancelled() => Err("Scan cancelled during name resolution".to_owned()),
        result = resolve_host(&report.hostname, &mut dns) => result,
    };
    report.timings.resolution_ms = {
let (started,): (Instant,) = (resolution_started,);
let inlined_result: f64 = {

    started.elapsed().as_secs_f64() * 1000.0

};
inlined_result
};
    let address_collection_incomplete = dns.lookup_outcomes.iter().any(|outcome|
        matches!(outcome.record_type.as_str(), "A" | "AAAA") && !outcome.status.conclusive());
    let incomplete_dns = dns.lookup_outcomes.iter().filter(|outcome| !outcome.status.conclusive())
        .map(|outcome| format!("{}: {}{}", outcome.record_type, outcome.status,
            outcome.failure.as_ref().map(|error| format!(" ({error})")).unwrap_or_default()))
        .collect::<Vec<_>>();
    if !incomplete_dns.is_empty() {
        report.warnings.push(format!("Initial DNS coverage incomplete: {}", incomplete_dns.join("; ")));
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
    let limiter = Arc::new(ConnectionRateLimiter::new(
        request.connection_starts_per_second,
    ));
    if request.dns_assessment && !cancel.is_cancelled() {
        let (observations, warnings) = asset_dns::assess_dns(
            &report.hostname, request, &cancel, limiter.as_ref(), &progress,
        ).await;
        report.dns_observations = observations;
        report.warnings.extend(warnings);
    }
    if request.asset_discovery && !cancel.is_cancelled() {
        let (assets, warnings, coverage) = asset_dns::discover_assets(
            &report.hostname,
            request,
            &cancel,
            limiter.clone(),
            &progress,
        )
        .await;
        report.discovered_assets = assets;
        report.discovery_coverage = coverage;
        report.warnings.extend(warnings);
    }
    if cancel.is_cancelled() {
        report.status = ExposureScanStatus::Cancelled;
        report.error = Some("Scan cancelled".to_owned());
        finalize_report(&mut report, total_started, &cancel, &progress).await;
        ({
let (progress, event,): (& Option < Sender < ExposureScanProgress > >, _,) = (&progress, || {
            ExposureScanProgress::Completed(report.clone())
        },);

    if let Some(progress) = progress {
        let _ = progress.send(event());
    }

});
        return report;
    }
    if let Err(error) = resolution {
        report.status = ExposureScanStatus::Failed;
        report.error = Some(error);
        finalize_report(&mut report, total_started, &cancel, &progress).await;
        ({
let (progress, event,): (& Option < Sender < ExposureScanProgress > >, _,) = (&progress, || {
            ExposureScanProgress::Completed(report.clone())
        },);

    if let Some(progress) = progress {
        let _ = progress.send(event());
    }

});
        return report;
    }
    if report.resolved_addresses.is_empty() {
        report.status = ExposureScanStatus::Failed;
        report.error = Some(if address_collection_incomplete {
            "Target address collection was incomplete; no usable public destination was obtained".to_owned()
        } else {
            "Target has no publicly routable A or AAAA address".to_owned()
        });
        finalize_report(&mut report, total_started, &cancel, &progress).await;
        ({
let (progress, event,): (& Option < Sender < ExposureScanProgress > >, _,) = (&progress, || {
            ExposureScanProgress::Completed(report.clone())
        },);

    if let Some(progress) = progress {
        let _ = progress.send(event());
    }

});
        return report;
    }
    for ip in &report.resolved_addresses {
        endpoint_health::register(*ip);
    }
    let mut ports = request
        .ports
        .ports(TransportProtocol::Tcp)
        .unwrap_or_default();
    if let Some(port) = parsed.supplied_port
        && !ports.contains(&port)
    {
        ports.push(port);
        ports.sort_unstable();
    }
    let total_endpoints = report.resolved_addresses.len().saturating_mul(ports.len());
    ({
let (progress, event,): (& Option < Sender < ExposureScanProgress > >, _,) = (&progress, || ExposureScanProgress::Resolved {
        public_addresses: report.resolved_addresses.clone(),
        total_endpoints,
    },);

    if let Some(progress) = progress {
        let _ = progress.send(event());
    }

});
    let scan_started = Instant::now();
    send_phase_progress(
        &progress,
        ExposureScanPhase::PortScanning,
        ExposureScanPhaseState::Running,
        0.0,
        format!("0 / {total_endpoints} endpoints"),
    );
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
            let scan = ScanContext {
                hostname: &report.hostname,
                request,
                cancel: &cancel,
                limiter: &limiter,
                client_certificate: client_certificate.as_ref(),
            };
            pending.push(scan_endpoint(ProbeContext { ip, port, scan }));
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
            ({
let (progress, event,): (& Option < Sender < ExposureScanProgress > >, _,) = (&progress, || ExposureScanProgress::EndpointCompleted {
                completed,
                total: total_endpoints,
                endpoint: endpoint.clone(),
            },);

    if let Some(progress) = progress {
        let _ = progress.send(event());
    }

});
            send_phase_progress(
                &progress,
                ExposureScanPhase::PortScanning,
                ExposureScanPhaseState::Running,
                completed as f32 / total_endpoints.max(1) as f32,
                format!("{completed} / {total_endpoints} endpoints"),
            );
            report.endpoints.push(endpoint);
        }
        if cancel.is_cancelled() {
            scheduling_done = true;
        }
    }
    drop(pending);
    report.endpoints.sort_by(|left, right| {
        left.ip
            .to_string()
            .cmp(&right.ip.to_string())
            .then(left.port.cmp(&right.port))
    });
    if !cancel.is_cancelled() {
        send_phase_progress(
            &progress,
            ExposureScanPhase::PortScanning,
            ExposureScanPhaseState::Complete,
            1.0,
            format!("{completed} / {total_endpoints} endpoints"),
        );
    }
    if request.udp_scanning && !cancel.is_cancelled() {
        let (udp_endpoints, findings) = udp_scan::run(
            &report.resolved_addresses,
            &report.hostname,
            request,
            &cancel,
            limiter.clone(),
            &progress,
        )
        .await;
        report.udp_endpoints = udp_endpoints;
        report.findings.extend(findings);
    }
    if request.service_access_checks && !cancel.is_cancelled() {
        let (access, findings) = service_access::run(
            &report.endpoints,
            &report.hostname,
            request,
            &cancel,
            limiter.clone(),
            &progress,
        )
        .await;
        report.service_access = access;
        report.findings.extend(findings);
    }
    if !cancel.is_cancelled() {
        ({
let (endpoints, request, hostname, auth_store, cancel, limiter, progress,): (& mut [EndpointScan], & ExposureScanRequest, & str, SharedAuthStore, & CancellationToken, Arc < ConnectionRateLimiter >, & Option < Sender < ExposureScanProgress > >,) = (&mut report.endpoints, request, &report.hostname, auth_store, &cancel, limiter.clone(), &progress,);
async move {

    let jobs = endpoints
        .iter()
        .enumerate()
        .filter_map(|(index, endpoint)| {
            if endpoint_health::stopped(endpoint.ip, endpoint.port) {
                return None;
            }
            ({
let (endpoint,): (& EndpointScan,) = (endpoint,);
{

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

}).map(|scheme| (index, endpoint.ip, endpoint.port, scheme))
        })
        .collect::<Vec<_>>();
    let total = jobs.len();
    send_phase_progress(
        progress,
        ExposureScanPhase::EndpointDiagnostics,
        ExposureScanPhaseState::Running,
        0.0,
        format!("0 / {total} diagnostics"),
    );
    let mut pending = FuturesUnordered::new();
    let mut next = 0usize;
    let mut completed = 0usize;
    loop {
        while next < jobs.len() && pending.len() < request.concurrency && !cancel.is_cancelled() {
            let (index, ip, port, scheme) = jobs[next];
            next += 1;
            send_phase_progress(
                progress,
                ExposureScanPhase::EndpointDiagnostics,
                ExposureScanPhaseState::Running,
                completed as f32 / total.max(1) as f32,
                format!("Diagnosing {scheme}://{hostname}:{port} ({completed}/{total})"),
            );
            let diagnostic_request =
                {
let (configured, hostname, scheme, port,): (& DiagnosticRequest, & str, & str, u16,) = (&request.diagnostic_request, hostname, scheme, port,);
let inlined_result: DiagnosticRequest = {

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

};
inlined_result
};
            let auth_store = auth_store.clone();
            let cancel = cancel.clone();
            let limiter = limiter.clone();
            pending.push(async move {
                let Ok(attempt) = endpoint_health::begin(ip, port, &cancel).await else {
                    return (index, ip, port, Vec::new());
                };
                let monitor = matches!(diagnostic_request.method.as_str(), "GET" | "HEAD");
                let traces = endpoint_health::inside(run_diagnostic_session_for_exposure(
                    1,
                    diagnostic_request,
                    auth_store,
                    cancel.clone(),
                    ip,
                    limiter,
                ))
                .await;
                if let Some(attempt) = attempt {
                    let result = if monitor {
                        traces
                            .last()
                            .map(|trace| {
                                endpoint_health::outcome(
                                    trace.http.status,
                                    trace.error.as_ref().map(|error| error.message.as_str()),
                                )
                            })
                            .unwrap_or(endpoint_health::Outcome::Ignored)
                    } else {
                        endpoint_health::Outcome::Ignored
                    };
                    attempt.finish_http(result, None, &cancel).await;
                }
                (index, ip, port, traces)
            });
        }
        let Some((index, ip, port, traces)) = pending.next().await else {
            break;
        };
        endpoints[index].diagnostics = traces;
        completed += 1;
        send_phase_progress(
            progress,
            ExposureScanPhase::EndpointDiagnostics,
            ExposureScanPhaseState::Running,
            completed as f32 / total.max(1) as f32,
            format!("{completed} / {total} diagnostics — {ip}:{port}"),
        );
        if cancel.is_cancelled() {
            break;
        }
    }
    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::EndpointDiagnostics,
            ExposureScanPhaseState::Complete,
            1.0,
            format!("{completed} / {total} diagnostics"),
        );
    }

}
})
        .await;
    }
    if request.security_operations && !cancel.is_cancelled() {
        let mut crawl_request = request.clone();
        crawl_request.crawl_max_urls = crawl_request.crawl_max_urls.saturating_sub(
            exposure_probe::security_operations_exposure_path_count(crawl_request.crawl_max_urls),
        );
        let crawl = crawl::run(
            &crawl_request,
            &report.hostname,
            parsed.seed_url.as_ref(),
            &report.endpoints,
            &cancel,
            &progress,
            crawl_auth.as_ref(),
            client_certificate.as_ref(),
        )
        .await;
        exposure_probe::audit_advanced_browser_and_cors(
            &mut report.endpoints,
            &crawl.resources,
            &crawl.external_indicators,
            &report.hostname,
            request,
            &cancel,
            limiter.as_ref(),
            client_certificate.as_ref(),
        )
        .await;
        if matches!( request.web_probe_level, crate::WebProbeLevel::Active | crate::WebProbeLevel::StateChanging) && !cancel.is_cancelled() {
            active_web::run(
                &mut report.endpoints,
                &crawl.resources,
                &crawl.forms,
                ScanContext {
                    hostname: &report.hostname,
                    request,
                    cancel: &cancel,
                    limiter: limiter.as_ref(),
                    client_certificate: client_certificate.as_ref(),
                },
                &progress,
            )
            .await;
        }
        if request.service_access_checks && !cancel.is_cancelled() {
            let access = stream_inventory::websocket_checks(
                &crawl,
                &report.hostname,
                request,
                &cancel,
                limiter.as_ref(),
                crawl_auth.as_ref(),
                client_certificate.as_ref(),
            )
            .await;
            report
                .findings
                .extend(access.iter().filter_map(service_access::access_finding));
            report.service_access.extend(access);
        }
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
        let mut captured_stream_scripts = Vec::new();
        if !cancel.is_cancelled() {
            let javascript = javascript::analyze(
                &mut report.endpoints,
                request,
                &cancel,
                limiter.as_ref(),
                &mut enrichment,
                &progress,
                crawl_auth.as_ref(),
                &report.hostname,
                client_certificate.as_ref(),
            )
            .await;
            report.warnings.extend(javascript.warnings);
            if !cancel.is_cancelled() {
                report.warnings.extend(fingerprints::detect_async(
                    &mut report.endpoints,
                    &crawl.technology_resources,
                    &javascript.captured_responses,
                    &cancel,
                    &progress,
                ).await);
            }
            captured_stream_scripts = javascript.captured_responses;
            if !cancel.is_cancelled() {
                let technology = technology::analyze(
                    &mut report.endpoints,
                    &crawl.technology_resources,
                    request,
                    &cancel,
                    limiter.as_ref(),
                    &mut enrichment,
                    &progress,
                )
                .await;
                report.warnings.extend(technology.warnings);
                report.findings.extend(technology.findings);
            }
        }
        report.stream_observations =
            stream_inventory::collect(&report.endpoints, &crawl, &captured_stream_scripts);
        stream_inventory::probe_candidates(
            &mut report.stream_observations,
            &report.hostname,
            &report.resolved_addresses,
            request,
            &cancel,
            limiter.as_ref(),
            crawl_auth.as_ref(),
            client_certificate.as_ref(),
        )
        .await;
        stream_inventory::include_websocket_results(
            &mut report.stream_observations,
            &report.service_access,
        );
        report.findings.extend(crawl.findings);
        report.crawl_observed_web_surfaces = crawl.observed_web_surfaces;
        report.crawl_origins = crawl.origins;
        report.crawled_resources = crawl.resources;
        report.crawl_forms = crawl.forms;
        report.crawl_contacts = crawl.contacts;
        report.crawl_external_indicators = crawl.external_indicators;
        report.crawl_skipped_urls = crawl.skipped_urls;
    } else if !cancel.is_cancelled() {
        if matches!( request.web_probe_level, crate::WebProbeLevel::Active | crate::WebProbeLevel::StateChanging) {
            active_web::run(
                &mut report.endpoints,
                &[],
                &[],
                ScanContext {
                    hostname: &report.hostname,
                    request,
                    cancel: &cancel,
                    limiter: limiter.as_ref(),
                    client_certificate: client_certificate.as_ref(),
                },
                &progress,
            )
            .await;
        }
        report.warnings.extend(fingerprints::detect_async(
            &mut report.endpoints,
            &[],
            &[],
            &cancel,
            &progress,
        ).await);
    }
    report.timings.scan_ms = {
let (started,): (Instant,) = (scan_started,);
let inlined_result: f64 = {

    started.elapsed().as_secs_f64() * 1000.0

};
inlined_result
};
    report.status = if cancel.is_cancelled() {
        ExposureScanStatus::Cancelled
    } else {
        ExposureScanStatus::Completed
    };
    if cancel.is_cancelled() {
        report.error = Some("Scan cancelled".to_owned());
    }
    finalize_report(&mut report, total_started, &cancel, &progress).await;
    ({
let (progress, event,): (& Option < Sender < ExposureScanProgress > >, _,) = (&progress, || {
        ExposureScanProgress::Completed(report.clone())
    },);

    if let Some(progress) = progress {
        let _ = progress.send(event());
    }

});
    report

}
})
    .await
}

fn public_stream_finding(
    ip: IpAddr,
    port: u16,
    transport: TransportProtocol,
    protocol: &str,
    method: &str,
    mut evidence: Vec<String>,
) -> ExposureFinding {
    evidence.insert(0, format!("Handshake method: {method}"));
    ExposureFinding {
        details: Vec::new(),
        title: format!("Public {protocol} endpoint confirmed"),
        description: format!(
            "A protocol-valid {protocol} response confirmed a publicly reachable protocol endpoint. The bounded check did not access media, credentials, stream keys, or application content."
        ),
        ip,
        port,
        transport,
        evidence,
        component_kind: None,
    }
}

#[path = "security_analysis.rs"]
mod security_analysis;
use security_analysis::{add_security_summary_finding, build_security_summary};

pub(super) fn send_phase_progress(
    progress: &Option<Sender<ExposureScanProgress>>,
    phase: ExposureScanPhase,
    state: ExposureScanPhaseState,
    fraction: f32,
    text: impl Into<String>,
) {
    let fraction = if fraction.is_finite() {
        fraction.clamp(0.0, 1.0)
    } else {
        0.0
    };
    ({
        let (progress, event): (&Option<Sender<ExposureScanProgress>>, _) =
            (progress, || ExposureScanProgress::PhaseProgress {
                phase,
                state,
                fraction,
                text: text.into(),
            });

        if let Some(progress) = progress {
            let _ = progress.send(event());
        }
    });
}

#[path = "exposure_probe.rs"]
mod exposure_probe;
pub(crate) use exposure_probe::add_product;
use exposure_probe::{
    ProbeContext, ScanContext, active_http_request, active_raw_http_exchange, html_attribute,
    looks_like_soft_404, same_origin, scan_endpoint, single_http_request, url_path,
    websocket_upgrade_exchange,
};

#[path = "product_analysis.rs"]
mod product_analysis;
use product_analysis::{
    apply_product_rules, reconcile_web_server_products, record_observed_web_surfaces,
};

impl EndpointCookieJar {
    fn eligible<'a>(&'a mut self, url: &Url) -> Vec<&'a StoredCookie> {
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
                        {
                            let (host, domain): (&str, &str) = (&host, &cookie.key.domain);
                            {
                                host.eq_ignore_ascii_case(domain)
                                    || (host.parse::<IpAddr>().is_err()
                                        && host
                                            .strip_suffix(domain)
                                            .is_some_and(|prefix| prefix.ends_with('.')))
                            }
                        }
                    }
                    && ({
                        let (request_path, cookie_path): (&str, &str) =
                            (url.path(), &cookie.key.path);
                        {
                            request_path == cookie_path
                                || request_path
                                    .strip_prefix(cookie_path)
                                    .is_some_and(|suffix| {
                                        cookie_path.ends_with('/') || suffix.starts_with('/')
                                    })
                        }
                    })
            })
            .collect::<Vec<_>>();
        cookies.sort_by_key(|cookie| std::cmp::Reverse(cookie.key.path.len()));
        cookies
    }
}

impl EndpointCookieJar {
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
                    && ({
                        let (request_path, cookie_path): (&str, &str) =
                            (&cookie.key.path, &existing.key.path);
                        {
                            request_path == cookie_path
                                || request_path
                                    .strip_prefix(cookie_path)
                                    .is_some_and(|suffix| {
                                        cookie_path.ends_with('/') || suffix.starts_with('/')
                                    })
                        }
                    })
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
}

async fn finalize_report(
    report: &mut ExposureScanReport,
    started: Instant,
    cancel: &CancellationToken,
    progress: &Option<Sender<ExposureScanProgress>>,
) {
    if report.resolved_addresses.is_empty() {
        let reason = report.error.as_deref().unwrap_or("Target resolution did not complete");
        for phase in ExposureScanPhase::ALL {
            if !matches!(phase, ExposureScanPhase::DnsAssessment | ExposureScanPhase::AssetDiscovery | ExposureScanPhase::FinalizingReport) {
                send_phase_progress(progress, phase, ExposureScanPhaseState::Skipped, 1.0, reason);
            }
        }
    }
    report.endpoint_health = endpoint_health::observations();
    for endpoint in &mut report.endpoints {
        if endpoint_health::stopped(endpoint.ip, endpoint.port) {
            let reason = endpoint_health::STOP_REASON.to_owned();
            if !endpoint.evidence.contains(&reason) {
                endpoint.evidence.push(reason);
            }
        }
    }
    send_phase_progress(
        progress,
        ExposureScanPhase::FinalizingReport,
        ExposureScanPhaseState::Running,
        0.0,
        "Building security summary",
    );
    if cancel.is_cancelled() {
        report.status = ExposureScanStatus::Cancelled;
        report.error = Some("Scan cancelled".to_owned());
        report.timings.total_ms = started.elapsed().as_secs_f64() * 1000.0;
        return;
    }
    let mut input = report.clone();
    match crate::blocking::run(cancel, move |cancel| {
        let report = &mut input;
        for endpoint in &mut report.endpoints {
            if cancel.is_cancelled() {
                return input;
            }
            exposure_probe::product_identification::record_service_results(
                endpoint,
                &report.service_access,
            );
            exposure_probe::product_identification::record_captured(endpoint, cancel);
            crate::product_catalog::reconcile(endpoint);
        }

        let mut report = input;
        report.security_checks = report
            .endpoints
            .iter()
            .flat_map(|endpoint| endpoint.security_checks.iter().cloned())
            .collect();
        report.security_checks.sort_by(|left, right| {
            left.ip
                .cmp(&right.ip)
                .then(left.port.cmp(&right.port))
                .then(left.class.cmp(&right.class))
                .then(left.check_id.cmp(&right.check_id))
                .then(left.probe_url.cmp(&right.probe_url))
        });
        report.security_checks.dedup_by(|left, right| {
            left.ip == right.ip
                && left.port == right.port
                && left.check_id == right.check_id
                && left.probe_url == right.probe_url
        });
        report.findings.extend(
            report
                .security_checks
                .iter()
                .filter(|check| check.outcome == CheckOutcome::Vulnerable)
                .map(|check| ExposureFinding {
                    details: Vec::new(),
                    title: check.title.clone(),
                    description: format!(
                        "The {} security check confirmed the tested condition",
                        check.class
                    ),
                    ip: check.ip,
                    port: check.port,
                    transport: TransportProtocol::Tcp,
                    evidence: check.evidence.clone(),
                    component_kind: None,
                }),
        );
        let crawl_findings = std::mem::take(&mut report.findings);
        let mut findings = build_security_summary(
            &report.endpoints,
            report.request.security_operations,
            cancel,
        )
        .into_iter()
        .map(|finding| {
            (
                ({
                    let finding = &finding;
                    (
                        finding.ip,
                        finding.port,
                        finding.transport,
                        finding.title.clone(),
                    )
                }),
                finding,
            )
        })
        .collect::<BTreeMap<_, _>>();
        for finding in crawl_findings {
            if cancel.is_cancelled() {
                return report;
            }
            add_security_summary_finding(&mut findings, finding);
        }
        report.findings = findings.into_values().collect();
    finding_assessment::finalize_findings(&mut report, cancel);

        report
    })
    .await
    {
        Ok(processed) => {
            *report = processed;
            send_phase_progress(
                progress,
                ExposureScanPhase::FinalizingReport,
                ExposureScanPhaseState::Complete,
                1.0,
                "Report assembled",
            );
        }
        Err(crate::blocking::Error::Cancelled) => {
            report.status = ExposureScanStatus::Cancelled;
            report.error = Some("Scan cancelled".to_owned());
        }
        Err(error) => {
            report.status = ExposureScanStatus::Failed;
            report.error = Some(error.to_string());
        }
    }
    report.timings.total_ms = started.elapsed().as_secs_f64() * 1000.0;
}
