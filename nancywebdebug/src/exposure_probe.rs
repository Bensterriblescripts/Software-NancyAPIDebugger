use super::*;
use flate2::read::ZlibDecoder;
use std::collections::BTreeSet;
use std::io::Read as _;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeTier {
    Standard,
    SecurityOperations,
}

#[derive(Clone, Copy)]
enum ExposureSignature {
    Legacy,
    GitHead,
    GitConfig,
    GitRefs,
    GitIndex,
    GitLog,
    GitPackMetadata,
    Dotenv,
    WebConfig,
    JsonConfig,
    AwsCredentials,
    KubernetesConfig,
    PhpConfig,
    Properties,
    RailsCredentials,
    RailsKey,
    DjangoSettings,
    AzureCredentials,
    GoogleCredentials,
    Ci,
    Archive,
    VimSwap,
    Actuator(ActuatorKind),
}

#[derive(Clone, Copy)]
enum ActuatorKind {
    Env,
    ConfigProps,
    Beans,
    Mappings,
    ScheduledTasks,
    Caches,
    Conditions,
    Loggers,
    ThreadDump,
    Prometheus,
    Info,
}

struct ExposureProbe {
    family: &'static str,
    path: String,
    signature: ExposureSignature,
    tier: ProbeTier,
}

#[derive(Clone, Copy)]
pub(super) struct ScanContext<'a> {
    pub(super) hostname: &'a str,
    pub(super) request: &'a ExposureScanRequest,
    pub(super) cancel: &'a CancellationToken,
    pub(super) limiter: &'a ConnectionRateLimiter,
    pub(super) client_certificate: Option<&'a LoadedClientCertificate>,
}

#[derive(Clone, Copy)]
pub(super) struct ProbeContext<'a> {
    pub(super) ip: IpAddr,
    pub(super) port: u16,
    pub(super) scan: ScanContext<'a>,
}

impl ProbeContext<'_> {
    pub(super) fn with_port(self, port: u16) -> Self {
        Self { port, ..self }
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

pub(super) async fn scan_endpoint(context: ProbeContext<'_>) -> EndpointScan {
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
    let negotiation_only = NEGOTIATION_ONLY_TCP_PORTS.contains(&context.port);
    let should_probe_tls = TLS_PORTS.contains(&context.port)
        || (endpoint.service == ServiceKind::Unknown && !negotiation_only);
    if should_probe_tls {
        for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
            let observation = probe_tls_version(context, version).await;
            endpoint.tls.push(observation);
        }
        if TLS_PORTS.contains(&context.port) || endpoint.tls.iter().any(|tls| tls.supported) {
            endpoint.tls_probe_attempts = probe_legacy_tls(context).await;
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
        add_raw_tls_findings(&mut endpoint);
    }
    let tls_http = endpoint
        .tls
        .iter()
        .any(|tls| tls.supported && matches!(tls.alpn.as_deref(), Some("h2") | Some("http/1.1")));
    let unknown_before_http =
        endpoint.service == ServiceKind::Unknown || endpoint.service == ServiceKind::Tls;
    if !negotiation_only
        && (HTTPS_PORTS.contains(&context.port)
            || tls_http
            || (unknown_before_http && endpoint.tls.iter().any(|v| v.supported)))
    {
        audit_http(&mut endpoint, "https", context).await;
    }
    if !negotiation_only
        && endpoint.http.is_empty()
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

pub(super) fn add_product(
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

async fn probe_legacy_tls(context: ProbeContext<'_>) -> Vec<TlsProbeAttempt> {
    const MODERN_SUITES: &[u16] = &[0xc02f, 0xc02b, 0xc013, 0xc009, 0x009c, 0x002f];
    const WEAK_SUITES: &[(&str, &str, u16)] = &[
        ("tls.cipher.null-md5", "TLS_RSA_WITH_NULL_MD5", 0x0001),
        ("tls.cipher.null-sha", "TLS_RSA_WITH_NULL_SHA", 0x0002),
        (
            "tls.cipher.export",
            "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
            0x0003,
        ),
        ("tls.cipher.rc4", "TLS_RSA_WITH_RC4_128_SHA", 0x0005),
        (
            "tls.cipher.export-des",
            "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
            0x0008,
        ),
        ("tls.cipher.des", "TLS_RSA_WITH_DES_CBC_SHA", 0x0009),
        ("tls.cipher.3des", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x000a),
        (
            "tls.cipher.static-rsa",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0x009c,
        ),
        (
            "tls.cipher.sha1-mac",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x002f,
        ),
    ];
    let mut attempts = Vec::new();
    for (check_id, label, version) in [
        ("tls.protocol.1_0", "TLS 1.0", 0x0301),
        ("tls.protocol.1_1", "TLS 1.1", 0x0302),
    ] {
        attempts.push(
            raw_tls_attempt(context, check_id, label, version, MODERN_SUITES, true, true).await,
        );
    }
    for (check_id, cipher, suite) in WEAK_SUITES {
        attempts.push(
            raw_tls_attempt(context, check_id, "TLS 1.2", 0x0303, &[*suite], true, false).await,
        );
        if context.scan.cancel.is_cancelled() {
            return attempts;
        }
        if let Some(last) = attempts.last_mut() {
            last.offered_cipher = Some((*cipher).to_owned());
        }
    }
    attempts.push(
        raw_tls_attempt(
            context,
            "tls.renegotiation.legacy-client-hello",
            "TLS 1.2",
            0x0303,
            MODERN_SUITES,
            false,
            false,
        )
        .await,
    );
    attempts
}

async fn raw_tls_attempt(
    context: ProbeContext<'_>,
    check_id: &str,
    protocol: &str,
    version: u16,
    suites: &[u16],
    signal_secure_renegotiation: bool,
    offer_compression: bool,
) -> TlsProbeAttempt {
    let mut result = TlsProbeAttempt {
        check_id: check_id.to_owned(),
        offered_protocol: protocol.to_owned(),
        offered_cipher: None,
        accepted: false,
        negotiated_protocol: None,
        negotiated_cipher: None,
        compression: None,
        secure_renegotiation: None,
        error: None,
    };
    let mut candidate = limited_connect(context).await;
    let Some(mut stream) = candidate.stream.take() else {
        result.error = candidate.attempt.error;
        return result;
    };
    let hello = raw_client_hello(
        context.scan.hostname,
        version,
        suites,
        signal_secure_renegotiation,
        offer_compression,
    );
    let operation = async {
        stream.write_all(&hello).await?;
        stream.flush().await?;
        let mut response = vec![0u8; 16_384];
        let length = stream.read(&mut response).await?;
        response.truncate(length);
        Ok::<_, std::io::Error>(response)
    };
    let response = tokio::select! {
        _ = context.scan.cancel.cancelled() => {
            result.error = Some("Scan cancelled".to_owned());
            return result;
        }
        response = tokio::time::timeout(context.scan.request.probe_timeout, operation) => response,
    };
    match response {
        Ok(Ok(response)) => match parse_server_hello(&response) {
            Some((selected_version, selected_cipher, compression, secure_renegotiation)) => {
                result.accepted = true;
                result.negotiated_protocol = Some(tls_version_label(selected_version).to_owned());
                result.negotiated_cipher = Some(format!("0x{selected_cipher:04X}"));
                result.compression = Some(compression);
                result.secure_renegotiation = Some(secure_renegotiation);
            }
            None => {
                result.error = Some(if response.first() == Some(&21) {
                    "Server returned a TLS alert".to_owned()
                } else {
                    "No parseable ServerHello was returned".to_owned()
                });
            }
        },
        Ok(Err(error)) => result.error = Some(error.to_string()),
        Err(_) => result.error = Some("Raw TLS probe timed out".to_owned()),
    }
    result
}

fn raw_client_hello(
    hostname: &str,
    version: u16,
    suites: &[u16],
    signal_secure_renegotiation: bool,
    offer_compression: bool,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&version.to_be_bytes());
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_be_bytes();
    for index in 0..32 {
        body.push(seed[index % seed.len()] ^ (index as u8).wrapping_mul(31));
    }
    body.push(0);
    let suite_length = suites.len() * 2 + usize::from(signal_secure_renegotiation) * 2;
    body.extend_from_slice(&(suite_length as u16).to_be_bytes());
    for suite in suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    if signal_secure_renegotiation {
        body.extend_from_slice(&0x00ffu16.to_be_bytes());
    }
    if offer_compression {
        body.extend_from_slice(&[2, 0, 1]);
    } else {
        body.extend_from_slice(&[1, 0]);
    }
    let mut extensions = Vec::new();
    if !hostname.parse::<IpAddr>().is_ok() && hostname.len() <= u16::MAX as usize {
        let name = hostname.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        push_tls_extension(&mut extensions, 0, &sni);
    }
    push_tls_extension(&mut extensions, 10, &[0, 4, 0, 23, 0, 24]);
    push_tls_extension(&mut extensions, 11, &[1, 0]);
    push_tls_extension(
        &mut extensions,
        13,
        &[0, 12, 4, 3, 5, 3, 6, 3, 4, 1, 5, 1, 2, 1],
    );
    if signal_secure_renegotiation {
        push_tls_extension(&mut extensions, 0xff01, &[0]);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = vec![1];
    let length = body.len();
    handshake.extend_from_slice(&[
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
    ]);
    handshake.extend_from_slice(&body);
    let mut record = vec![22];
    record.extend_from_slice(&version.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn push_tls_extension(output: &mut Vec<u8>, kind: u16, value: &[u8]) {
    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);
}

fn parse_server_hello(bytes: &[u8]) -> Option<(u16, u16, u8, bool)> {
    let mut record_offset = 0usize;
    while record_offset + 5 <= bytes.len() {
        let record_type = bytes[record_offset];
        let length =
            u16::from_be_bytes([bytes[record_offset + 3], bytes[record_offset + 4]]) as usize;
        let start = record_offset + 5;
        let end = start.checked_add(length)?;
        if end > bytes.len() {
            return None;
        }
        if record_type == 22 && bytes.get(start) == Some(&2) {
            let body = start + 4;
            let version = u16::from_be_bytes([*bytes.get(body)?, *bytes.get(body + 1)?]);
            let session_length = *bytes.get(body + 34)? as usize;
            let cipher_offset = body + 35 + session_length;
            let cipher =
                u16::from_be_bytes([*bytes.get(cipher_offset)?, *bytes.get(cipher_offset + 1)?]);
            let compression = *bytes.get(cipher_offset + 2)?;
            let extension_length = bytes
                .get(cipher_offset + 3..cipher_offset + 5)
                .map(|value| u16::from_be_bytes([value[0], value[1]]) as usize)
                .unwrap_or(0);
            let mut extension_offset = cipher_offset + 5;
            let extension_end = extension_offset.saturating_add(extension_length).min(end);
            let mut secure_renegotiation = false;
            while extension_offset + 4 <= extension_end {
                let kind =
                    u16::from_be_bytes([bytes[extension_offset], bytes[extension_offset + 1]]);
                let length =
                    u16::from_be_bytes([bytes[extension_offset + 2], bytes[extension_offset + 3]])
                        as usize;
                if kind == 0xff01 {
                    secure_renegotiation = true;
                }
                extension_offset = extension_offset.checked_add(4 + length)?;
            }
            return Some((version, cipher, compression, secure_renegotiation));
        }
        record_offset = end;
    }
    None
}

fn tls_version_label(version: u16) -> &'static str {
    match version {
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown TLS version",
    }
}

fn add_raw_tls_findings(endpoint: &mut EndpointScan) {
    for attempt in &endpoint.tls_probe_attempts {
        if !attempt.accepted {
            continue;
        }
        if matches!(
            attempt.check_id.as_str(),
            "tls.protocol.1_0" | "tls.protocol.1_1"
        ) {
            endpoint.findings.push(finding(
                endpoint,
                "Obsolete TLS protocol accepted",
                "The server completed a ServerHello using TLS 1.0 or TLS 1.1",
                vec![format!(
                    "{} accepted and negotiated {}",
                    attempt.offered_protocol,
                    attempt.negotiated_protocol.as_deref().unwrap_or("unknown")
                )],
            ));
        } else if attempt.check_id.starts_with("tls.cipher.") {
            endpoint.findings.push(finding(
                endpoint,
                "Weak TLS cipher suite accepted",
                "The server selected a weak or static-RSA suite when it was individually offered",
                vec![format!(
                    "{} selected {}",
                    attempt.offered_cipher.as_deref().unwrap_or("weak suite"),
                    attempt.negotiated_cipher.as_deref().unwrap_or("unknown")
                )],
            ));
        }
        if attempt
            .compression
            .is_some_and(|compression| compression != 0)
        {
            endpoint.findings.push(finding(
                endpoint,
                "TLS compression negotiated",
                "The server selected a non-null TLS compression method",
                vec![format!(
                    "Compression method {}",
                    attempt.compression.unwrap_or_default()
                )],
            ));
        }
    }
    if endpoint
        .tls_probe_attempts
        .iter()
        .find(|attempt| attempt.check_id == "tls.renegotiation.legacy-client-hello")
        .is_some_and(|attempt| attempt.accepted && attempt.secure_renegotiation != Some(true))
    {
        endpoint.findings.push(finding(
            endpoint,
            "Legacy TLS renegotiation signaling accepted",
            "The server accepted a legacy ClientHello without the secure-renegotiation extension or SCSV",
            vec!["Legacy ClientHello produced a ServerHello without secure-renegotiation signaling".to_owned()],
        ));
    }
}

async fn probe_tls_version(context: ProbeContext<'_>, version: TlsVersion) -> TlsObservation {
    let options = TlsHandshakeOptions {
        version: Some(version),
        permissive: false,
        offer_http2: true,
        use_client_certificate: false,
    };
    let mut observation = match tls_handshake(context, options).await {
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
    };
    let baseline_status = observation.client_auth.status;
    let should_retry = matches!(
        baseline_status,
        ClientAuthStatus::Optional | ClientAuthStatus::Required
    ) && context
        .scan
        .client_certificate
        .is_some_and(|certificate| certificate.applies_to(context.scan.hostname));
    if !should_retry {
        return observation;
    }
    let retry_options = TlsHandshakeOptions {
        use_client_certificate: true,
        permissive: observation.unverified || observation.validation_error.is_some(),
        ..options
    };
    match tls_handshake(context, retry_options).await {
        Ok(success) => {
            let mut retried = TlsObservation::from_trace(
                version,
                context.scan.hostname,
                if retry_options.permissive {
                    TlsObservationState::Unverified
                } else {
                    TlsObservationState::Verified
                },
                success.trace,
                observation.validation_error.clone(),
                None,
            );
            retried.client_auth.evidence.insert(
                0,
                format!(
                    "No-certificate handshake classified client authentication as {baseline_status}"
                ),
            );
            retried
        }
        Err(failure) => {
            observation.client_auth = failure.trace.client_auth;
            observation.client_auth.status = ClientAuthStatus::Rejected;
            observation.client_auth.evidence.insert(
                0,
                format!(
                    "No-certificate handshake classified client authentication as {baseline_status}"
                ),
            );
            observation.client_auth.evidence.push(format!(
                "Selected client certificate retry failed: {}",
                failure.error
            ));
            observation
        }
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
        let (mut supported, verified, unverified) = match state {
            TlsObservationState::Verified => (true, true, false),
            TlsObservationState::Unverified => (true, false, true),
            TlsObservationState::Unsupported => (false, false, false),
        };
        if trace.client_auth.certificate_requested {
            supported = true;
        }
        let hostname_valid = trace
            .certificates
            .first()
            .and_then(|certificate| certificate_hostname_valid(certificate, hostname));
        let certificate_expired = trace.certificates.first().and_then(certificate_is_expired);
        let certificate_not_yet_valid = trace
            .certificates
            .first()
            .and_then(certificate_is_not_yet_valid);
        let validation_error = validation_error.or(trace.validation_error.clone());
        let ocsp = parse_ocsp_observation(&trace.ocsp_response);
        let revocation = revocation_state(state, validation_error.as_deref(), ocsp.as_ref());
        let chain_diagnostics =
            certificate_chain_diagnostics(&trace.certificates, validation_error.as_deref());
        let client_auth = trace.client_auth.clone();
        Self {
            requested_version,
            supported,
            verified,
            unverified,
            negotiated_version: supported.then_some(trace.version).flatten(),
            alpn: supported.then_some(trace.alpn).flatten(),
            cipher: supported.then_some(trace.cipher_suite).flatten(),
            validation_error,
            hostname_valid,
            certificate_expired,
            certificate_not_yet_valid,
            revocation,
            ocsp,
            chain_diagnostics,
            certificates: trace.certificates,
            error,
            client_auth,
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
    use_client_certificate: bool,
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
        options
            .use_client_certificate
            .then_some(context.scan.client_certificate)
            .flatten()
            .filter(|certificate| certificate.applies_to(context.scan.hostname)),
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

fn revocation_state(
    state: TlsObservationState,
    validation_error: Option<&str>,
    ocsp: Option<&OcspObservation>,
) -> RevocationState {
    if ocsp.and_then(|value| value.certificate_status.as_deref()) == Some("Revoked") {
        return RevocationState::Revoked;
    }
    if ocsp.and_then(|value| value.certificate_status.as_deref()) == Some("Good") {
        return RevocationState::Good;
    }
    if let Some(error) = validation_error.map(str::to_ascii_lowercase) {
        if error.contains("revoked") {
            return RevocationState::Revoked;
        }
        if error.contains("offline") || error.contains("revocation server") {
            return RevocationState::Offline;
        }
        if error.contains("revocation") {
            return RevocationState::Unknown;
        }
    }
    if cfg!(windows) && matches!(state, TlsObservationState::Verified) {
        RevocationState::Good
    } else if cfg!(windows) {
        RevocationState::Unknown
    } else {
        RevocationState::NotChecked
    }
}

fn parse_ocsp_observation(bytes: &[u8]) -> Option<OcspObservation> {
    if bytes.is_empty() {
        return None;
    }
    let mut observation = OcspObservation {
        bytes: bytes.len(),
        response_status: "Malformed".to_owned(),
        certificate_status: None,
        produced_at: None,
        this_update: None,
        next_update: None,
        fresh: None,
        error: None,
    };
    let Some((0x30, sequence_start, sequence_end)) = der_tlv(bytes, 0) else {
        observation.error = Some("Stapled OCSP response is not a DER sequence".to_owned());
        return Some(observation);
    };
    let Some((0x0a, status_start, status_end)) = der_tlv(bytes, sequence_start) else {
        observation.error = Some("Stapled OCSP response has no response status".to_owned());
        return Some(observation);
    };
    let status = bytes
        .get(status_start..status_end)
        .and_then(|value| value.last())
        .copied();
    observation.response_status = match status {
        Some(0) => "Successful",
        Some(1) => "Malformed request",
        Some(2) => "Internal error",
        Some(3) => "Try later",
        Some(5) => "Signature required",
        Some(6) => "Unauthorized",
        _ => "Unknown",
    }
    .to_owned();
    if status != Some(0) {
        return Some(observation);
    }
    let mut times = Vec::new();
    scan_ocsp_der(
        bytes,
        sequence_start,
        sequence_end,
        0,
        &mut observation,
        &mut times,
    );
    observation.produced_at = times.first().cloned();
    observation.this_update = times.get(1).cloned();
    observation.next_update = times.get(2).cloned();
    if let Some(this_update) = observation.this_update.as_deref().and_then(asn1_time_unix) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|value| value.as_secs() as i64);
        observation.fresh = now.map(|now| {
            this_update <= now
                && observation
                    .next_update
                    .as_deref()
                    .and_then(asn1_time_unix)
                    .is_none_or(|next_update| now <= next_update)
        });
    }
    Some(observation)
}

fn der_tlv(bytes: &[u8], offset: usize) -> Option<(u8, usize, usize)> {
    let tag = *bytes.get(offset)?;
    let first = *bytes.get(offset + 1)?;
    let (length, header) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for byte in bytes.get(offset + 2..offset + 2 + count)? {
            length = length.checked_mul(256)?.checked_add(*byte as usize)?;
        }
        (length, 2 + count)
    };
    let start = offset.checked_add(header)?;
    let end = start.checked_add(length)?;
    (end <= bytes.len()).then_some((tag, start, end))
}

fn scan_ocsp_der(
    bytes: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    observation: &mut OcspObservation,
    times: &mut Vec<String>,
) {
    if depth > 12 {
        return;
    }
    let mut offset = start;
    while offset < end {
        let Some((tag, value_start, value_end)) = der_tlv(bytes, offset) else {
            break;
        };
        if value_end > end {
            break;
        }
        if tag == 0x18
            && let Ok(value) = std::str::from_utf8(&bytes[value_start..value_end])
        {
            times.push(value.to_owned());
        }
        if tag == 0x30
            && let Some((0x30, _, first_end)) = der_tlv(bytes, value_start)
            && let Some((status_tag, _, _)) = der_tlv(bytes, first_end)
            && matches!(status_tag, 0x80 | 0xa0 | 0x81 | 0xa1 | 0x82 | 0xa2)
        {
            observation.certificate_status = Some(
                match status_tag & 0x1f {
                    0 => "Good",
                    1 => "Revoked",
                    _ => "Unknown",
                }
                .to_owned(),
            );
        }
        if tag & 0x20 != 0 || matches!(tag, 0x04) {
            scan_ocsp_der(bytes, value_start, value_end, depth + 1, observation, times);
        }
        offset = value_end;
    }
}

fn asn1_time_unix(value: &str) -> Option<i64> {
    let digits = value.strip_suffix('Z')?;
    if digits.len() < 14 || !digits[..14].bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let number = |range: std::ops::Range<usize>| digits.get(range)?.parse::<i64>().ok();
    let year = number(0..4)?;
    let month = number(4..6)?;
    let day = number(6..8)?;
    let hour = number(8..10)?;
    let minute = number(10..12)?;
    let second = number(12..14)?;
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn certificate_chain_diagnostics(
    certificates: &[CertificateTrace],
    validation_error: Option<&str>,
) -> Vec<String> {
    let mut diagnostics = Vec::new();
    if certificates.is_empty() {
        diagnostics.push("No peer certificate chain was captured".to_owned());
        return diagnostics;
    }
    if certificates[0].subject == certificates[0].issuer {
        diagnostics.push("Leaf certificate is self-signed".to_owned());
    }
    for pair in certificates.windows(2) {
        if pair[0].issuer != pair[1].subject {
            diagnostics.push(format!(
                "Broken chain ordering: issuer '{}' is not the next subject '{}'",
                pair[0].issuer, pair[1].subject
            ));
        }
    }
    let mut fingerprints = HashSet::new();
    if certificates
        .iter()
        .any(|certificate| !fingerprints.insert(&certificate.sha256))
    {
        diagnostics.push("Certificate chain contains a duplicate certificate".to_owned());
    }
    if certificates
        .last()
        .is_some_and(|certificate| certificate.subject == certificate.issuer)
    {
        diagnostics.push("Server sent a root certificate".to_owned());
    } else if certificates.len() == 1 && certificates[0].subject != certificates[0].issuer {
        diagnostics.push("Certificate chain may be missing an intermediate".to_owned());
    }
    if let Some(error) = validation_error {
        diagnostics.push(format!("Platform trust validation failed: {error}"));
    }
    for (index, certificate) in certificates.iter().enumerate() {
        let role = if index == 0 { "Leaf" } else { "CA" };
        if weak_signature_oid(&certificate.signature_algorithm) {
            diagnostics.push(format!(
                "{role} certificate uses weak signature algorithm {}",
                certificate.signature_algorithm
            ));
        }
        if certificate.public_key_algorithm == "1.2.840.113549.1.1.1"
            && certificate.public_key_bits.is_some_and(|bits| bits < 2048)
        {
            diagnostics.push(format!(
                "{role} certificate has a {}-bit RSA key",
                certificate.public_key_bits.unwrap_or_default()
            ));
        }
        if certificate.public_key_algorithm == "1.2.840.10045.2.1"
            && certificate.public_key_bits.is_some_and(|bits| bits < 224)
        {
            diagnostics.push(format!(
                "{role} certificate has a {}-bit EC key",
                certificate.public_key_bits.unwrap_or_default()
            ));
        }
        if index == 0 {
            if certificate.is_ca == Some(true) {
                diagnostics.push("Leaf certificate is marked as a CA".to_owned());
            }
            if certificate
                .key_usage
                .iter()
                .any(|usage| usage == "Key Cert Sign")
            {
                diagnostics
                    .push("Leaf certificate key usage permits certificate signing".to_owned());
            }
            if !certificate.extended_key_usage.is_empty()
                && !certificate
                    .extended_key_usage
                    .iter()
                    .any(|usage| matches!(usage.as_str(), "Any" | "Server authentication"))
            {
                diagnostics
                    .push("Leaf certificate EKU does not permit server authentication".to_owned());
            }
        } else if certificate.is_ca != Some(true) {
            diagnostics.push(format!(
                "Certificate {index} is used as a CA without CA basic constraints"
            ));
        }
    }
    diagnostics
}

fn weak_signature_oid(oid: &str) -> bool {
    matches!(
        oid,
        "1.2.840.113549.1.1.4" | "1.2.840.113549.1.1.5" | "1.2.840.10040.4.3" | "1.2.840.10045.4.1"
    )
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
    if endpoint
        .tls
        .iter()
        .any(|tls| tls.revocation == RevocationState::Revoked)
    {
        endpoint.findings.push(finding(
            endpoint,
            "Revoked TLS certificate",
            "Windows chain validation or a stapled OCSP response reported the certificate as revoked",
            vec!["Certificate revocation status: Revoked".to_owned()],
        ));
    }
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
            transport: endpoint.transport,
            evidence: errors,
            component_kind: None,
        });
    }
    let certificate_issues = endpoint
        .tls
        .iter()
        .flat_map(|tls| &tls.chain_diagnostics)
        .filter(|diagnostic| {
            !diagnostic.starts_with("Server sent a root certificate")
                && !diagnostic.starts_with("Platform trust validation failed")
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    if !certificate_issues.is_empty() {
        endpoint.findings.push(finding(
            endpoint,
            "TLS certificate chain or key weakness",
            "The presented certificate chain contains a structural, usage, signature, or key-strength issue",
            certificate_issues.into_iter().collect(),
        ));
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
        for issue in super::browser_policy::response_issues(
            root,
            &final_scheme,
            context.scan.request.security_operations,
        ) {
            endpoint.findings.push(finding(
                endpoint,
                issue.title,
                issue.description,
                vec![issue.evidence],
            ));
        }
        if let Some(hsts) = super::browser_policy::hsts_assessment(root, &final_scheme) {
            let (title, severity, outcome, evidence) = match hsts.issue {
                Some(issue) => (
                    issue.title.to_owned(),
                    if issue.title == "Weak HSTS max-age" {
                        FindingSeverity::Low
                    } else {
                        FindingSeverity::Medium
                    },
                    CheckOutcome::Vulnerable,
                    vec![issue.evidence],
                ),
                None => (
                    "HSTS policy weakness".to_owned(),
                    FindingSeverity::Informational,
                    CheckOutcome::NotObserved,
                    vec![format!(
                        "HSTS max-age is {} seconds",
                        hsts.max_age.unwrap_or_default()
                    )],
                ),
            };
            endpoint.security_checks.push(SecurityCheckResult {
                ip: endpoint.ip,
                port: endpoint.port,
                check_id: "tls.hsts.policy".to_owned(),
                class: VulnerabilityClass::Tls,
                title,
                severity,
                confidence: Confidence::High,
                outcome,
                probe_url: Some(root.url.clone()),
                request_evidence: Some("GET /".to_owned()),
                evidence,
                reason: None,
            });
            endpoint.security_checks.push(SecurityCheckResult {
                ip: endpoint.ip,
                port: endpoint.port,
                check_id: "tls.hsts.include-subdomains".to_owned(),
                class: VulnerabilityClass::Tls,
                title: "HSTS includeSubDomains hardening".to_owned(),
                severity: FindingSeverity::Informational,
                confidence: Confidence::High,
                outcome: CheckOutcome::NotObserved,
                probe_url: Some(root.url.clone()),
                request_evidence: None,
                evidence: hsts
                    .include_subdomains
                    .then(|| vec!["includeSubDomains is present".to_owned()])
                    .unwrap_or_default(),
                reason: (!hsts.include_subdomains).then(|| {
                    "includeSubDomains is absent; this is a hardening observation".to_owned()
                }),
            });
            let preload_eligible = hsts.max_age.is_some_and(|value| value >= 31_536_000)
                && hsts.include_subdomains
                && hsts.preload;
            endpoint.security_checks.push(SecurityCheckResult {
                ip: endpoint.ip,
                port: endpoint.port,
                check_id: "tls.hsts.preload-eligibility".to_owned(),
                class: VulnerabilityClass::Tls,
                title: "HSTS preload eligibility".to_owned(),
                severity: FindingSeverity::Informational,
                confidence: Confidence::Medium,
                outcome: CheckOutcome::NotObserved,
                probe_url: Some(root.url.clone()),
                request_evidence: None,
                evidence: preload_eligible
                    .then(|| vec!["Header meets the local syntactic preload checks".to_owned()])
                    .unwrap_or_default(),
                reason: (!preload_eligible).then(|| {
                    "Header does not meet local max-age, includeSubDomains, and preload-directive criteria; no preload-list lookup was performed".to_owned()
                }),
            });
        }
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
    if !context.scan.request.security_operations {
        let origins = vec![
            ("arbitrary", "https://nancy-exposure.invalid".to_owned()),
            ("null", "null".to_owned()),
        ];
        let samples =
            run_cors_matrix_for_path(endpoint, scheme, "/", &origins, context, cookie_jar).await;
        add_cors_sample_findings(endpoint, &samples, false);
    }
    audit_exposure_paths(
        endpoint,
        scheme,
        context,
        cookie_jar,
        baseline.as_ref(),
        &baseline_path,
    )
    .await;
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
        "/login/index.php",
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

pub(super) fn html_attribute(tag: &str, attribute: &str) -> Option<String> {
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

pub(super) fn same_origin(left: &Url, right: &Url) -> bool {
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

async fn audit_exposure_paths(
    endpoint: &mut EndpointScan,
    scheme: &str,
    context: ProbeContext<'_>,
    cookie_jar: Option<&Mutex<EndpointCookieJar>>,
    baseline: Option<&HttpObservation>,
    baseline_path: &str,
) {
    let mut probes = standard_exposure_probes();
    if context.scan.request.security_operations {
        let cap = 96usize.min(context.scan.request.crawl_max_urls);
        probes.extend(security_operations_exposure_probes().into_iter().take(cap));
    }
    let mut git_oid = None;
    let mut git_ref = None;
    for probe in probes {
        if context.scan.cancel.is_cancelled() {
            break;
        }
        if probe.tier == ProbeTier::SecurityOperations && !context.scan.request.security_operations
        {
            continue;
        }
        let chain =
            request_http_chain_with_cookies(context, scheme, "GET", &probe.path, &[], cookie_jar)
                .await
                .unwrap_or_default();
        if let Some(response) = chain.last() {
            if matches!(response.status, 401 | 403) || redirects_to_login(&chain) {
                endpoint.evidence.push(format!(
                    "Protected {} endpoint evidence: {} returned {}",
                    probe.family, probe.path, response.status
                ));
            } else if (200..300).contains(&response.status)
                && redirect_chain_preserves_path(&chain, &probe.path)
                && !baseline.is_some_and(|baseline| {
                    looks_like_soft_404(baseline, response, baseline_path, &probe.path)
                })
                && let Some(signature) = validate_exposure_probe(&probe, response)
            {
                let (title, description) = exposure_family_text(probe.family);
                endpoint.findings.push(finding(
                    endpoint,
                    title,
                    description,
                    vec![
                        format!("GET {} returned {}", probe.path, response.status),
                        signature,
                    ],
                ));
                if is_textual_exposure(&probe) {
                    for issue in super::artifact_analysis::text_artifact_secret_issues(
                        &response.url,
                        &response.body,
                        None,
                    ) {
                        endpoint.findings.push(finding(
                            endpoint,
                            issue.title,
                            issue.description,
                            vec![issue.evidence],
                        ));
                    }
                }
                match probe.signature {
                    ExposureSignature::GitHead => {
                        let text = String::from_utf8_lossy(&response.body);
                        git_oid = git_object_id(text.trim());
                        git_ref = text
                            .trim()
                            .strip_prefix("ref: ")
                            .filter(|value| safe_git_ref(value))
                            .map(|value| format!("/.git/{value}"));
                    }
                    ExposureSignature::GitRefs => {
                        git_oid = first_git_object_id(&response.body).or(git_oid);
                    }
                    _ => {}
                }
            }
        }
        endpoint.http.extend(chain);
    }
    if git_oid.is_none()
        && let Some(reference) = git_ref
        && !context.scan.cancel.is_cancelled()
    {
        let chain =
            request_http_chain_with_cookies(context, scheme, "GET", &reference, &[], cookie_jar)
                .await
                .unwrap_or_default();
        if let Some(response) = chain.last()
            && (200..300).contains(&response.status)
            && redirect_chain_preserves_path(&chain, &reference)
            && !baseline.is_some_and(|baseline| {
                looks_like_soft_404(baseline, response, baseline_path, &reference)
            })
            && let Some(object_id) = first_git_object_id(&response.body)
        {
            endpoint.findings.push(finding(
                endpoint,
                "Exposed Git repository metadata",
                "A Git reference is publicly readable",
                vec![
                    format!("GET {reference} returned {}", response.status),
                    "Git object identifier detected; value withheld".to_owned(),
                ],
            ));
            git_oid = Some(object_id);
        }
        endpoint.http.extend(chain);
    }
    if let Some(object_id) = git_oid
        && !context.scan.cancel.is_cancelled()
    {
        let object_path = format!("/.git/objects/{}/{}", &object_id[..2], &object_id[2..]);
        let chain =
            request_http_chain_with_cookies(context, scheme, "GET", &object_path, &[], cookie_jar)
                .await
                .unwrap_or_default();
        if let Some(response) = chain.last()
            && (200..300).contains(&response.status)
            && redirect_chain_preserves_path(&chain, &object_path)
            && valid_loose_git_object(&response.body)
        {
            endpoint.findings.push(finding(
                endpoint,
                "Exposed Git repository object",
                "One referenced loose Git object is publicly readable",
                vec![
                    format!("GET {object_path} returned {}", response.status),
                    "Bounded zlib output contained a valid Git object header".to_owned(),
                ],
            ));
        }
        endpoint.http.extend(chain);
    }
}

fn standard_exposure_probes() -> Vec<ExposureProbe> {
    [
        ("Git", "/.git/HEAD", ExposureSignature::GitHead),
        ("Git", "/.git/config", ExposureSignature::GitConfig),
        ("Git", "/.git/packed-refs", ExposureSignature::GitRefs),
        ("Configuration", "/.env", ExposureSignature::Dotenv),
        ("Configuration", "/.env.bak", ExposureSignature::Dotenv),
        ("Configuration", "/web.config", ExposureSignature::WebConfig),
        (
            "Configuration",
            "/appsettings.json",
            ExposureSignature::JsonConfig,
        ),
        (
            "Credentials",
            "/.aws/credentials",
            ExposureSignature::AwsCredentials,
        ),
        (
            "Credentials",
            "/.kube/config",
            ExposureSignature::KubernetesConfig,
        ),
        ("Runtime", "/server-status", ExposureSignature::Legacy),
        ("Runtime", "/server-info", ExposureSignature::Legacy),
        ("Runtime", "/debug", ExposureSignature::Legacy),
        ("Runtime", "/metrics", ExposureSignature::Legacy),
        ("Actuator", "/actuator", ExposureSignature::Legacy),
        ("Actuator", "/actuator/health", ExposureSignature::Legacy),
        ("API documentation", "/swagger", ExposureSignature::Legacy),
        (
            "API documentation",
            "/swagger/index.html",
            ExposureSignature::Legacy,
        ),
        (
            "API documentation",
            "/openapi.json",
            ExposureSignature::Legacy,
        ),
        ("API documentation", "/api-docs", ExposureSignature::Legacy),
        ("Runtime", "/phpinfo.php", ExposureSignature::Legacy),
    ]
    .into_iter()
    .map(|(family, path, signature)| ExposureProbe {
        family,
        path: path.to_owned(),
        signature,
        tier: ProbeTier::Standard,
    })
    .collect()
}

fn security_operations_exposure_probes() -> Vec<ExposureProbe> {
    let mut probes = Vec::new();
    for base in ["/config.php"] {
        for suffix in [".bak", ".old", ".orig", "~", ".swp", ".swo"] {
            let signature = if matches!(suffix, ".swp" | ".swo") {
                ExposureSignature::VimSwap
            } else {
                ExposureSignature::PhpConfig
            };
            push_probe(&mut probes, "Backup", format!("{base}{suffix}"), signature);
        }
    }
    for name in ["backup", "site", "source", "www", "dist"] {
        for extension in ["zip", "tar", "tar.gz", "tgz", "gz", "gzip", "7z"] {
            push_probe(
                &mut probes,
                "Archive",
                format!("/{name}.{extension}"),
                ExposureSignature::Archive,
            );
        }
    }
    for (path, signature) in [
        ("/.env.local", ExposureSignature::Dotenv),
        ("/.env.production", ExposureSignature::Dotenv),
        ("/.env.development", ExposureSignature::Dotenv),
        ("/.env.staging", ExposureSignature::Dotenv),
        ("/config.php", ExposureSignature::PhpConfig),
        ("/wp-config.php", ExposureSignature::PhpConfig),
        (
            "/appsettings.Development.json",
            ExposureSignature::JsonConfig,
        ),
        (
            "/appsettings.Production.json",
            ExposureSignature::JsonConfig,
        ),
        ("/application.properties", ExposureSignature::Properties),
        ("/application.yml", ExposureSignature::Properties),
        ("/bootstrap.properties", ExposureSignature::Properties),
        ("/bootstrap.yml", ExposureSignature::Properties),
        (
            "/config/credentials.yml",
            ExposureSignature::RailsCredentials,
        ),
        (
            "/config/credentials.yml.enc",
            ExposureSignature::RailsCredentials,
        ),
        ("/config/database.yml", ExposureSignature::RailsCredentials),
        ("/config/master.key", ExposureSignature::RailsKey),
        ("/settings.py", ExposureSignature::DjangoSettings),
        ("/local_settings.py", ExposureSignature::DjangoSettings),
    ] {
        push_probe(
            &mut probes,
            "Framework configuration",
            path.to_owned(),
            signature,
        );
    }
    for (path, signature) in [
        (
            "/.azure/azureProfile.json",
            ExposureSignature::AzureCredentials,
        ),
        (
            "/.azure/accessTokens.json",
            ExposureSignature::AzureCredentials,
        ),
        (
            "/.config/gcloud/application_default_credentials.json",
            ExposureSignature::GoogleCredentials,
        ),
        (
            "/service-account.json",
            ExposureSignature::GoogleCredentials,
        ),
        (
            "/google-service-account.json",
            ExposureSignature::GoogleCredentials,
        ),
        ("/kubeconfig", ExposureSignature::KubernetesConfig),
        ("/.kube/config.bak", ExposureSignature::KubernetesConfig),
    ] {
        push_probe(&mut probes, "Cloud credentials", path.to_owned(), signature);
    }
    for (path, signature) in [
        ("/.git/index", ExposureSignature::GitIndex),
        ("/.git/logs/HEAD", ExposureSignature::GitLog),
        ("/.git/refs/heads/main", ExposureSignature::GitRefs),
        ("/.git/refs/heads/master", ExposureSignature::GitRefs),
        ("/.git/refs/remotes/origin/HEAD", ExposureSignature::GitHead),
        (
            "/.git/objects/info/packs",
            ExposureSignature::GitPackMetadata,
        ),
        (
            "/.git/objects/info/alternates",
            ExposureSignature::GitPackMetadata,
        ),
    ] {
        push_probe(&mut probes, "Git", path.to_owned(), signature);
    }
    for (path, kind) in [
        ("/actuator/env", ActuatorKind::Env),
        ("/actuator/configprops", ActuatorKind::ConfigProps),
        ("/actuator/beans", ActuatorKind::Beans),
        ("/actuator/mappings", ActuatorKind::Mappings),
        ("/actuator/scheduledtasks", ActuatorKind::ScheduledTasks),
        ("/actuator/caches", ActuatorKind::Caches),
        ("/actuator/conditions", ActuatorKind::Conditions),
        ("/actuator/loggers", ActuatorKind::Loggers),
        ("/actuator/threaddump", ActuatorKind::ThreadDump),
        ("/actuator/prometheus", ActuatorKind::Prometheus),
        ("/actuator/info", ActuatorKind::Info),
    ] {
        push_probe(
            &mut probes,
            "Actuator",
            path.to_owned(),
            ExposureSignature::Actuator(kind),
        );
    }
    for path in [
        "/Jenkinsfile",
        "/.gitlab-ci.yml",
        "/.github/workflows/ci.yml",
        "/.github/workflows/build.yml",
        "/.github/workflows/release.yml",
        "/.circleci/config.yml",
        "/azure-pipelines.yml",
        "/bitbucket-pipelines.yml",
        "/.travis.yml",
        "/buildspec.yml",
        "/build.zip",
        "/artifacts.zip",
    ] {
        let signature = if path.ends_with(".zip") {
            ExposureSignature::Archive
        } else {
            ExposureSignature::Ci
        };
        push_probe(&mut probes, "CI artifact", path.to_owned(), signature);
    }
    probes
}

pub(super) fn security_operations_exposure_path_count(limit: usize) -> usize {
    security_operations_exposure_probes()
        .len()
        .min(96)
        .min(limit)
}

fn push_probe(
    probes: &mut Vec<ExposureProbe>,
    family: &'static str,
    path: String,
    signature: ExposureSignature,
) {
    probes.push(ExposureProbe {
        family,
        path,
        signature,
        tier: ProbeTier::SecurityOperations,
    });
}

fn validate_exposure_probe(probe: &ExposureProbe, response: &HttpObservation) -> Option<String> {
    let body = &response.body;
    let text = std::str::from_utf8(body).ok();
    let lower = text.map(str::to_ascii_lowercase);
    let signature = match probe.signature {
        ExposureSignature::Legacy => {
            return sensitive_signature(&probe.path, response).map(|item| item.2);
        }
        ExposureSignature::GitHead => text.is_some_and(|text| {
            text.trim().starts_with("ref: refs/") || git_object_id(text.trim()).is_some()
        }),
        ExposureSignature::GitConfig => lower.as_deref().is_some_and(|text| {
            text.contains("[core]") && text.contains("repositoryformatversion")
                || text.contains("[remote \"") && text.contains("url =")
        }),
        ExposureSignature::GitRefs => first_git_object_id(body).is_some(),
        ExposureSignature::GitIndex => body.starts_with(b"DIRC") && body.len() >= 12,
        ExposureSignature::GitLog => text.is_some_and(|text| {
            text.lines().any(|line| {
                let mut fields = line.split_ascii_whitespace();
                fields.next().and_then(git_object_id).is_some()
                    && fields.next().and_then(git_object_id).is_some()
            })
        }),
        ExposureSignature::GitPackMetadata => lower.as_deref().is_some_and(|text| {
            text.lines().any(|line| {
                line.trim_start().starts_with('p') && line.contains("pack-")
                    || line.contains("../objects")
            })
        }),
        ExposureSignature::Dotenv => text.is_some_and(valid_dotenv),
        ExposureSignature::WebConfig => lower.as_deref().is_some_and(|text| {
            text.contains("<configuration")
                && (text.contains("<system.web")
                    || text.contains("<appsettings")
                    || text.contains("<connectionstrings"))
        }),
        ExposureSignature::JsonConfig => serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .is_some_and(|json| json_config_signature(&json)),
        ExposureSignature::AwsCredentials => lower.as_deref().is_some_and(|text| {
            text.contains("aws_access_key_id")
                && (text.contains("aws_secret_access_key") || text.contains("[default]"))
        }),
        ExposureSignature::KubernetesConfig => lower.as_deref().is_some_and(|text| {
            text.contains("apiversion:") && text.contains("clusters:") && text.contains("contexts:")
        }),
        ExposureSignature::PhpConfig => lower.as_deref().is_some_and(|text| {
            text.contains("<?php")
                && (text.contains("db_password")
                    || text.contains("database_url")
                    || text.contains("define(")
                    || text.contains("$config"))
        }),
        ExposureSignature::Properties => text.is_some_and(valid_properties),
        ExposureSignature::RailsCredentials => {
            body.len() >= 16
                && (lower.as_deref().is_some_and(|text| {
                    text.contains("secret_key_base:")
                        || text.contains("active_record:")
                        || text.contains("adapter:") && text.contains("database:")
                }) || probe.path.ends_with(".enc") && !looks_like_html(body))
        }
        ExposureSignature::RailsKey => text.is_some_and(|text| {
            let value = text.trim();
            matches!(value.len(), 32 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        }),
        ExposureSignature::DjangoSettings => lower.as_deref().is_some_and(|text| {
            text.contains("installed_apps")
                && (text.contains("secret_key") || text.contains("databases"))
        }),
        ExposureSignature::AzureCredentials => serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .is_some_and(|json| {
                json.get("subscriptions").is_some()
                    || json.get("accessToken").is_some()
                    || json.get("refreshToken").is_some()
            }),
        ExposureSignature::GoogleCredentials => serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .is_some_and(|json| {
                json.get("type").and_then(|value| value.as_str()) == Some("service_account")
                    && json.get("client_email").is_some()
                    && json.get("private_key").is_some()
                    || json.get("client_id").is_some() && json.get("client_secret").is_some()
            }),
        ExposureSignature::Ci => text.is_some_and(|text| valid_ci(&probe.path, text)),
        ExposureSignature::Archive => valid_archive(&probe.path, body),
        ExposureSignature::VimSwap => body.starts_with(b"b0VIM "),
        ExposureSignature::Actuator(kind) => valid_actuator(kind, response),
    };
    signature.then(|| format!("Validated {} content signature", probe.family))
}

fn exposure_family_text(family: &str) -> (&'static str, &'static str) {
    match family {
        "Git" => (
            "Exposed Git repository metadata",
            "Validated Git repository data is publicly readable",
        ),
        "Archive" | "Backup" => (
            "Exposed backup or source archive",
            "A signature-confirmed backup or source artifact is publicly readable",
        ),
        "Credentials" | "Cloud credentials" => (
            "Exposed credential file",
            "A recognizable credential file is publicly readable",
        ),
        "CI artifact" => (
            "Exposed CI artifact",
            "A recognizable CI configuration or build artifact is publicly readable",
        ),
        "Actuator" => (
            "Exposed Spring Actuator endpoint",
            "A validated Spring Actuator response is publicly readable",
        ),
        "API documentation" => (
            "Exposed API documentation",
            "Validated API documentation is publicly readable",
        ),
        "Runtime" => (
            "Exposed runtime information",
            "Validated runtime or diagnostic information is publicly readable",
        ),
        _ => (
            "Exposed configuration artifact",
            "A recognizable configuration artifact is publicly readable",
        ),
    }
}

fn valid_dotenv(text: &str) -> bool {
    text.lines()
        .filter(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return false;
            }
            let Some((key, _)) = line.split_once('=') else {
                return false;
            };
            key.bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
                && [
                    "APP_",
                    "DB_",
                    "DATABASE_",
                    "AWS_",
                    "AZURE_",
                    "GOOGLE_",
                    "SECRET",
                    "PASSWORD",
                    "API_KEY",
                ]
                .iter()
                .any(|prefix| key.starts_with(prefix))
        })
        .count()
        >= 1
}

fn json_config_signature(json: &serde_json::Value) -> bool {
    json.as_object().is_some_and(|object| {
        [
            "ConnectionStrings",
            "Logging",
            "AllowedHosts",
            "Kestrel",
            "Authentication",
            "Database",
        ]
        .iter()
        .filter(|key| object.keys().any(|name| name.eq_ignore_ascii_case(key)))
        .count()
            >= 2
    })
}

fn valid_properties(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower
        .lines()
        .filter(|line| {
            let line = line.trim();
            line.starts_with("spring.") && (line.contains('=') || line.contains(':'))
        })
        .count()
        >= 2
}

fn valid_ci(path: &str, text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if path.eq_ignore_ascii_case("/Jenkinsfile") {
        return lower.contains("pipeline {") || lower.contains("node {");
    }
    let markers = [
        "stages:",
        "jobs:",
        "steps:",
        "script:",
        "image:",
        "trigger:",
        "pipelines:",
        "version:",
        "phases:",
    ];
    markers
        .iter()
        .filter(|marker| {
            lower
                .lines()
                .any(|line| line.trim_start().starts_with(**marker))
        })
        .count()
        >= 2
}

fn valid_archive(path: &str, body: &[u8]) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".zip") {
        body.starts_with(b"PK\x03\x04")
            || body.starts_with(b"PK\x05\x06")
            || body.starts_with(b"PK\x07\x08")
    } else if lower.ends_with(".7z") {
        body.starts_with(b"7z\xBC\xAF\x27\x1C")
    } else if lower.ends_with(".tar") {
        body.get(257..262) == Some(b"ustar")
    } else if lower.ends_with(".tgz")
        || lower.ends_with(".gz")
        || lower.ends_with(".gzip")
        || lower.ends_with(".tar.gz")
    {
        body.starts_with(&[0x1f, 0x8b])
    } else {
        false
    }
}

fn valid_actuator(kind: ActuatorKind, response: &HttpObservation) -> bool {
    if matches!(kind, ActuatorKind::Prometheus) {
        let text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
        return text.contains("# help ") && text.contains("# type ")
            || header_values(response, "content-type")
                .any(|value| value.to_ascii_lowercase().contains("openmetrics"));
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&response.body) else {
        return false;
    };
    match kind {
        ActuatorKind::Env => {
            json.get("propertySources").is_some() || json.get("activeProfiles").is_some()
        }
        ActuatorKind::ConfigProps => json.get("contexts").is_some(),
        ActuatorKind::Beans => {
            json.get("contexts").is_some()
                && response.body.windows(7).any(|value| value == b"\"beans\"")
        }
        ActuatorKind::Mappings => {
            json.get("contexts").is_some()
                && response
                    .body
                    .windows(10)
                    .any(|value| value == b"\"mappings\"")
        }
        ActuatorKind::ScheduledTasks => ["cron", "fixedDelay", "fixedRate", "custom"]
            .iter()
            .any(|key| json.get(key).is_some()),
        ActuatorKind::Caches => json.get("cacheManagers").is_some(),
        ActuatorKind::Conditions => {
            json.get("contexts").is_some()
                && (response
                    .body
                    .windows(17)
                    .any(|value| value == b"\"positiveMatches\"")
                    || response
                        .body
                        .windows(17)
                        .any(|value| value == b"\"negativeMatches\""))
        }
        ActuatorKind::Loggers => json.get("levels").is_some() && json.get("loggers").is_some(),
        ActuatorKind::ThreadDump => json
            .get("threads")
            .and_then(|value| value.as_array())
            .is_some(),
        ActuatorKind::Info => json.as_object().is_some_and(|value| !value.is_empty()),
        ActuatorKind::Prometheus => false,
    }
}

fn looks_like_html(body: &[u8]) -> bool {
    let start = String::from_utf8_lossy(&body[..body.len().min(256)])
        .trim_start()
        .to_ascii_lowercase();
    start.starts_with("<!doctype html") || start.starts_with("<html")
}

fn is_textual_exposure(probe: &ExposureProbe) -> bool {
    !matches!(
        probe.signature,
        ExposureSignature::Archive | ExposureSignature::GitIndex | ExposureSignature::VimSwap
    ) && (!matches!(probe.signature, ExposureSignature::RailsCredentials)
        || !probe.path.ends_with(".enc"))
}

fn git_object_id(value: &str) -> Option<String> {
    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn first_git_object_id(body: &[u8]) -> Option<String> {
    std::str::from_utf8(body).ok()?.lines().find_map(|line| {
        line.trim_start_matches('^')
            .split_ascii_whitespace()
            .next()
            .and_then(git_object_id)
    })
}

fn safe_git_ref(value: &str) -> bool {
    value.starts_with("refs/")
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
}

fn valid_loose_git_object(body: &[u8]) -> bool {
    let mut output = Vec::new();
    let mut decoder = ZlibDecoder::new(body).take((MAX_HTTP_BODY_BYTES + 1) as u64);
    if decoder.read_to_end(&mut output).is_err() || output.len() > MAX_HTTP_BODY_BYTES {
        return false;
    }
    let Some(nul) = output.iter().position(|byte| *byte == 0) else {
        return false;
    };
    let Ok(header) = std::str::from_utf8(&output[..nul]) else {
        return false;
    };
    let Some((kind, size)) = header.split_once(' ') else {
        return false;
    };
    matches!(kind, "blob" | "tree" | "commit" | "tag")
        && size.parse::<usize>().ok() == Some(output.len().saturating_sub(nul + 1))
}

fn redirect_chain_preserves_path(chain: &[HttpObservation], requested: &str) -> bool {
    chain.iter().all(|response| {
        Url::parse(&response.url)
            .ok()
            .is_some_and(|url| url.path().eq_ignore_ascii_case(requested))
    })
}

fn redirects_to_login(chain: &[HttpObservation]) -> bool {
    chain.iter().any(|response| {
        response
            .redirect_location
            .as_deref()
            .is_some_and(|location| {
                let lower = location.to_ascii_lowercase();
                lower.contains("login") || lower.contains("signin") || lower.contains("/auth")
            })
    })
}

async fn audit_management_http(
    endpoint: &mut EndpointScan,
    scheme: &str,
    context: ProbeContext<'_>,
    cookie_jar: Option<&Mutex<EndpointCookieJar>>,
) {
    if let Some(path) = management_probe_path(context.port) {
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
            && (matches!(response.status, 401 | 403) || redirects_to_login(&chain))
        {
            endpoint.evidence.push(format!(
                "Protected management endpoint evidence: {path} returned {}",
                response.status
            ));
        }
        endpoint.http.extend(chain);
    }
    if context.scan.request.security_operations && !context.scan.cancel.is_cancelled() {
        audit_fingerprinted_management_products(endpoint, scheme, context, cookie_jar).await;
    }
}

#[derive(Clone, Copy)]
enum ManagementProductKind {
    Jenkins,
    Grafana,
    ArgoCd,
    KubernetesDashboard,
    Jupyter,
    Airflow,
    PgAdmin,
    Portainer,
}

struct ManagementProductProbe {
    kind: ManagementProductKind,
    product: &'static str,
    fingerprint_path: &'static str,
    listing_path: &'static str,
    listing_name: &'static str,
}

const MANAGEMENT_PRODUCT_PROBES: &[ManagementProductProbe] = &[
    ManagementProductProbe {
        kind: ManagementProductKind::Jenkins,
        product: "Jenkins",
        fingerprint_path: "/",
        listing_path: "/api/json?tree=jobs[name,url]",
        listing_name: "jobs",
    },
    ManagementProductProbe {
        kind: ManagementProductKind::Grafana,
        product: "Grafana",
        fingerprint_path: "/api/health",
        listing_path: "/api/search?type=dash-db",
        listing_name: "dashboards",
    },
    ManagementProductProbe {
        kind: ManagementProductKind::ArgoCd,
        product: "Argo CD",
        fingerprint_path: "/api/version",
        listing_path: "/api/v1/applications",
        listing_name: "applications",
    },
    ManagementProductProbe {
        kind: ManagementProductKind::KubernetesDashboard,
        product: "Kubernetes Dashboard",
        fingerprint_path: "/",
        listing_path: "/api/v1/workload/default",
        listing_name: "workloads",
    },
    ManagementProductProbe {
        kind: ManagementProductKind::Jupyter,
        product: "Jupyter",
        fingerprint_path: "/tree",
        listing_path: "/api/sessions",
        listing_name: "sessions and notebooks",
    },
    ManagementProductProbe {
        kind: ManagementProductKind::Airflow,
        product: "Apache Airflow",
        fingerprint_path: "/login/",
        listing_path: "/api/v1/dags?limit=100",
        listing_name: "DAGs",
    },
    ManagementProductProbe {
        kind: ManagementProductKind::PgAdmin,
        product: "pgAdmin",
        fingerprint_path: "/login?next=/",
        listing_path: "/browser/server/obj/",
        listing_name: "registered servers",
    },
    ManagementProductProbe {
        kind: ManagementProductKind::Portainer,
        product: "Portainer",
        fingerprint_path: "/api/status",
        listing_path: "/api/endpoints",
        listing_name: "endpoints",
    },
];

async fn audit_fingerprinted_management_products(
    endpoint: &mut EndpointScan,
    scheme: &str,
    context: ProbeContext<'_>,
    cookie_jar: Option<&Mutex<EndpointCookieJar>>,
) {
    for probe in MANAGEMENT_PRODUCT_PROBES {
        if context.scan.cancel.is_cancelled() {
            return;
        }
        let existing = endpoint
            .http
            .iter()
            .find(|response| management_fingerprint(probe.kind, response));
        let mut fingerprint_chain = Vec::new();
        let fingerprint = if let Some(response) = existing {
            Some(response.clone())
        } else {
            fingerprint_chain = request_http_chain_with_cookies(
                context,
                scheme,
                "GET",
                probe.fingerprint_path,
                &[],
                cookie_jar,
            )
            .await
            .unwrap_or_default();
            fingerprint_chain
                .iter()
                .find(|response| management_fingerprint(probe.kind, response))
                .cloned()
        };
        endpoint.http.extend(fingerprint_chain);
        let Some(fingerprint) = fingerprint else {
            continue;
        };
        let version = management_version(probe.kind, &fingerprint);
        add_product(
            endpoint,
            probe.product,
            ProductLayer::Server,
            version,
            Confidence::High,
            format!(
                "Conservative {} root/login/version signature",
                probe.product
            ),
        );
        let chain = request_http_chain_with_cookies(
            context,
            scheme,
            "GET",
            probe.listing_path,
            &[],
            cookie_jar,
        )
        .await
        .unwrap_or_default();
        if let Some(response) = chain.last() {
            if matches!(response.status, 401 | 403) || redirects_to_login(&chain) {
                endpoint.evidence.push(format!(
                    "Protected {} management evidence: {} returned {}",
                    probe.product, probe.listing_path, response.status
                ));
            } else if (200..300).contains(&response.status)
                && validated_management_listing(probe.kind, response)
            {
                endpoint.findings.push(finding(
                    endpoint,
                    &format!("Unauthenticated {} management data", probe.product),
                    &format!(
                        "The {} interface returned validated {} data without authentication",
                        probe.product, probe.listing_name
                    ),
                    vec![
                        format!(
                            "GET {} returned {} without authentication",
                            probe.listing_path, response.status
                        ),
                        format!("Validated {} listing structure", probe.listing_name),
                    ],
                ));
            }
        }
        endpoint.http.extend(chain);
    }
}

fn management_fingerprint(kind: ManagementProductKind, response: &HttpObservation) -> bool {
    let text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    let json = serde_json::from_slice::<serde_json::Value>(&response.body).ok();
    match kind {
        ManagementProductKind::Jenkins => {
            header_values(response, "x-jenkins").next().is_some()
                || text.contains("dashboard [jenkins]")
                || text.contains("jenkins.io") && text.contains("login")
        }
        ManagementProductKind::Grafana => {
            text.contains("grafanabootdata")
                || text.contains("<title>grafana</title>")
                || json.as_ref().is_some_and(|json| {
                    json.get("database").is_some()
                        && (json.get("version").is_some() || json.get("commit").is_some())
                })
        }
        ManagementProductKind::ArgoCd => {
            text.contains("<title>argo cd</title>")
                || text.contains("argocd") && text.contains("login")
                || json.as_ref().is_some_and(|json| {
                    json.get("Version").is_some()
                        && (json.get("GitCommit").is_some() || json.get("BuildDate").is_some())
                })
        }
        ManagementProductKind::KubernetesDashboard => {
            text.contains("kubernetes dashboard")
                && (text.contains("<title") || text.contains("login"))
        }
        ManagementProductKind::Jupyter => {
            (text.contains("jupyter notebook") || text.contains("jupyterlab"))
                && (text.contains("<title") || text.contains("login"))
                || header_values(response, "x-jupyter-version")
                    .next()
                    .is_some()
        }
        ManagementProductKind::Airflow => {
            text.contains("apache airflow") && (text.contains("<title") || text.contains("login"))
        }
        ManagementProductKind::PgAdmin => {
            text.contains("pgadmin 4") && (text.contains("<title") || text.contains("login"))
        }
        ManagementProductKind::Portainer => {
            text.contains("portainer") && (text.contains("<title") || text.contains("login"))
                || json.as_ref().is_some_and(|json| {
                    json.get("Version").is_some() && json.get("InstanceID").is_some()
                })
        }
    }
}

fn management_version(kind: ManagementProductKind, response: &HttpObservation) -> Option<String> {
    match kind {
        ManagementProductKind::Jenkins => header_values(response, "x-jenkins")
            .next()
            .map(str::to_owned),
        _ => {
            let json = serde_json::from_slice::<serde_json::Value>(&response.body).ok()?;
            ["version", "Version"].iter().find_map(|key| {
                json.get(key)
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
            })
        }
    }
}

fn validated_management_listing(kind: ManagementProductKind, response: &HttpObservation) -> bool {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&response.body) else {
        return false;
    };
    match kind {
        ManagementProductKind::Jenkins => json
            .get("jobs")
            .and_then(|value| value.as_array())
            .is_some_and(|items| !items.is_empty()),
        ManagementProductKind::Grafana => json.as_array().is_some_and(|items| {
            !items.is_empty()
                && items
                    .iter()
                    .all(|item| item.get("uid").is_some() || item.get("title").is_some())
        }),
        ManagementProductKind::ArgoCd => json
            .get("items")
            .and_then(|value| value.as_array())
            .is_some_and(|items| {
                !items.is_empty() && items.iter().all(|item| item.get("metadata").is_some())
            }),
        ManagementProductKind::KubernetesDashboard => json.as_object().is_some_and(|object| {
            [
                "pods",
                "deployments",
                "replicaSets",
                "statefulSets",
                "daemonSets",
            ]
            .iter()
            .any(|key| object.contains_key(*key))
        }),
        ManagementProductKind::Jupyter => json.as_array().is_some_and(|items| {
            !items.is_empty()
                && items.iter().all(|item| {
                    item.get("id").is_some()
                        && (item.get("notebook").is_some() || item.get("path").is_some())
                })
        }),
        ManagementProductKind::Airflow => json
            .get("dags")
            .and_then(|value| value.as_array())
            .is_some_and(|items| !items.is_empty()),
        ManagementProductKind::PgAdmin => {
            json.get("data").is_some_and(|data| {
                data.as_array().is_some_and(|items| !items.is_empty())
                    || data.as_object().is_some_and(|items| !items.is_empty())
            }) && (json.get("success").and_then(|value| value.as_bool()) == Some(true)
                || json.get("status").is_some())
        }
        ManagementProductKind::Portainer => json.as_array().is_some_and(|items| {
            !items.is_empty()
                && items
                    .iter()
                    .all(|item| item.get("Id").is_some() && item.get("Name").is_some())
        }),
    }
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
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum CorsAllowMode {
    None,
    Wildcard,
    Reflected,
    Other,
}

#[derive(Clone, Debug)]
struct CorsSample {
    path: String,
    url: String,
    origin_kind: &'static str,
    method: &'static str,
    status: u16,
    mode: CorsAllowMode,
    credentials: bool,
    methods: BTreeSet<String>,
    headers: BTreeSet<String>,
    vary_origin: bool,
}

impl CorsSample {
    fn allowed(&self) -> bool {
        matches!(
            self.mode,
            CorsAllowMode::Wildcard | CorsAllowMode::Reflected
        )
    }
}

async fn run_cors_matrix_for_path(
    endpoint: &mut EndpointScan,
    scheme: &str,
    path: &str,
    origins: &[(&'static str, String)],
    context: ProbeContext<'_>,
    cookie_jar: Option<&Mutex<EndpointCookieJar>>,
) -> Vec<CorsSample> {
    let mut samples = Vec::new();
    for (origin_kind, origin) in origins {
        if context.scan.cancel.is_cancelled() {
            break;
        }
        for method in ["GET", "OPTIONS"] {
            let headers = if method == "OPTIONS" {
                vec![
                    ("Origin", origin.as_str()),
                    ("Access-Control-Request-Method", "PUT"),
                    (
                        "Access-Control-Request-Headers",
                        "Authorization, X-Nancy-Probe",
                    ),
                ]
            } else {
                vec![("Origin", origin.as_str())]
            };
            let chain = request_http_chain_with_cookies(
                context, scheme, method, path, &headers, cookie_jar,
            )
            .await
            .unwrap_or_default();
            if let Some(response) = chain.last() {
                samples.push(cors_sample(path, origin_kind, origin, method, response));
            }
            endpoint.http.extend(chain);
        }
    }
    samples
}

fn cors_sample(
    path: &str,
    origin_kind: &'static str,
    origin: &str,
    method: &'static str,
    response: &HttpObservation,
) -> CorsSample {
    let allow_origins = header_values(response, "access-control-allow-origin")
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let mode = if allow_origins.iter().any(|value| *value == "*") {
        CorsAllowMode::Wildcard
    } else if allow_origins
        .iter()
        .any(|value| value.eq_ignore_ascii_case(origin))
    {
        CorsAllowMode::Reflected
    } else if allow_origins.is_empty() {
        CorsAllowMode::None
    } else {
        CorsAllowMode::Other
    };
    CorsSample {
        path: path.to_owned(),
        url: safe_http_url(&response.url),
        origin_kind,
        method,
        status: response.status,
        mode,
        credentials: header_values(response, "access-control-allow-credentials")
            .any(|value| value.trim().eq_ignore_ascii_case("true")),
        methods: csv_header_tokens(response, "access-control-allow-methods"),
        headers: csv_header_tokens(response, "access-control-allow-headers"),
        vary_origin: header_values(response, "vary")
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case("origin")),
    }
}

fn csv_header_tokens(response: &HttpObservation, name: &str) -> BTreeSet<String> {
    header_values(response, name)
        .flat_map(|value| value.split(','))
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn add_cors_sample_findings(endpoint: &mut EndpointScan, samples: &[CorsSample], advanced: bool) {
    for sample in samples {
        let evidence = format!(
            "{} {} returned {}; tested {} origin",
            sample.method, sample.url, sample.status, sample.origin_kind
        );
        match sample.mode {
            CorsAllowMode::Wildcard => endpoint.findings.push(finding(
                endpoint,
                "Wildcard CORS origin is allowed",
                "The response permits requests from every web origin",
                vec![evidence.clone()],
            )),
            CorsAllowMode::Reflected if sample.origin_kind == "null" => {
                endpoint.findings.push(finding(
                    endpoint,
                    "Null CORS origin is allowed",
                    "The response permits the opaque null origin",
                    vec![evidence.clone()],
                ));
            }
            CorsAllowMode::Reflected if sample.credentials => endpoint.findings.push(finding(
                endpoint,
                "Arbitrary CORS origin reflected with credentials",
                "The server reflects an untrusted origin while allowing credentials",
                vec![
                    evidence.clone(),
                    "Access-Control-Allow-Credentials: true".to_owned(),
                ],
            )),
            CorsAllowMode::Reflected if sample.origin_kind == "arbitrary" => {
                endpoint.findings.push(finding(
                    endpoint,
                    "Arbitrary CORS origin is reflected",
                    "The server reflects an untrusted origin without credential access",
                    vec![evidence.clone()],
                ));
            }
            _ => {}
        }
        if sample.mode == CorsAllowMode::Reflected && !sample.vary_origin {
            endpoint.findings.push(finding(
                endpoint,
                "CORS response omits Vary: Origin",
                "A dynamic allow-origin response can be incorrectly reused by shared caches",
                vec![evidence.clone()],
            ));
        }
        if advanced
            && sample.mode == CorsAllowMode::Reflected
            && matches!(sample.origin_kind, "hostname-prefix" | "hostname-suffix")
        {
            endpoint.findings.push(finding(
                endpoint,
                "CORS hostname validation is bypassable",
                "The allow-origin policy accepted an attacker-controlled hostname containing the trusted hostname",
                vec![evidence],
            ));
        }
    }
    if advanced {
        for get in samples.iter().filter(|sample| sample.method == "GET") {
            let Some(preflight) = samples.iter().find(|sample| {
                sample.method == "OPTIONS"
                    && sample.path == get.path
                    && sample.origin_kind == get.origin_kind
            }) else {
                continue;
            };
            let methods_conflict = !get.methods.is_empty()
                && !preflight.methods.is_empty()
                && get.methods != preflight.methods;
            let headers_conflict = !get.headers.is_empty()
                && !preflight.headers.is_empty()
                && get.headers != preflight.headers;
            if get.mode != preflight.mode
                || get.credentials != preflight.credentials
                || methods_conflict
                || headers_conflict
            {
                endpoint.findings.push(finding(
                    endpoint,
                    "CORS GET and preflight policies are inconsistent",
                    "GET and preflight responses apply materially different CORS policies",
                    vec![format!(
                        "GET and OPTIONS differ at {} for {} origin",
                        get.path, get.origin_kind
                    )],
                ));
            }
        }
    }
}

fn safe_http_url(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return value.chars().take(512).collect();
    };
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

pub(super) async fn audit_advanced_browser_and_cors(
    endpoints: &mut [EndpointScan],
    resources: &[CrawledResource],
    external_indicators: &[CrawlExternalIndicator],
    hostname: &str,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
    client_certificate: Option<&LoadedClientCertificate>,
) {
    let origins = [
        ("arbitrary", "https://nancy-exposure.invalid".to_owned()),
        ("null", "null".to_owned()),
        (
            "hostname-prefix",
            format!(
                "https://{}.nancy-exposure.invalid",
                hostname.trim_end_matches('.')
            ),
        ),
        (
            "hostname-suffix",
            format!("https://nancy-exposure-{}", hostname.trim_end_matches('.')),
        ),
    ];
    let external_origins = concrete_external_origins(external_indicators);
    for endpoint in endpoints.iter_mut() {
        if cancel.is_cancelled() {
            return;
        }
        let Some(scheme) = endpoint_scheme(endpoint) else {
            continue;
        };
        let scan = ScanContext {
            hostname,
            request,
            cancel,
            limiter,
            client_certificate: client_certificate
                .filter(|certificate| certificate.applies_to(hostname)),
        };
        let context = ProbeContext {
            ip: endpoint.ip,
            port: endpoint.port,
            scan,
        };
        let mut paths = vec!["/".to_owned()];
        for resource in resources.iter().filter(|resource| {
            resource.ip == endpoint.ip
                && resource.port == endpoint.port
                && resource
                    .status
                    .is_some_and(|status| (200..300).contains(&status))
                && api_like_resource(resource)
        }) {
            let Ok(url) = Url::parse(&resource.url) else {
                continue;
            };
            let path = url_path(&url);
            if !paths.contains(&path) {
                paths.push(path);
            }
            if paths.len() == 12 {
                break;
            }
        }
        let mut root_samples = Vec::new();
        for path in &paths {
            let samples =
                run_cors_matrix_for_path(endpoint, scheme, path, &origins, context, None).await;
            add_cors_sample_findings(endpoint, &samples, true);
            if path == "/" {
                root_samples = samples;
            } else if cors_policy_weaker(&root_samples, &samples) {
                endpoint.findings.push(finding(
                    endpoint,
                    "CORS policy is weaker on an API endpoint",
                    "A tested API-like endpoint applies a materially weaker policy than the origin root",
                    vec![format!("Weaker CORS policy at {scheme}://{hostname}:{}{path}", endpoint.port)],
                ));
            }
        }
        let api_paths = paths.iter().take(4).cloned().collect::<Vec<_>>();
        let mut checked_dns = HashSet::new();
        for origin in external_origins.iter().take(8) {
            for path in &api_paths {
                if cancel.is_cancelled() {
                    return;
                }
                let chain = request_http_chain_with_cookies(
                    context,
                    scheme,
                    "GET",
                    path,
                    &[("Origin", origin.as_str())],
                    None,
                )
                .await
                .unwrap_or_default();
                let trusted = chain
                    .last()
                    .map(|response| cors_sample(path, "external", origin, "GET", response))
                    .is_some_and(|sample| sample.allowed());
                endpoint.http.extend(chain);
                if trusted
                    && checked_dns.insert(origin.clone())
                    && let Some((host, cname, provider)) =
                        dangling_provider_origin(origin, cancel).await
                {
                    endpoint.findings.push(finding(
                        endpoint,
                        "Potential CORS-trusted DNS takeover",
                        "A CORS-trusted external origin terminates at a recognized dangling service-provider CNAME",
                        vec![format!(
                            "Trusted origin {origin}; hostname {host}; provider {provider}; terminal CNAME {cname}; registration was not attempted"
                        )],
                    ));
                }
            }
        }
    }
}

fn endpoint_scheme(endpoint: &EndpointScan) -> Option<&'static str> {
    if endpoint
        .http
        .iter()
        .any(|response| response.url.starts_with("https://"))
    {
        Some("https")
    } else if endpoint
        .http
        .iter()
        .any(|response| response.url.starts_with("http://"))
    {
        Some("http")
    } else {
        None
    }
}

fn api_like_resource(resource: &CrawledResource) -> bool {
    resource
        .content_type
        .as_deref()
        .is_some_and(|content_type| content_type.to_ascii_lowercase().contains("json"))
        || Url::parse(&resource.url).ok().is_some_and(|url| {
            let path = url.path().to_ascii_lowercase();
            [
                "/api/", "/api", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/",
            ]
            .iter()
            .any(|marker| path.contains(marker))
        })
}

fn cors_policy_weaker(root: &[CorsSample], candidate: &[CorsSample]) -> bool {
    candidate.iter().any(|sample| {
        let Some(reference) = root.iter().find(|reference| {
            reference.origin_kind == sample.origin_kind && reference.method == sample.method
        }) else {
            return false;
        };
        sample.allowed() && !reference.allowed()
            || sample.credentials && !reference.credentials
            || sample.mode == CorsAllowMode::Wildcard && reference.mode != CorsAllowMode::Wildcard
            || !reference.methods.is_empty() && !sample.methods.is_subset(&reference.methods)
            || !reference.headers.is_empty() && !sample.headers.is_subset(&reference.headers)
    })
}

fn concrete_external_origins(indicators: &[CrawlExternalIndicator]) -> Vec<String> {
    let mut origins = BTreeSet::new();
    for indicator in indicators {
        let Ok(url) = Url::parse(&indicator.value) else {
            continue;
        };
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.host_str().is_some_and(|host| host.contains('*'))
        {
            continue;
        }
        origins.insert(url.origin().ascii_serialization());
        if origins.len() == 8 {
            break;
        }
    }
    origins.into_iter().collect()
}

async fn dangling_provider_origin(
    origin: &str,
    cancel: &CancellationToken,
) -> Option<(String, String, &'static str)> {
    const PROVIDERS: &[(&str, &str)] = &[
        ("s3.amazonaws.com", "Amazon S3"),
        ("azurewebsites.net", "Azure App Service"),
        ("cloudapp.net", "Azure Cloud App"),
        ("github.io", "GitHub Pages"),
        ("herokudns.com", "Heroku"),
        ("netlify.app", "Netlify"),
        ("netlify.com", "Netlify"),
        ("vercel-dns.com", "Vercel"),
        ("fastly.net", "Fastly"),
        ("zendesk.com", "Zendesk"),
        ("readme.io", "ReadMe"),
        ("pantheonsite.io", "Pantheon"),
        ("ghost.io", "Ghost"),
    ];
    let url = Url::parse(origin).ok()?;
    let host = url.host_str()?.trim_end_matches('.').to_owned();
    if host.parse::<IpAddr>().is_ok() || cancel.is_cancelled() {
        return None;
    }
    let mut current = host.clone();
    let mut terminal_cname = None;
    let mut seen = HashSet::new();
    for _ in 0..8 {
        if !seen.insert(current.clone()) || cancel.is_cancelled() {
            return None;
        }
        let mut trace = crate::diagnostics::DnsTrace::default();
        tokio::select! {
            _ = cancel.cancelled() => return None,
            result = crate::request::resolve_host(&current, &mut trace) => result.ok()?,
        }
        if !trace.addresses.is_empty() {
            return None;
        }
        let nxdomain = trace.attempts.iter().any(|attempt| {
            attempt
                .response_code
                .as_deref()
                .is_some_and(|code| code.eq_ignore_ascii_case("NXDomain"))
        });
        let next = trace
            .records
            .iter()
            .rev()
            .find(|record| record.record_type.eq_ignore_ascii_case("CNAME"))
            .map(|record| record.value.trim_end_matches('.').to_ascii_lowercase());
        if let Some(next) = next {
            terminal_cname = Some(next.clone());
            current = next;
            continue;
        }
        if !nxdomain {
            return None;
        }
        let cname = terminal_cname?;
        return PROVIDERS.iter().find_map(|(suffix, provider)| {
            (cname == *suffix || cname.ends_with(&format!(".{suffix}")))
                .then(|| (host.clone(), cname.clone(), *provider))
        });
    }
    None
}

pub(super) fn header_values<'a>(
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

pub(super) async fn single_http_request_with_limit(
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
    let started = Instant::now();
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
        let (bytes, framing) = read_http_response(&mut stream, method, body_limit).await?;
        let mut response = parse_http_response(method, bytes, tls_unverified, body_limit, framing)?;
        response.duration_ms = started.elapsed().as_secs_f64() * 1_000.0;
        Ok(response)
    };
    tokio::select! {
        _ = context.scan.cancel.cancelled() => Err("Scan cancelled".to_owned()),
        result = tokio::time::timeout(context.scan.request.probe_timeout, operation) => {
            result.map_err(|_| "HTTP probe timed out".to_owned())?
        }
    }
}

pub(super) async fn active_http_request(
    context: ProbeContext<'_>,
    scheme: &str,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    cookie_header: Option<&str>,
    host_override: Option<&str>,
) -> Result<HttpObservation, String> {
    let valid_token = |value: &str| {
        !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
    };
    if !matches!(scheme, "http" | "https") {
        return Err("Active request scheme must be HTTP or HTTPS".to_owned());
    }
    if !valid_token(method) {
        return Err("Active request method is invalid".to_owned());
    }
    if !(path == "*" || path.starts_with('/'))
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err("Active request target is invalid".to_owned());
    }
    if !headers.iter().all(|(name, value)| {
        valid_token(name)
            && !matches!(
                name.to_ascii_lowercase().as_str(),
                "host" | "content-length" | "transfer-encoding" | "connection"
            )
            && !value.bytes().any(|byte| {
                byte == b'\r' || byte == b'\n' || (byte.is_ascii_control() && byte != b'\t')
            })
    }) {
        return Err("Active request contains an unsafe header name or value".to_owned());
    }
    if cookie_header.is_some_and(|value| value.bytes().any(|byte| byte.is_ascii_control()))
        || host_override.is_some_and(|value| {
            value.is_empty()
                || value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b' ')
        })
    {
        return Err("Active request contains an unsafe cookie or Host value".to_owned());
    }
    let started = Instant::now();
    let operation = async {
        let (mut stream, tls_unverified) = connect_http_stream(context, scheme).await?;
        let host = host_override
            .map(str::to_owned)
            .unwrap_or_else(|| host_header(context.scan.hostname, context.port, scheme));
        let mut bytes = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nancywebdebug-active/{}\r\nAccept: */*\r\nConnection: close\r\n",
            env!("CARGO_PKG_VERSION")
        )
        .into_bytes();
        for (name, value) in headers {
            bytes.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(value.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        if let Some(cookie) = cookie_header {
            bytes.extend_from_slice(b"Cookie: ");
            bytes.extend_from_slice(cookie.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(body);
        stream
            .write_all(&bytes)
            .await
            .map_err(|error| error.to_string())?;
        stream.flush().await.map_err(|error| error.to_string())?;
        let (response_bytes, framing) =
            read_http_response(&mut stream, method, MAX_HTTP_BODY_BYTES).await?;
        let mut response = parse_http_response(
            method,
            response_bytes,
            tls_unverified,
            MAX_HTTP_BODY_BYTES,
            framing,
        )?;
        response.duration_ms = started.elapsed().as_secs_f64() * 1_000.0;
        Ok(response)
    };
    tokio::select! {
        _ = context.scan.cancel.cancelled() => Err("Scan cancelled".to_owned()),
        result = tokio::time::timeout(context.scan.request.probe_timeout, operation) => {
            result.map_err(|_| "Active HTTP probe timed out".to_owned())?
        }
    }
}

pub(super) async fn active_raw_http_exchange(
    context: ProbeContext<'_>,
    scheme: &str,
    request: &[u8],
) -> Result<(Vec<u8>, f64, bool), String> {
    if !matches!(scheme, "http" | "https") {
        return Err("Raw request scheme must be HTTP or HTTPS".to_owned());
    }
    if request.len() > 128 * 1024 {
        return Err("Raw request exceeds the 128 KiB limit".to_owned());
    }
    let started = Instant::now();
    let operation = async {
        let (mut stream, _) = connect_http_stream(context, scheme).await?;
        stream
            .write_all(request)
            .await
            .map_err(|error| error.to_string())?;
        stream.flush().await.map_err(|error| error.to_string())?;
        let mut output = Vec::new();
        let mut buffer = [0u8; 8192];
        let mut peer_closed = false;
        loop {
            match tokio::time::timeout(Duration::from_millis(750), stream.read(&mut buffer)).await {
                Ok(Ok(0)) => {
                    peer_closed = true;
                    break;
                }
                Err(_) => break,
                Ok(Ok(length)) => {
                    output.extend_from_slice(&buffer[..length]);
                    if output.len() > MAX_HTTP_HEADER_BYTES + MAX_HTTP_BODY_BYTES {
                        output.truncate(MAX_HTTP_HEADER_BYTES + MAX_HTTP_BODY_BYTES);
                        break;
                    }
                }
                Ok(Err(error)) => return Err(error.to_string()),
            }
        }
        Ok((output, peer_closed))
    };
    tokio::select! {
        _ = context.scan.cancel.cancelled() => Err("Scan cancelled".to_owned()),
        result = tokio::time::timeout(context.scan.request.probe_timeout, operation) => {
            result
                .map_err(|_| "Raw HTTP probe timed out".to_owned())?
                .map(|(bytes, peer_closed)| {
                    (
                        bytes,
                        started.elapsed().as_secs_f64() * 1_000.0,
                        peer_closed,
                    )
                })
        }
    }
}

pub(super) async fn websocket_upgrade_exchange(
    context: ProbeContext<'_>,
    scheme: &str,
    request: &[u8],
) -> Result<Vec<u8>, String> {
    let operation = async {
        let (mut stream, _) = connect_http_stream(context, scheme).await?;
        stream
            .write_all(request)
            .await
            .map_err(|error| error.to_string())?;
        stream.flush().await.map_err(|error| error.to_string())?;
        let mut output = Vec::new();
        let mut buffer = [0u8; 2048];
        loop {
            let length = stream
                .read(&mut buffer)
                .await
                .map_err(|error| error.to_string())?;
            if length == 0 {
                return Err("WebSocket upgrade response ended before its headers".to_owned());
            }
            output.extend_from_slice(&buffer[..length]);
            if let Some(end) = find_header_end(&output) {
                output.truncate(end);
                return Ok(output);
            }
            if output.len() > MAX_HTTP_HEADER_BYTES {
                return Err("WebSocket upgrade headers exceed 64 KiB".to_owned());
            }
        }
    };
    tokio::select! {
        _ = context.scan.cancel.cancelled() => Err("Scan cancelled".to_owned()),
        result = tokio::time::timeout(context.scan.request.probe_timeout, operation) => {
            result.map_err(|_| "WebSocket upgrade timed out".to_owned())?
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
        use_client_certificate: true,
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
) -> Result<(Vec<u8>, ResponseFraming), String> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut header_end = None;
    let mut framing = ResponseFraming::default();
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
            Err(_) if header_end.is_some() => {
                framing.read_timed_out = true;
                break;
            }
            Err(_) => return Err("HTTP response headers timed out".to_owned()),
        };
        if length == 0 {
            framing.completed = true;
            break;
        }
        if header_end.is_some() {
            framing.body_read_events += 1;
        }
        bytes.extend_from_slice(&buffer[..length]);
        if header_end.is_none() {
            header_end = find_header_end(&bytes);
            if let Some(end) = header_end
                && bytes.len() > end
            {
                framing.body_read_events += 1;
            }
            if header_end.is_none() && bytes.len() > MAX_HTTP_HEADER_BYTES {
                return Err("HTTP response headers exceed 64 KiB".to_owned());
            }
        }
        if let Some(end) = header_end {
            if method.eq_ignore_ascii_case("HEAD") {
                bytes.truncate(end);
                framing.completed = true;
                break;
            }
            let header_text = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
            let body_length = bytes.len().saturating_sub(end);
            if let Some(content_length) = parse_content_length(&header_text)
                && body_length >= content_length.min(body_limit + 1)
            {
                framing.completed = content_length <= body_limit;
                framing.body_limit_reached = content_length > body_limit;
                break;
            }
            if header_text.contains("transfer-encoding: chunked")
                && bytes[end..].windows(5).any(|window| window == b"0\r\n\r\n")
            {
                framing.completed = true;
                break;
            }
            if body_length > body_limit {
                framing.body_limit_reached = true;
                break;
            }
        }
    }
    Ok((bytes, framing))
}

fn parse_http_response(
    method: &str,
    bytes: Vec<u8>,
    tls_unverified: bool,
    body_limit: usize,
    mut framing: ResponseFraming,
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
    framing.transfer_chunked = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    });
    if framing.transfer_chunked
        && let Some((decoded, chunks, complete)) = decode_chunked(&body, body_limit)
    {
        body = decoded;
        framing.decoded_chunks = chunks;
        framing.completed |= complete;
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
        duration_ms: 0.0,
        framing,
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

fn decode_chunked(bytes: &[u8], body_limit: usize) -> Option<(Vec<u8>, usize, bool)> {
    let mut position = 0usize;
    let mut output = Vec::new();
    let mut chunks = 0usize;
    loop {
        if position >= bytes.len() {
            return (chunks > 0).then_some((output, chunks, false));
        }
        let Some(line_end) = bytes[position..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|line_end| line_end + position)
        else {
            return (chunks > 0).then_some((output, chunks, false));
        };
        let size_text = std::str::from_utf8(&bytes[position..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        position = line_end + 2;
        if size == 0 {
            return Some((output, chunks, true));
        }
        let end = position.checked_add(size)?;
        if end + 2 > bytes.len() {
            return (chunks > 0).then_some((output, chunks, false));
        }
        output.extend_from_slice(&bytes[position..end]);
        chunks += 1;
        if output.len() > body_limit {
            return Some((output, chunks, false));
        }
        position = end + 2;
    }
}

pub(super) fn url_host(hostname: &str) -> String {
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

pub(super) fn url_path(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    }
}
