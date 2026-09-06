#[path = "product_identification.rs"]
pub(super) mod product_identification;

use super::product_analysis::{
    response_is_soft_404, wordpress_api_response, wordpress_login_response,
};
use super::*;
use flate2::read::ZlibDecoder;
use std::borrow::Cow;
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
    endpoint.attempted = candidate.attempted;
    endpoint.connect_duration_ms = candidate.attempt.duration_ms;
    endpoint.state = {
        let (candidate,): (&TcpCandidate,) = (&candidate,);
        let inlined_result: PortState = {
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
        };
        inlined_result
    };
    endpoint.error = candidate.attempt.error.clone();
    if endpoint.state != PortState::Open {
        return endpoint;
    }
    let mut stream = candidate.stream.take().unwrap();
    endpoint.banner = ({
        let (stream, probe_timeout, cancel): (&mut TcpStream, Duration, &CancellationToken) = (
            &mut stream,
            context.scan.request.probe_timeout,
            context.scan.cancel,
        );
        async move {
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
    })
    .await;
    if !endpoint.banner.is_empty() {
        endpoint.evidence.push(format!(
            "Server-initiated banner: {}",
            escaped_evidence(&endpoint.banner)
        ));
    }
    ({
        let (endpoint,): (&mut EndpointScan,) = (&mut endpoint,);

        let banner = String::from_utf8_lossy(&endpoint.banner).into_owned();
        let lower = banner.to_ascii_lowercase();
        product_identification::record_text(endpoint, &banner, "Greeting");
        if banner.starts_with("SSH-") {
            ({
                let (endpoint, kind, confidence, evidence): (
                    &mut EndpointScan,
                    ServiceKind,
                    Confidence,
                    &str,
                ) = (
                    endpoint,
                    ServiceKind::Ssh,
                    Confidence::High,
                    "SSH identification banner",
                );

                if confidence >= endpoint.service_confidence {
                    endpoint.service = kind;
                    endpoint.service_confidence = confidence;
                }
                if !endpoint.evidence.iter().any(|item| item == evidence) {
                    endpoint.evidence.push(evidence.to_owned());
                }
            });
        } else if lower.starts_with("220") && lower.contains("ftp") {
            ({
                let (endpoint, kind, confidence, evidence): (
                    &mut EndpointScan,
                    ServiceKind,
                    Confidence,
                    &str,
                ) = (
                    endpoint,
                    ServiceKind::Ftp,
                    Confidence::High,
                    "FTP greeting banner",
                );

                if confidence >= endpoint.service_confidence {
                    endpoint.service = kind;
                    endpoint.service_confidence = confidence;
                }
                if !endpoint.evidence.iter().any(|item| item == evidence) {
                    endpoint.evidence.push(evidence.to_owned());
                }
            });
        } else if lower.starts_with("220") && (lower.contains("smtp") || lower.contains("esmtp")) {
            ({
                let (endpoint, kind, confidence, evidence): (
                    &mut EndpointScan,
                    ServiceKind,
                    Confidence,
                    &str,
                ) = (
                    endpoint,
                    ServiceKind::Smtp,
                    Confidence::High,
                    "SMTP greeting banner",
                );

                if confidence >= endpoint.service_confidence {
                    endpoint.service = kind;
                    endpoint.service_confidence = confidence;
                }
                if !endpoint.evidence.iter().any(|item| item == evidence) {
                    endpoint.evidence.push(evidence.to_owned());
                }
            });
        } else if lower.starts_with("+ok") {
            ({
                let (endpoint, kind, confidence, evidence): (
                    &mut EndpointScan,
                    ServiceKind,
                    Confidence,
                    &str,
                ) = (
                    endpoint,
                    ServiceKind::Pop3,
                    Confidence::High,
                    "POP3 greeting banner",
                );

                if confidence >= endpoint.service_confidence {
                    endpoint.service = kind;
                    endpoint.service_confidence = confidence;
                }
                if !endpoint.evidence.iter().any(|item| item == evidence) {
                    endpoint.evidence.push(evidence.to_owned());
                }
            });
        } else if lower.starts_with('*') && (lower.contains("imap") || lower.contains("capability"))
        {
            ({
                let (endpoint, kind, confidence, evidence): (
                    &mut EndpointScan,
                    ServiceKind,
                    Confidence,
                    &str,
                ) = (
                    endpoint,
                    ServiceKind::Imap,
                    Confidence::High,
                    "IMAP greeting banner",
                );

                if confidence >= endpoint.service_confidence {
                    endpoint.service = kind;
                    endpoint.service_confidence = confidence;
                }
                if !endpoint.evidence.iter().any(|item| item == evidence) {
                    endpoint.evidence.push(evidence.to_owned());
                }
            });
        } else if let Some(version) = mysql_banner_version(&endpoint.banner) {
            ({
                let (endpoint, kind, confidence, evidence): (
                    &mut EndpointScan,
                    ServiceKind,
                    Confidence,
                    &str,
                ) = (
                    endpoint,
                    ServiceKind::Mysql,
                    Confidence::High,
                    "MySQL-compatible handshake packet",
                );

                if confidence >= endpoint.service_confidence {
                    endpoint.service = kind;
                    endpoint.service_confidence = confidence;
                }
                if !endpoint.evidence.iter().any(|item| item == evidence) {
                    endpoint.evidence.push(evidence.to_owned());
                }
            });
            product_identification::record_mysql(endpoint, &version);
        } else if endpoint.banner.starts_with(b"RFB ") {
            ({
                let (endpoint, kind, confidence, evidence): (
                    &mut EndpointScan,
                    ServiceKind,
                    Confidence,
                    &str,
                ) = (
                    endpoint,
                    ServiceKind::Vnc,
                    Confidence::High,
                    "VNC RFB protocol banner",
                );

                if confidence >= endpoint.service_confidence {
                    endpoint.service = kind;
                    endpoint.service_confidence = confidence;
                }
                if !endpoint.evidence.iter().any(|item| item == evidence) {
                    endpoint.evidence.push(evidence.to_owned());
                }
            });
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
            ({
                let (endpoint, kind, confidence, evidence): (
                    &mut EndpointScan,
                    ServiceKind,
                    Confidence,
                    &str,
                ) = (
                    endpoint,
                    ServiceKind::Rsync,
                    Confidence::High,
                    "rsync daemon protocol banner",
                );

                if confidence >= endpoint.service_confidence {
                    endpoint.service = kind;
                    endpoint.service_confidence = confidence;
                }
                if !endpoint.evidence.iter().any(|item| item == evidence) {
                    endpoint.evidence.push(evidence.to_owned());
                }
            });
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
            ({
                let (endpoint, kind, confidence, evidence): (
                    &mut EndpointScan,
                    ServiceKind,
                    Confidence,
                    &str,
                ) = (
                    endpoint,
                    ServiceKind::Http,
                    Confidence::High,
                    "HTTP status line banner",
                );

                if confidence >= endpoint.service_confidence {
                    endpoint.service = kind;
                    endpoint.service_confidence = confidence;
                }
                if !endpoint.evidence.iter().any(|item| item == evidence) {
                    endpoint.evidence.push(evidence.to_owned());
                }
            });
        }
    });
    ({
        let (endpoint, context): (&mut EndpointScan, ProbeContext<'_>) = (&mut endpoint, context);
        async move {
            let payload = {
                let (port, hostname): (u16, &str) = (endpoint.port, context.scan.hostname);
                let inlined_result: Option<Cow<'static, [u8]>> = {
                    match port {
                        21 => Some(Cow::Borrowed(b"SYST\r\n")),
                        25 | 587 => Some(Cow::Borrowed(b"EHLO scanner.invalid\r\n")),
                        102 => Some(Cow::Borrowed(&[
                            3, 0, 0, 22, 17, 224, 0, 0, 0, 1, 0, 193, 2, 1, 0, 194, 2, 1, 2, 192,
                            1, 10,
                        ])),
                        110 => Some(Cow::Borrowed(b"CAPA\r\n")),
                        143 => Some(Cow::Borrowed(b"a001 CAPABILITY\r\n")),
                        502 => Some(Cow::Borrowed(&[0, 1, 0, 0, 0, 5, 255, 43, 14, 1, 0])),
                        2181 => Some(Cow::Borrowed(b"ruok")),
                        2404 => Some(Cow::Borrowed(&[104, 4, 67, 0, 0, 0])),
                        3389 => Some(Cow::Borrowed(&[
                            3, 0, 0, 19, 14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0,
                        ])),
                        4369 => Some(Cow::Borrowed(&[0, 1, b'n'])),
                        4840 => Some(Cow::Borrowed(
                            b"HELF\x3e\0\0\0\0\0\0\0\xff\xff\0\0\xff\xff\0\0\0\0\0\0\0\0\0\0\x1e\0\0\0opc.tcp://scanner.invalid:4840",
                        )),
                        5432 => Some(Cow::Borrowed(&[0, 0, 0, 8, 4, 210, 22, 47])),
                        6379 => Some(Cow::Borrowed(b"PING\r\n")),
                        8009 => Some(Cow::Borrowed(&[18, 52, 0, 1, 10])),
                        9042 => Some(Cow::Borrowed(&[4, 0, 0, 0, 5, 0, 0, 0, 0])),
                        9418 => Some(Cow::Owned({
                            let (hostname,): (&str,) = (hostname,);
                            let inlined_result: Vec<u8> = {
                                let command = format!(
                                    "git-upload-pack /nancy-exposure-probe\0host={hostname}\0"
                                );
                                format!("{:04x}{command}", command.len() + 4).into_bytes()
                            };
                            inlined_result
                        })),
                        9600 => Some(Cow::Borrowed(&[
                            b'F', b'I', b'N', b'S', 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ])),
                        11211 => Some(Cow::Borrowed(b"version\r\n")),
                        44818 => Some(Cow::Borrowed(&[
                            99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ])),
                        _ => None,
                    }
                };
                inlined_result
            };
            let Some(payload) = payload else {
                return;
            };
            let response = ({
let (context, payload,): (ProbeContext < '_ >, & [u8],) = (context, payload.as_ref(),);
async move {

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
}).await;
            if response.is_empty() {
                return;
            }
            ({
                let (endpoint, response): (&mut EndpointScan, &[u8]) = (endpoint, &response);

                let text = String::from_utf8_lossy(response);
                product_identification::record_text(endpoint, &text, "Guided response");
                let lower = text.to_ascii_lowercase();
                match endpoint.port {
                    21 if lower.starts_with("2") || lower.contains("ftp") => {
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::Ftp,
                                Confidence::High,
                                "FTP command response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
                    }
                    25 | 587 if lower.starts_with("220") || lower.starts_with("250") => {
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::Smtp,
                                Confidence::High,
                                "SMTP EHLO response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
                    }
                    110 if lower.starts_with("+ok") => {
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::Pop3,
                                Confidence::High,
                                "POP3 CAPA response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
                    }
                    143 if lower.starts_with('*') || lower.contains("a001 ok") => {
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::Imap,
                                Confidence::High,
                                "IMAP CAPABILITY response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
                    }
                    102 if response.len() >= 7
                        && response.starts_with(&[3, 0])
                        && response[5] & 0xf0 == 0xd0 =>
                    {
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::IsoOnTcp,
                                Confidence::High,
                                "ISO-on-TCP COTP connection confirmation",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
                    }
                    502 if response.len() >= 9
                        && response.starts_with(&[0, 1, 0, 0])
                        && matches!(response[7], 43 | 171) =>
                    {
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::Modbus,
                                Confidence::High,
                                "Modbus/TCP device-identification response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
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
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::ZooKeeper,
                                Confidence::High,
                                "ZooKeeper four-letter-word response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
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
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::Iec104,
                                Confidence::High,
                                "IEC 60870-5-104 TESTFR confirmation",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
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
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::PostgreSql,
                                Confidence::High,
                                "PostgreSQL SSLRequest response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
                        add_product(
                            endpoint,
                            "PostgreSQL",
                            ProductLayer::Protocol,
                            None,
                            Confidence::Medium,
                            "PostgreSQL SSL negotiation behavior".to_owned(),
                        );
                    }
                    6379 if lower.trim() == "+pong" || lower.starts_with("-noauth ") => {
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::Redis,
                                Confidence::High,
                                "Redis PING response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
                        add_product(
                            endpoint,
                            "Redis",
                            ProductLayer::Protocol,
                            None,
                            Confidence::Low,
                            format!(
                                "Redis-compatible protocol response: {}",
                                escaped_evidence(response)
                            ),
                        );
                    }
                    4369 if response.len() >= 4
                        && u32::from_be_bytes([
                            response[0],
                            response[1],
                            response[2],
                            response[3],
                        ]) == 4369 =>
                    {
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::ErlangEpmd,
                                Confidence::High,
                                "Erlang EPMD names response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
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
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::OpcUa,
                                Confidence::High,
                                "OPC UA TCP acknowledgement",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
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
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::Ajp,
                                Confidence::High,
                                "AJP CPONG response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
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
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::Cassandra,
                                Confidence::High,
                                "Cassandra native SUPPORTED response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
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
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::Git,
                                Confidence::High,
                                "Git daemon protocol error response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
                        add_product(
                            endpoint,
                            "Git daemon",
                            ProductLayer::Protocol,
                            None,
                            Confidence::Medium,
                            "Git upload-pack request received a repository error".to_owned(),
                        );
                    }
                    9600 if response.len() >= 16
                        && response.starts_with(b"FINS")
                        && response[11] == 1 =>
                    {
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::OmronFins,
                                Confidence::High,
                                "Omron FINS/TCP node-address response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
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
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::Memcached,
                                Confidence::High,
                                "Memcached version response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
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
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::EtherNetIp,
                                Confidence::High,
                                "EtherNet/IP ListIdentity response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
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
                        ({
                            let (endpoint, kind, confidence, evidence): (
                                &mut EndpointScan,
                                ServiceKind,
                                Confidence,
                                &str,
                            ) = (
                                endpoint,
                                ServiceKind::Rdp,
                                Confidence::High,
                                "RDP negotiation response",
                            );

                            if confidence >= endpoint.service_confidence {
                                endpoint.service = kind;
                                endpoint.service_confidence = confidence;
                            }
                            if !endpoint.evidence.iter().any(|item| item == evidence) {
                                endpoint.evidence.push(evidence.to_owned());
                            }
                        });
                    }
                    _ => {}
                }
            });
            endpoint.evidence.push(format!(
                "Guided probe response: {}",
                escaped_evidence(&response)
            ));
        }
    })
    .await;
    if {
        let context = context;
        context.scan.cancel.is_cancelled()
            || crate::exposure::endpoint_health::stopped(context.ip, context.port)
    } {
        endpoint.evidence.push(
            if {
                let context = context;
                crate::exposure::endpoint_health::stopped(context.ip, context.port)
            } {
                endpoint_health::STOP_REASON
            } else {
                "Probing cancelled"
            }
            .to_owned(),
        );
        return endpoint;
    }
    let negotiation_only = NEGOTIATION_ONLY_TCP_PORTS.contains(&context.port);
    let panel_listener_protocol = context.port != 2222 || endpoint.service != ServiceKind::Ssh;
    let should_probe_tls = panel_listener_protocol
        && (TLS_PORTS.contains(&context.port)
            || (endpoint.service == ServiceKind::Unknown && !negotiation_only));
    if should_probe_tls {
        for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
            let observation = ({
let (context, version,): (ProbeContext < '_ >, TlsVersion,) = (context, version,);
async move {

    let options = TlsHandshakeOptions {
        version: Some(version),
        permissive: false,
        offer_http2: true,
        use_client_certificate: false,
    };
    let mut observation = match tls_handshake(context, options).await {
        Ok(success) => {
let (requested_version, hostname, state, trace, validation_error, error,): (TlsVersion, & str, TlsObservationState, TlsTrace, Option < String >, Option < String >,) = (version, context.scan.hostname, TlsObservationState::Verified, success.trace, None, None,);
{

        let (mut supported, unverified) = match state {
            TlsObservationState::Verified => (true, false),
            TlsObservationState::Unverified => (true, true),
            TlsObservationState::Unsupported => (false, false),
        };
        if trace.client_auth.certificate_requested {
            supported = true;
        }
        let hostname_valid = trace
            .certificates
            .first()
            .and_then(|certificate| {
let (certificate, hostname,): (& CertificateTrace, & str,) = (certificate, hostname,);
let inlined_result: Option < bool > = {
'inlined_certificate_hostname_valid: {

    let names = certificate
        .subject_alt_names
        .iter()
        .filter_map(|name| {
            name.strip_prefix("DNS: ")
                .or_else(|| name.strip_prefix("IP: "))
        })
        .collect::<Vec<_>>();
    if names.is_empty() {
        break 'inlined_certificate_hostname_valid None;
    }
    Some(
        names
            .into_iter()
            .any(|name| {
let (pattern, hostname,): (& str, & str,) = (name, hostname,);
{
'inlined_hostname_matches: {

    if pattern.eq_ignore_ascii_case(hostname) {
        break 'inlined_hostname_matches true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        break 'inlined_hostname_matches false;
    };
    let Some(prefix) = hostname
        .to_ascii_lowercase()
        .strip_suffix(&format!(".{}", suffix.to_ascii_lowercase()))
        .map(str::to_owned)
    else {
        break 'inlined_hostname_matches false;
    };
    !prefix.is_empty() && !prefix.contains('.')

}
}

}),
    )

}
};
inlined_result
});
        let certificate_expired = trace.certificates.first().and_then(|certificate: & CertificateTrace| {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    certificate.not_after_unix.map(|not_after| now > not_after)
});
        let certificate_not_yet_valid = trace
            .certificates
            .first()
            .and_then(|certificate: & CertificateTrace| {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    certificate
        .not_before_unix
        .map(|not_before| now < not_before)
});
        let validation_error = validation_error.or(trace.validation_error.clone());
        let ocsp = {
let (bytes,): (& [u8],) = (&trace.ocsp_response,);
{
'inlined_parse_ocsp_observation: {

    if bytes.is_empty() {
        break 'inlined_parse_ocsp_observation None;
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
        break 'inlined_parse_ocsp_observation Some(observation);
    };
    let Some((0x0a, status_start, status_end)) = der_tlv(bytes, sequence_start) else {
        observation.error = Some("Stapled OCSP response has no response status".to_owned());
        break 'inlined_parse_ocsp_observation Some(observation);
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
        break 'inlined_parse_ocsp_observation Some(observation);
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
    if let Some(this_update) = observation.this_update.as_deref().and_then(|value: & str| {
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
}) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|value| value.as_secs() as i64);
        observation.fresh = now.map(|now| {
            this_update <= now
                && observation
                    .next_update
                    .as_deref()
                    .and_then(|value: & str| {
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
})
                    .is_none_or(|next_update| now <= next_update)
        });
    }
    Some(observation)

}
}

};
        let revocation = {
let (state, validation_error, ocsp,): (TlsObservationState, Option < & str >, Option < & OcspObservation >,) = (state, validation_error.as_deref(), ocsp.as_ref(),);
let inlined_result: RevocationState = {
'inlined_revocation_state: {

    if ocsp.and_then(|value| value.certificate_status.as_deref()) == Some("Revoked") {
        break 'inlined_revocation_state RevocationState::Revoked;
    }
    if ocsp.and_then(|value| value.certificate_status.as_deref()) == Some("Good") {
        break 'inlined_revocation_state RevocationState::Good;
    }
    if let Some(error) = validation_error.map(str::to_ascii_lowercase) {
        if error.contains("revoked") {
            break 'inlined_revocation_state RevocationState::Revoked;
        }
        if error.contains("offline") || error.contains("revocation server") {
            break 'inlined_revocation_state RevocationState::Offline;
        }
        if error.contains("revocation") {
            break 'inlined_revocation_state RevocationState::Unknown;
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
};
inlined_result
};
        let chain_diagnostics =
            {
let (certificates, validation_error,): (& [CertificateTrace], Option < & str >,) = (&trace.certificates, validation_error.as_deref(),);
let inlined_result: Vec < String > = {
'inlined_certificate_chain_diagnostics: {

    let mut diagnostics = Vec::new();
    if certificates.is_empty() {
        diagnostics.push("No peer certificate chain was captured".to_owned());
        break 'inlined_certificate_chain_diagnostics diagnostics;
    }
    if certificates[0].subject == certificates[0].issuer {
        diagnostics.push("Leaf certificate is inlined_self-signed".to_owned());
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
        if {
let (oid,): (& str,) = (&certificate.signature_algorithm,);
{

    matches!(
        oid,
        "1.2.840.113549.1.1.4" | "1.2.840.113549.1.1.5" | "1.2.840.10040.4.3" | "1.2.840.10045.4.1"
    )

}

} {
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
};
inlined_result
};
        let client_auth = trace.client_auth.clone();
        TlsObservation {
            requested_version,
            supported,
            unverified,
            alpn: supported.then_some(trace.alpn).flatten(),
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

},
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
                    {
let (requested_version, hostname, state, trace, validation_error, error,): (TlsVersion, & str, TlsObservationState, TlsTrace, Option < String >, Option < String >,) = (version, context.scan.hostname, TlsObservationState::Unverified, success.trace, validation_error, None,);
{

        let (mut supported, unverified) = match state {
            TlsObservationState::Verified => (true, false),
            TlsObservationState::Unverified => (true, true),
            TlsObservationState::Unsupported => (false, false),
        };
        if trace.client_auth.certificate_requested {
            supported = true;
        }
        let hostname_valid = trace
            .certificates
            .first()
            .and_then(|certificate| {
let (certificate, hostname,): (& CertificateTrace, & str,) = (certificate, hostname,);
let inlined_result: Option < bool > = {
'inlined_certificate_hostname_valid: {

    let names = certificate
        .subject_alt_names
        .iter()
        .filter_map(|name| {
            name.strip_prefix("DNS: ")
                .or_else(|| name.strip_prefix("IP: "))
        })
        .collect::<Vec<_>>();
    if names.is_empty() {
        break 'inlined_certificate_hostname_valid None;
    }
    Some(
        names
            .into_iter()
            .any(|name| {
let (pattern, hostname,): (& str, & str,) = (name, hostname,);
{
'inlined_hostname_matches: {

    if pattern.eq_ignore_ascii_case(hostname) {
        break 'inlined_hostname_matches true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        break 'inlined_hostname_matches false;
    };
    let Some(prefix) = hostname
        .to_ascii_lowercase()
        .strip_suffix(&format!(".{}", suffix.to_ascii_lowercase()))
        .map(str::to_owned)
    else {
        break 'inlined_hostname_matches false;
    };
    !prefix.is_empty() && !prefix.contains('.')

}
}

}),
    )

}
};
inlined_result
});
        let certificate_expired = trace.certificates.first().and_then(|certificate: & CertificateTrace| {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    certificate.not_after_unix.map(|not_after| now > not_after)
});
        let certificate_not_yet_valid = trace
            .certificates
            .first()
            .and_then(|certificate: & CertificateTrace| {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    certificate
        .not_before_unix
        .map(|not_before| now < not_before)
});
        let validation_error = validation_error.or(trace.validation_error.clone());
        let ocsp = {
let (bytes,): (& [u8],) = (&trace.ocsp_response,);
{
'inlined_parse_ocsp_observation: {

    if bytes.is_empty() {
        break 'inlined_parse_ocsp_observation None;
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
        break 'inlined_parse_ocsp_observation Some(observation);
    };
    let Some((0x0a, status_start, status_end)) = der_tlv(bytes, sequence_start) else {
        observation.error = Some("Stapled OCSP response has no response status".to_owned());
        break 'inlined_parse_ocsp_observation Some(observation);
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
        break 'inlined_parse_ocsp_observation Some(observation);
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
    if let Some(this_update) = observation.this_update.as_deref().and_then(|value: & str| {
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
}) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|value| value.as_secs() as i64);
        observation.fresh = now.map(|now| {
            this_update <= now
                && observation
                    .next_update
                    .as_deref()
                    .and_then(|value: & str| {
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
})
                    .is_none_or(|next_update| now <= next_update)
        });
    }
    Some(observation)

}
}

};
        let revocation = {
let (state, validation_error, ocsp,): (TlsObservationState, Option < & str >, Option < & OcspObservation >,) = (state, validation_error.as_deref(), ocsp.as_ref(),);
let inlined_result: RevocationState = {
'inlined_revocation_state: {

    if ocsp.and_then(|value| value.certificate_status.as_deref()) == Some("Revoked") {
        break 'inlined_revocation_state RevocationState::Revoked;
    }
    if ocsp.and_then(|value| value.certificate_status.as_deref()) == Some("Good") {
        break 'inlined_revocation_state RevocationState::Good;
    }
    if let Some(error) = validation_error.map(str::to_ascii_lowercase) {
        if error.contains("revoked") {
            break 'inlined_revocation_state RevocationState::Revoked;
        }
        if error.contains("offline") || error.contains("revocation server") {
            break 'inlined_revocation_state RevocationState::Offline;
        }
        if error.contains("revocation") {
            break 'inlined_revocation_state RevocationState::Unknown;
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
};
inlined_result
};
        let chain_diagnostics =
            {
let (certificates, validation_error,): (& [CertificateTrace], Option < & str >,) = (&trace.certificates, validation_error.as_deref(),);
let inlined_result: Vec < String > = {
'inlined_certificate_chain_diagnostics: {

    let mut diagnostics = Vec::new();
    if certificates.is_empty() {
        diagnostics.push("No peer certificate chain was captured".to_owned());
        break 'inlined_certificate_chain_diagnostics diagnostics;
    }
    if certificates[0].subject == certificates[0].issuer {
        diagnostics.push("Leaf certificate is inlined_self-signed".to_owned());
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
        if {
let (oid,): (& str,) = (&certificate.signature_algorithm,);
{

    matches!(
        oid,
        "1.2.840.113549.1.1.4" | "1.2.840.113549.1.1.5" | "1.2.840.10040.4.3" | "1.2.840.10045.4.1"
    )

}

} {
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
};
inlined_result
};
        let client_auth = trace.client_auth.clone();
        TlsObservation {
            requested_version,
            supported,
            unverified,
            alpn: supported.then_some(trace.alpn).flatten(),
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
                }
                Err(mut fallback) => {
                    if !invalid_certificates.is_empty() {
                        fallback.trace.certificates = invalid_certificates;
                    }
                    {
let (requested_version, hostname, state, trace, validation_error, error,): (TlsVersion, & str, TlsObservationState, TlsTrace, Option < String >, Option < String >,) = (version, context.scan.hostname, TlsObservationState::Unsupported, fallback.trace, validation_error, Some(format!(
                            "Validated handshake failed: {}; permissive retry failed: {}",
                            invalid.error, fallback.error
                        )),);
{

        let (mut supported, unverified) = match state {
            TlsObservationState::Verified => (true, false),
            TlsObservationState::Unverified => (true, true),
            TlsObservationState::Unsupported => (false, false),
        };
        if trace.client_auth.certificate_requested {
            supported = true;
        }
        let hostname_valid = trace
            .certificates
            .first()
            .and_then(|certificate| {
let (certificate, hostname,): (& CertificateTrace, & str,) = (certificate, hostname,);
let inlined_result: Option < bool > = {
'inlined_certificate_hostname_valid: {

    let names = certificate
        .subject_alt_names
        .iter()
        .filter_map(|name| {
            name.strip_prefix("DNS: ")
                .or_else(|| name.strip_prefix("IP: "))
        })
        .collect::<Vec<_>>();
    if names.is_empty() {
        break 'inlined_certificate_hostname_valid None;
    }
    Some(
        names
            .into_iter()
            .any(|name| {
let (pattern, hostname,): (& str, & str,) = (name, hostname,);
{
'inlined_hostname_matches: {

    if pattern.eq_ignore_ascii_case(hostname) {
        break 'inlined_hostname_matches true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        break 'inlined_hostname_matches false;
    };
    let Some(prefix) = hostname
        .to_ascii_lowercase()
        .strip_suffix(&format!(".{}", suffix.to_ascii_lowercase()))
        .map(str::to_owned)
    else {
        break 'inlined_hostname_matches false;
    };
    !prefix.is_empty() && !prefix.contains('.')

}
}

}),
    )

}
};
inlined_result
});
        let certificate_expired = trace.certificates.first().and_then(|certificate: & CertificateTrace| {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    certificate.not_after_unix.map(|not_after| now > not_after)
});
        let certificate_not_yet_valid = trace
            .certificates
            .first()
            .and_then(|certificate: & CertificateTrace| {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    certificate
        .not_before_unix
        .map(|not_before| now < not_before)
});
        let validation_error = validation_error.or(trace.validation_error.clone());
        let ocsp = {
let (bytes,): (& [u8],) = (&trace.ocsp_response,);
{
'inlined_parse_ocsp_observation: {

    if bytes.is_empty() {
        break 'inlined_parse_ocsp_observation None;
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
        break 'inlined_parse_ocsp_observation Some(observation);
    };
    let Some((0x0a, status_start, status_end)) = der_tlv(bytes, sequence_start) else {
        observation.error = Some("Stapled OCSP response has no response status".to_owned());
        break 'inlined_parse_ocsp_observation Some(observation);
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
        break 'inlined_parse_ocsp_observation Some(observation);
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
    if let Some(this_update) = observation.this_update.as_deref().and_then(|value: & str| {
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
}) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|value| value.as_secs() as i64);
        observation.fresh = now.map(|now| {
            this_update <= now
                && observation
                    .next_update
                    .as_deref()
                    .and_then(|value: & str| {
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
})
                    .is_none_or(|next_update| now <= next_update)
        });
    }
    Some(observation)

}
}

};
        let revocation = {
let (state, validation_error, ocsp,): (TlsObservationState, Option < & str >, Option < & OcspObservation >,) = (state, validation_error.as_deref(), ocsp.as_ref(),);
let inlined_result: RevocationState = {
'inlined_revocation_state: {

    if ocsp.and_then(|value| value.certificate_status.as_deref()) == Some("Revoked") {
        break 'inlined_revocation_state RevocationState::Revoked;
    }
    if ocsp.and_then(|value| value.certificate_status.as_deref()) == Some("Good") {
        break 'inlined_revocation_state RevocationState::Good;
    }
    if let Some(error) = validation_error.map(str::to_ascii_lowercase) {
        if error.contains("revoked") {
            break 'inlined_revocation_state RevocationState::Revoked;
        }
        if error.contains("offline") || error.contains("revocation server") {
            break 'inlined_revocation_state RevocationState::Offline;
        }
        if error.contains("revocation") {
            break 'inlined_revocation_state RevocationState::Unknown;
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
};
inlined_result
};
        let chain_diagnostics =
            {
let (certificates, validation_error,): (& [CertificateTrace], Option < & str >,) = (&trace.certificates, validation_error.as_deref(),);
let inlined_result: Vec < String > = {
'inlined_certificate_chain_diagnostics: {

    let mut diagnostics = Vec::new();
    if certificates.is_empty() {
        diagnostics.push("No peer certificate chain was captured".to_owned());
        break 'inlined_certificate_chain_diagnostics diagnostics;
    }
    if certificates[0].subject == certificates[0].issuer {
        diagnostics.push("Leaf certificate is inlined_self-signed".to_owned());
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
        if {
let (oid,): (& str,) = (&certificate.signature_algorithm,);
{

    matches!(
        oid,
        "1.2.840.113549.1.1.4" | "1.2.840.113549.1.1.5" | "1.2.840.10040.4.3" | "1.2.840.10045.4.1"
    )

}

} {
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
};
inlined_result
};
        let client_auth = trace.client_auth.clone();
        TlsObservation {
            requested_version,
            supported,
            unverified,
            alpn: supported.then_some(trace.alpn).flatten(),
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
                }
            }
        }
        Err(failure) => {
let (requested_version, hostname, state, trace, validation_error, error,): (TlsVersion, & str, TlsObservationState, TlsTrace, Option < String >, Option < String >,) = (version, context.scan.hostname, TlsObservationState::Unsupported, failure.trace, None, Some(failure.error),);
{

        let (mut supported, unverified) = match state {
            TlsObservationState::Verified => (true, false),
            TlsObservationState::Unverified => (true, true),
            TlsObservationState::Unsupported => (false, false),
        };
        if trace.client_auth.certificate_requested {
            supported = true;
        }
        let hostname_valid = trace
            .certificates
            .first()
            .and_then(|certificate| {
let (certificate, hostname,): (& CertificateTrace, & str,) = (certificate, hostname,);
let inlined_result: Option < bool > = {
'inlined_certificate_hostname_valid: {

    let names = certificate
        .subject_alt_names
        .iter()
        .filter_map(|name| {
            name.strip_prefix("DNS: ")
                .or_else(|| name.strip_prefix("IP: "))
        })
        .collect::<Vec<_>>();
    if names.is_empty() {
        break 'inlined_certificate_hostname_valid None;
    }
    Some(
        names
            .into_iter()
            .any(|name| {
let (pattern, hostname,): (& str, & str,) = (name, hostname,);
{
'inlined_hostname_matches: {

    if pattern.eq_ignore_ascii_case(hostname) {
        break 'inlined_hostname_matches true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        break 'inlined_hostname_matches false;
    };
    let Some(prefix) = hostname
        .to_ascii_lowercase()
        .strip_suffix(&format!(".{}", suffix.to_ascii_lowercase()))
        .map(str::to_owned)
    else {
        break 'inlined_hostname_matches false;
    };
    !prefix.is_empty() && !prefix.contains('.')

}
}

}),
    )

}
};
inlined_result
});
        let certificate_expired = trace.certificates.first().and_then(|certificate: & CertificateTrace| {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    certificate.not_after_unix.map(|not_after| now > not_after)
});
        let certificate_not_yet_valid = trace
            .certificates
            .first()
            .and_then(|certificate: & CertificateTrace| {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    certificate
        .not_before_unix
        .map(|not_before| now < not_before)
});
        let validation_error = validation_error.or(trace.validation_error.clone());
        let ocsp = {
let (bytes,): (& [u8],) = (&trace.ocsp_response,);
{
'inlined_parse_ocsp_observation: {

    if bytes.is_empty() {
        break 'inlined_parse_ocsp_observation None;
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
        break 'inlined_parse_ocsp_observation Some(observation);
    };
    let Some((0x0a, status_start, status_end)) = der_tlv(bytes, sequence_start) else {
        observation.error = Some("Stapled OCSP response has no response status".to_owned());
        break 'inlined_parse_ocsp_observation Some(observation);
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
        break 'inlined_parse_ocsp_observation Some(observation);
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
    if let Some(this_update) = observation.this_update.as_deref().and_then(|value: & str| {
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
}) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|value| value.as_secs() as i64);
        observation.fresh = now.map(|now| {
            this_update <= now
                && observation
                    .next_update
                    .as_deref()
                    .and_then(|value: & str| {
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
})
                    .is_none_or(|next_update| now <= next_update)
        });
    }
    Some(observation)

}
}

};
        let revocation = {
let (state, validation_error, ocsp,): (TlsObservationState, Option < & str >, Option < & OcspObservation >,) = (state, validation_error.as_deref(), ocsp.as_ref(),);
let inlined_result: RevocationState = {
'inlined_revocation_state: {

    if ocsp.and_then(|value| value.certificate_status.as_deref()) == Some("Revoked") {
        break 'inlined_revocation_state RevocationState::Revoked;
    }
    if ocsp.and_then(|value| value.certificate_status.as_deref()) == Some("Good") {
        break 'inlined_revocation_state RevocationState::Good;
    }
    if let Some(error) = validation_error.map(str::to_ascii_lowercase) {
        if error.contains("revoked") {
            break 'inlined_revocation_state RevocationState::Revoked;
        }
        if error.contains("offline") || error.contains("revocation server") {
            break 'inlined_revocation_state RevocationState::Offline;
        }
        if error.contains("revocation") {
            break 'inlined_revocation_state RevocationState::Unknown;
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
};
inlined_result
};
        let chain_diagnostics =
            {
let (certificates, validation_error,): (& [CertificateTrace], Option < & str >,) = (&trace.certificates, validation_error.as_deref(),);
let inlined_result: Vec < String > = {
'inlined_certificate_chain_diagnostics: {

    let mut diagnostics = Vec::new();
    if certificates.is_empty() {
        diagnostics.push("No peer certificate chain was captured".to_owned());
        break 'inlined_certificate_chain_diagnostics diagnostics;
    }
    if certificates[0].subject == certificates[0].issuer {
        diagnostics.push("Leaf certificate is inlined_self-signed".to_owned());
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
        if {
let (oid,): (& str,) = (&certificate.signature_algorithm,);
{

    matches!(
        oid,
        "1.2.840.113549.1.1.4" | "1.2.840.113549.1.1.5" | "1.2.840.10040.4.3" | "1.2.840.10045.4.1"
    )

}

} {
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
};
inlined_result
};
        let client_auth = trace.client_auth.clone();
        TlsObservation {
            requested_version,
            supported,
            unverified,
            alpn: supported.then_some(trace.alpn).flatten(),
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

},
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
            let mut retried = {
let (requested_version, hostname, state, trace, validation_error, error,): (TlsVersion, & str, TlsObservationState, TlsTrace, Option < String >, Option < String >,) = (version, context.scan.hostname, if retry_options.permissive {
                    TlsObservationState::Unverified
                } else {
                    TlsObservationState::Verified
                }, success.trace, observation.validation_error.clone(), None,);
{

        let (mut supported, unverified) = match state {
            TlsObservationState::Verified => (true, false),
            TlsObservationState::Unverified => (true, true),
            TlsObservationState::Unsupported => (false, false),
        };
        if trace.client_auth.certificate_requested {
            supported = true;
        }
        let hostname_valid = trace
            .certificates
            .first()
            .and_then(|certificate| {
let (certificate, hostname,): (& CertificateTrace, & str,) = (certificate, hostname,);
let inlined_result: Option < bool > = {
'inlined_certificate_hostname_valid: {

    let names = certificate
        .subject_alt_names
        .iter()
        .filter_map(|name| {
            name.strip_prefix("DNS: ")
                .or_else(|| name.strip_prefix("IP: "))
        })
        .collect::<Vec<_>>();
    if names.is_empty() {
        break 'inlined_certificate_hostname_valid None;
    }
    Some(
        names
            .into_iter()
            .any(|name| {
let (pattern, hostname,): (& str, & str,) = (name, hostname,);
{
'inlined_hostname_matches: {

    if pattern.eq_ignore_ascii_case(hostname) {
        break 'inlined_hostname_matches true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        break 'inlined_hostname_matches false;
    };
    let Some(prefix) = hostname
        .to_ascii_lowercase()
        .strip_suffix(&format!(".{}", suffix.to_ascii_lowercase()))
        .map(str::to_owned)
    else {
        break 'inlined_hostname_matches false;
    };
    !prefix.is_empty() && !prefix.contains('.')

}
}

}),
    )

}
};
inlined_result
});
        let certificate_expired = trace.certificates.first().and_then(|certificate: & CertificateTrace| {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    certificate.not_after_unix.map(|not_after| now > not_after)
});
        let certificate_not_yet_valid = trace
            .certificates
            .first()
            .and_then(|certificate: & CertificateTrace| {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    certificate
        .not_before_unix
        .map(|not_before| now < not_before)
});
        let validation_error = validation_error.or(trace.validation_error.clone());
        let ocsp = {
let (bytes,): (& [u8],) = (&trace.ocsp_response,);
{
'inlined_parse_ocsp_observation: {

    if bytes.is_empty() {
        break 'inlined_parse_ocsp_observation None;
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
        break 'inlined_parse_ocsp_observation Some(observation);
    };
    let Some((0x0a, status_start, status_end)) = der_tlv(bytes, sequence_start) else {
        observation.error = Some("Stapled OCSP response has no response status".to_owned());
        break 'inlined_parse_ocsp_observation Some(observation);
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
        break 'inlined_parse_ocsp_observation Some(observation);
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
    if let Some(this_update) = observation.this_update.as_deref().and_then(|value: & str| {
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
}) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|value| value.as_secs() as i64);
        observation.fresh = now.map(|now| {
            this_update <= now
                && observation
                    .next_update
                    .as_deref()
                    .and_then(|value: & str| {
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
})
                    .is_none_or(|next_update| now <= next_update)
        });
    }
    Some(observation)

}
}

};
        let revocation = {
let (state, validation_error, ocsp,): (TlsObservationState, Option < & str >, Option < & OcspObservation >,) = (state, validation_error.as_deref(), ocsp.as_ref(),);
let inlined_result: RevocationState = {
'inlined_revocation_state: {

    if ocsp.and_then(|value| value.certificate_status.as_deref()) == Some("Revoked") {
        break 'inlined_revocation_state RevocationState::Revoked;
    }
    if ocsp.and_then(|value| value.certificate_status.as_deref()) == Some("Good") {
        break 'inlined_revocation_state RevocationState::Good;
    }
    if let Some(error) = validation_error.map(str::to_ascii_lowercase) {
        if error.contains("revoked") {
            break 'inlined_revocation_state RevocationState::Revoked;
        }
        if error.contains("offline") || error.contains("revocation server") {
            break 'inlined_revocation_state RevocationState::Offline;
        }
        if error.contains("revocation") {
            break 'inlined_revocation_state RevocationState::Unknown;
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
};
inlined_result
};
        let chain_diagnostics =
            {
let (certificates, validation_error,): (& [CertificateTrace], Option < & str >,) = (&trace.certificates, validation_error.as_deref(),);
let inlined_result: Vec < String > = {
'inlined_certificate_chain_diagnostics: {

    let mut diagnostics = Vec::new();
    if certificates.is_empty() {
        diagnostics.push("No peer certificate chain was captured".to_owned());
        break 'inlined_certificate_chain_diagnostics diagnostics;
    }
    if certificates[0].subject == certificates[0].issuer {
        diagnostics.push("Leaf certificate is inlined_self-signed".to_owned());
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
        if {
let (oid,): (& str,) = (&certificate.signature_algorithm,);
{

    matches!(
        oid,
        "1.2.840.113549.1.1.4" | "1.2.840.113549.1.1.5" | "1.2.840.10040.4.3" | "1.2.840.10045.4.1"
    )

}

} {
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
};
inlined_result
};
        let client_auth = trace.client_auth.clone();
        TlsObservation {
            requested_version,
            supported,
            unverified,
            alpn: supported.then_some(trace.alpn).flatten(),
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

};
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
}).await;
            endpoint.tls.push(observation);
        }
        if TLS_PORTS.contains(&context.port) || endpoint.tls.iter().any(|tls| tls.supported) {
            endpoint.tls_probe_attempts = ({

async move {
let inlined_result: Vec < TlsProbeAttempt > = {

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
            ({
let (context, check_id, protocol, version, suites, signal_secure_renegotiation, offer_compression,): (ProbeContext < '_ >, & str, & str, u16, & [u16], bool, bool,) = (context, check_id, label, version, MODERN_SUITES, true, true,);
async move {

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
    let hello = {
let (hostname, version, suites, signal_secure_renegotiation, offer_compression,): (& str, u16, & [u16], bool, bool,) = (context.scan.hostname, version, suites, signal_secure_renegotiation, offer_compression,);
let inlined_result: Vec < u8 > = {

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
        ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 0, &sni,);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
    }
    ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 10, &[0, 4, 0, 23, 0, 24],);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
    ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 11, &[1, 0],);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
    ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 13, &[0, 12, 4, 3, 5, 3, 6, 3, 4, 1, 5, 1, 2, 1],);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
    if signal_secure_renegotiation {
        ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 0xff01, &[0],);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
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

};
inlined_result
};
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
        Ok(Ok(response)) => match {
let (bytes,): (& [u8],) = (&response,);
{
'inlined_parse_server_hello: {

    let mut record_offset = 0usize;
    while record_offset + 5 <= bytes.len() {
        let record_type = bytes[record_offset];
        let length =
            u16::from_be_bytes([bytes[record_offset + 3], bytes[record_offset + 4]]) as usize;
        let start = record_offset + 5;
        let end = match start.checked_add(length) { Some(value) => value, None => break 'inlined_parse_server_hello None };
        if end > bytes.len() {
            break 'inlined_parse_server_hello None;
        }
        if record_type == 22 && bytes.get(start) == Some(&2) {
            let body = start + 4;
            let version = u16::from_be_bytes([*match bytes.get(body) { Some(value) => value, None => break 'inlined_parse_server_hello None }, *match bytes.get(body + 1) { Some(value) => value, None => break 'inlined_parse_server_hello None }]);
            let session_length = *match bytes.get(body + 34) { Some(value) => value, None => break 'inlined_parse_server_hello None } as usize;
            let cipher_offset = body + 35 + session_length;
            let cipher =
                u16::from_be_bytes([*match bytes.get(cipher_offset) { Some(value) => value, None => break 'inlined_parse_server_hello None }, *match bytes.get(cipher_offset + 1) { Some(value) => value, None => break 'inlined_parse_server_hello None }]);
            let compression = *match bytes.get(cipher_offset + 2) { Some(value) => value, None => break 'inlined_parse_server_hello None };
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
                extension_offset = match extension_offset.checked_add(4 + length) { Some(value) => value, None => break 'inlined_parse_server_hello None };
            }
            break 'inlined_parse_server_hello Some((version, cipher, compression, secure_renegotiation));
        }
        record_offset = end;
    }
    None

}
}

} {
            Some((selected_version, selected_cipher, compression, secure_renegotiation)) => {
                result.accepted = true;
                result.negotiated_protocol = Some(({
let (version,): (u16,) = (selected_version,);
let inlined_result: & 'static str = {

    match version {
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown TLS version",
    }

};
inlined_result
}).to_owned());
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
}).await,
        );
    }
    for (check_id, cipher, suite) in WEAK_SUITES {
        let offered_suite = [*suite];
        attempts.push(
            ({
let (context, check_id, protocol, version, suites, signal_secure_renegotiation, offer_compression,): (ProbeContext < '_ >, & str, & str, u16, & [u16], bool, bool,) = (context, check_id, "TLS 1.2", 0x0303, &offered_suite, true, false,);
async move {

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
    let hello = {
let (hostname, version, suites, signal_secure_renegotiation, offer_compression,): (& str, u16, & [u16], bool, bool,) = (context.scan.hostname, version, suites, signal_secure_renegotiation, offer_compression,);
let inlined_result: Vec < u8 > = {

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
        ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 0, &sni,);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
    }
    ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 10, &[0, 4, 0, 23, 0, 24],);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
    ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 11, &[1, 0],);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
    ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 13, &[0, 12, 4, 3, 5, 3, 6, 3, 4, 1, 5, 1, 2, 1],);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
    if signal_secure_renegotiation {
        ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 0xff01, &[0],);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
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

};
inlined_result
};
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
        Ok(Ok(response)) => match {
let (bytes,): (& [u8],) = (&response,);
{
'inlined_parse_server_hello: {

    let mut record_offset = 0usize;
    while record_offset + 5 <= bytes.len() {
        let record_type = bytes[record_offset];
        let length =
            u16::from_be_bytes([bytes[record_offset + 3], bytes[record_offset + 4]]) as usize;
        let start = record_offset + 5;
        let end = match start.checked_add(length) { Some(value) => value, None => break 'inlined_parse_server_hello None };
        if end > bytes.len() {
            break 'inlined_parse_server_hello None;
        }
        if record_type == 22 && bytes.get(start) == Some(&2) {
            let body = start + 4;
            let version = u16::from_be_bytes([*match bytes.get(body) { Some(value) => value, None => break 'inlined_parse_server_hello None }, *match bytes.get(body + 1) { Some(value) => value, None => break 'inlined_parse_server_hello None }]);
            let session_length = *match bytes.get(body + 34) { Some(value) => value, None => break 'inlined_parse_server_hello None } as usize;
            let cipher_offset = body + 35 + session_length;
            let cipher =
                u16::from_be_bytes([*match bytes.get(cipher_offset) { Some(value) => value, None => break 'inlined_parse_server_hello None }, *match bytes.get(cipher_offset + 1) { Some(value) => value, None => break 'inlined_parse_server_hello None }]);
            let compression = *match bytes.get(cipher_offset + 2) { Some(value) => value, None => break 'inlined_parse_server_hello None };
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
                extension_offset = match extension_offset.checked_add(4 + length) { Some(value) => value, None => break 'inlined_parse_server_hello None };
            }
            break 'inlined_parse_server_hello Some((version, cipher, compression, secure_renegotiation));
        }
        record_offset = end;
    }
    None

}
}

} {
            Some((selected_version, selected_cipher, compression, secure_renegotiation)) => {
                result.accepted = true;
                result.negotiated_protocol = Some(({
let (version,): (u16,) = (selected_version,);
let inlined_result: & 'static str = {

    match version {
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown TLS version",
    }

};
inlined_result
}).to_owned());
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
}).await,
        );
        if { let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) } {
            return attempts;
        }
        if let Some(last) = attempts.last_mut() {
            last.offered_cipher = Some((*cipher).to_owned());
        }
    }
    attempts.push(
        ({
let (context, check_id, protocol, version, suites, signal_secure_renegotiation, offer_compression,): (ProbeContext < '_ >, & str, & str, u16, & [u16], bool, bool,) = (context, "tls.renegotiation.legacy-client-hello", "TLS 1.2", 0x0303, MODERN_SUITES, false, false,);
async move {

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
    let hello = {
let (hostname, version, suites, signal_secure_renegotiation, offer_compression,): (& str, u16, & [u16], bool, bool,) = (context.scan.hostname, version, suites, signal_secure_renegotiation, offer_compression,);
let inlined_result: Vec < u8 > = {

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
        ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 0, &sni,);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
    }
    ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 10, &[0, 4, 0, 23, 0, 24],);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
    ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 11, &[1, 0],);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
    ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 13, &[0, 12, 4, 3, 5, 3, 6, 3, 4, 1, 5, 1, 2, 1],);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
    if signal_secure_renegotiation {
        ({
let (output, kind, value,): (& mut Vec < u8 >, u16, & [u8],) = (&mut extensions, 0xff01, &[0],);

    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);

});
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

};
inlined_result
};
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
        Ok(Ok(response)) => match {
let (bytes,): (& [u8],) = (&response,);
{
'inlined_parse_server_hello: {

    let mut record_offset = 0usize;
    while record_offset + 5 <= bytes.len() {
        let record_type = bytes[record_offset];
        let length =
            u16::from_be_bytes([bytes[record_offset + 3], bytes[record_offset + 4]]) as usize;
        let start = record_offset + 5;
        let end = match start.checked_add(length) { Some(value) => value, None => break 'inlined_parse_server_hello None };
        if end > bytes.len() {
            break 'inlined_parse_server_hello None;
        }
        if record_type == 22 && bytes.get(start) == Some(&2) {
            let body = start + 4;
            let version = u16::from_be_bytes([*match bytes.get(body) { Some(value) => value, None => break 'inlined_parse_server_hello None }, *match bytes.get(body + 1) { Some(value) => value, None => break 'inlined_parse_server_hello None }]);
            let session_length = *match bytes.get(body + 34) { Some(value) => value, None => break 'inlined_parse_server_hello None } as usize;
            let cipher_offset = body + 35 + session_length;
            let cipher =
                u16::from_be_bytes([*match bytes.get(cipher_offset) { Some(value) => value, None => break 'inlined_parse_server_hello None }, *match bytes.get(cipher_offset + 1) { Some(value) => value, None => break 'inlined_parse_server_hello None }]);
            let compression = *match bytes.get(cipher_offset + 2) { Some(value) => value, None => break 'inlined_parse_server_hello None };
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
                extension_offset = match extension_offset.checked_add(4 + length) { Some(value) => value, None => break 'inlined_parse_server_hello None };
            }
            break 'inlined_parse_server_hello Some((version, cipher, compression, secure_renegotiation));
        }
        record_offset = end;
    }
    None

}
}

} {
            Some((selected_version, selected_cipher, compression, secure_renegotiation)) => {
                result.accepted = true;
                result.negotiated_protocol = Some(({
let (version,): (u16,) = (selected_version,);
let inlined_result: & 'static str = {

    match version {
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown TLS version",
    }

};
inlined_result
}).to_owned());
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
})
        .await,
    );
    attempts

};
inlined_result
}
}).await;
        }
        if endpoint.tls.iter().any(|tls| tls.supported) && endpoint.service == ServiceKind::Unknown
        {
            endpoint.service = ServiceKind::Tls;
            endpoint.service_confidence = Confidence::High;
            endpoint
                .evidence
                .push("A TLS handshake completed successfully".to_owned());
        }
        ({
            let (endpoint,): (&mut EndpointScan,) = (&mut endpoint,);

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
                endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "Revoked TLS certificate", "Windows chain validation or a stapled OCSP response reported the certificate as revoked", vec!["Certificate revocation status: Revoked".to_owned()],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
            }
            if expired {
                let evidence = endpoint
                    .tls
                    .iter()
                    .flat_map(|tls| tls.certificates.first())
                    .map(|certificate| {
                        format!("Leaf certificate expired after {}", certificate.not_after)
                    })
                    .take(1)
                    .collect();
                endpoint.findings.push({
                    let (endpoint, title, description, evidence): (
                        &EndpointScan,
                        &str,
                        &str,
                        Vec<String>,
                    ) = (
                        endpoint,
                        "Expired TLS certificate",
                        "The leaf certificate validity period has ended",
                        evidence,
                    );
                    {
                        ExposureFinding {
        details: Vec::new(),
                            title: title.to_owned(),
                            description: description.to_owned(),
                            ip: endpoint.ip,
                            port: endpoint.port,
                            transport: endpoint.transport,
                            evidence,
                            component_kind: None,
                        }
                    }
                });
            }
            if hostname_mismatch {
                endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "TLS certificate hostname mismatch", "The leaf certificate subject alternative names do not match the requested hostname", endpoint
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
                .collect(),);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
            }
            if not_yet_valid {
                endpoint.findings.push({
                    let (endpoint, title, description, evidence): (
                        &EndpointScan,
                        &str,
                        &str,
                        Vec<String>,
                    ) = (
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
                    );
                    {
                        ExposureFinding {
        details: Vec::new(),
                            title: title.to_owned(),
                            description: description.to_owned(),
                            ip: endpoint.ip,
                            port: endpoint.port,
                            transport: endpoint.transport,
                            evidence,
                            component_kind: None,
                        }
                    }
                });
            }
            if !errors.is_empty() && !expired && !hostname_mismatch && !not_yet_valid {
                endpoint.findings.push(ExposureFinding {
        details: Vec::new(),
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
                endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "TLS certificate chain or key weakness", "The presented certificate chain contains a structural, usage, signature, or key-strength issue", certificate_issues.into_iter().collect(),);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
            }
        });
        ({
            let (endpoint,): (&mut EndpointScan,) = (&mut endpoint,);

            for attempt in &endpoint.tls_probe_attempts {
                if !attempt.accepted {
                    continue;
                }
                if matches!(
                    attempt.check_id.as_str(),
                    "tls.protocol.1_0" | "tls.protocol.1_1"
                ) {
                    endpoint.findings.push({
                        let (endpoint, title, description, evidence): (
                            &EndpointScan,
                            &str,
                            &str,
                            Vec<String>,
                        ) = (
                            endpoint,
                            "Obsolete TLS protocol accepted",
                            "The server completed a ServerHello using TLS 1.0 or TLS 1.1",
                            vec![format!(
                                "{} accepted and negotiated {}",
                                attempt.offered_protocol,
                                attempt.negotiated_protocol.as_deref().unwrap_or("unknown")
                            )],
                        );
                        {
                            ExposureFinding {
        details: Vec::new(),
                                title: title.to_owned(),
                                description: description.to_owned(),
                                ip: endpoint.ip,
                                port: endpoint.port,
                                transport: endpoint.transport,
                                evidence,
                                component_kind: None,
                            }
                        }
                    });
                } else if attempt.check_id.starts_with("tls.cipher.") {
                    endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "Weak TLS cipher suite accepted", "The server selected a weak or static-RSA suite when it was individually offered", vec![format!(
                    "{} selected {}",
                    attempt.offered_cipher.as_deref().unwrap_or("weak suite"),
                    attempt.negotiated_cipher.as_deref().unwrap_or("unknown")
                )],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
                }
                if attempt
                    .compression
                    .is_some_and(|compression| compression != 0)
                {
                    endpoint.findings.push({
                        let (endpoint, title, description, evidence): (
                            &EndpointScan,
                            &str,
                            &str,
                            Vec<String>,
                        ) = (
                            endpoint,
                            "TLS compression negotiated",
                            "The server selected a non-null TLS compression method",
                            vec![format!(
                                "Compression method {}",
                                attempt.compression.unwrap_or_default()
                            )],
                        );
                        {
                            ExposureFinding {
        details: Vec::new(),
                                title: title.to_owned(),
                                description: description.to_owned(),
                                ip: endpoint.ip,
                                port: endpoint.port,
                                transport: endpoint.transport,
                                evidence,
                                component_kind: None,
                            }
                        }
                    });
                }
            }
            if endpoint
                .tls_probe_attempts
                .iter()
                .find(|attempt| attempt.check_id == "tls.renegotiation.legacy-client-hello")
                .is_some_and(|attempt| {
                    attempt.accepted && attempt.secure_renegotiation != Some(true)
                })
            {
                endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "Legacy TLS renegotiation signaling accepted", "The server accepted a legacy ClientHello without the secure-renegotiation extension or SCSV", vec!["Legacy ClientHello produced a ServerHello without secure-renegotiation signaling".to_owned()],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
            }
        });
    }
    let tls_http = endpoint
        .tls
        .iter()
        .any(|tls| tls.supported && matches!(tls.alpn.as_deref(), Some("h2") | Some("http/1.1")));
    let unknown_before_http =
        endpoint.service == ServiceKind::Unknown || endpoint.service == ServiceKind::Tls;
    if !negotiation_only
        && panel_listener_protocol
        && (HTTPS_PORTS.contains(&context.port)
            || tls_http
            || (unknown_before_http && endpoint.tls.iter().any(|v| v.supported)))
    {
        ({
let (endpoint, scheme, context,): (& mut EndpointScan, & str, ProbeContext < '_ >,) = (&mut endpoint, "https", context,);
async move {

    let cookie_jar = context
        .scan
        .request
        .security_operations
        .then(|| Mutex::new(EndpointCookieJar::default()));
    let cookie_jar = cookie_jar.as_ref();
    let head = match request_http_chain(
        context,
        scheme,
        "HEAD",
        "/",
        &[],
        MAX_HTTP_BODY_BYTES,
        cookie_jar,
    )
    .await
    {
        Ok(observations) if !observations.is_empty() => observations,
        _ => return,
    };
    ({
let (endpoint, kind, confidence, evidence,): (& mut EndpointScan, ServiceKind, Confidence, & str,) = (endpoint, if scheme == "https" {
            ServiceKind::Https
        } else {
            ServiceKind::Http
        }, Confidence::High, "Valid HTTP response status and headers",);

    if confidence >= endpoint.service_confidence {
        endpoint.service = kind;
        endpoint.service_confidence = confidence;
    }
    if !endpoint.evidence.iter().any(|item| item == evidence) {
        endpoint.evidence.push(evidence.to_owned());
    }

});
    let initial_head = head.first().cloned();
    endpoint.http.extend(head);
    let root_get = request_http_chain(
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
        let continuity = request_http_chain(
            context,
            scheme,
            "GET",
            "/",
            &[],
            MAX_HTTP_BODY_BYTES,
            cookie_jar,
        )
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
                        {
let (base, location, hostname,): (& str, & str, & str,) = (&observation.url, location, context.scan.hostname,);
{

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

}
                    })
            });
        if !redirects_to_https {
            endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "Cleartext HTTP does not redirect to HTTPS", "The root HTTP response did not direct the client to HTTPS", initial_head
                    .as_ref()
                    .map(|item| format!("HEAD / returned {}", item.status))
                    .into_iter()
                    .collect(),);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
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
            endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, issue.title, issue.description, vec![issue.evidence],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
        }
        if let Some(hsts) = super::browser_policy::hsts_assessment(root, &final_scheme) {
            let (title, outcome, evidence) = match hsts.issue {
                Some(issue) => (
                    issue.title.to_owned(),
                    CheckOutcome::Vulnerable,
                    vec![issue.evidence],
                ),
                None => (
                    "HSTS policy weakness".to_owned(),
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
    let baseline_chain = request_http_chain(
        context,
        scheme,
        "GET",
        &baseline_path,
        &[],
        MAX_HTTP_BODY_BYTES,
        cookie_jar,
    )
    .await
    .unwrap_or_default();
    let baseline = baseline_chain.last().cloned();
    endpoint.http.extend(baseline_chain);
    ({
let (endpoint, root, baseline, context, cookie_jar,): (& mut EndpointScan, Option < & HttpObservation >, Option < & HttpObservation >, ProbeContext < '_ >, Option < & Mutex < EndpointCookieJar > >,) = (endpoint, final_root.as_ref(), baseline.as_ref(), context, cookie_jar,);
async move {

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
    let web_context = ProbeContext { port: port, ..(context) };
    let asset_paths = ({
let (root, base,): (& HttpObservation, & Url,) = (root, &base,);
let inlined_result: Vec < String > = {

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

};
inlined_result
})
        .into_iter()
        .take(MAX_WEB_ASSET_REQUESTS)
        .collect();
    for (_, chain) in independent_http_chains(web_context, &scheme, asset_paths, cookie_jar).await {
        endpoint.http.extend(chain);
    }

    let mut requested = HashSet::new();
    let mut discovery_count = 0usize;
    let baselines = baseline.into_iter().collect::<Vec<_>>();
    for group in [
        &["/login/index.php", "/wp-json/"][..],
        &["/wp-json/wc/store/v1/", "/rest/V1/store/storeConfigs", "/cart.js",
            "/api/storefront/store-context", "/Security/login", "/index.php?route=account/login",
            "/products", "/cart", "/checkout"][..],
    ] {
        let mut paths = Vec::new();
        for path in group {
            if discovery_count >= MAX_WEB_DISCOVERY_REQUESTS || context.scan.cancel.is_cancelled()
                || endpoint_health::stopped(context.ip, context.port) {
                break;
            }
            if requested.insert((*path).to_owned()) {
                discovery_count += 1;
                paths.push((*path).to_owned());
            }
        }
        for (path, chain) in independent_http_chains(web_context, &scheme, paths, cookie_jar).await {
            endpoint.http.extend(chain);
        if path == "/wp-json/"
            && !endpoint.http.iter().any(|response| {
                Url::parse(&response.url).is_ok_and(|url| same_origin(&base, &url))
                    && wordpress_api_response(response)
                    && !response_is_soft_404(response, &baselines)
            })
        {
            ({
let (endpoint, context, scheme, path, requested, count, cookie_jar,): (& mut EndpointScan, ProbeContext < '_ >, & str, & str, & mut HashSet < String >, & mut usize, Option < & Mutex < EndpointCookieJar > >,) = (endpoint, web_context, &scheme, "/?rest_route=/", &mut requested, &mut discovery_count, cookie_jar,);
async move {

    if ({ let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        || *count >= MAX_WEB_DISCOVERY_REQUESTS
        || !requested.insert(path.to_owned())
    {
        return;
    }
    *count += 1;
    let chain = request_http_chain(
        context,
        scheme,
        "GET",
        path,
        &[],
        MAX_HTTP_BODY_BYTES,
        cookie_jar,
    )
    .await
    .unwrap_or_default();
    endpoint.http.extend(chain);

}
})
            .await;
        }
    }

    }
    let hints = {
let (responses,): (_,) = (endpoint.http.iter().filter(|response| {
        Url::parse(&response.url).is_ok_and(|url| same_origin(&base, &url))
            && !response_is_soft_404(response, &baselines)
    }),);
let inlined_result: HashSet < & 'static str > = {

    let mut hints = HashSet::new();
    for response in responses {
        if !(200..300).contains(&response.status) && !matches!(response.status, 401 | 403) {
            continue;
        }
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
            || wordpress_api_response(response)
            || wordpress_login_response(response)
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

};
inlined_result
};
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
    let mut paths = Vec::new();
    for path in targeted {
        if discovery_count >= MAX_WEB_DISCOVERY_REQUESTS || context.scan.cancel.is_cancelled()
            || endpoint_health::stopped(context.ip, context.port) {
            break;
        }
        if requested.insert(path.to_owned()) {
            discovery_count += 1;
            paths.push(path.to_owned());
        }
    }
    for (_, chain) in independent_http_chains(web_context, &scheme, paths, cookie_jar).await {
        endpoint.http.extend(chain);
    }

}
})
    .await;
    let options = request_http_chain(
        context,
        scheme,
        "OPTIONS",
        "/",
        &[],
        MAX_HTTP_BODY_BYTES,
        cookie_jar,
    )
    .await
    .unwrap_or_default();
    endpoint.http.extend(options);
    let trace = request_http_chain(
        context,
        scheme,
        "TRACE",
        "/",
        &[],
        MAX_HTTP_BODY_BYTES,
        cookie_jar,
    )
    .await
    .unwrap_or_default();
    if let Some(response) = trace.last()
        && (200..300).contains(&response.status)
        && (String::from_utf8_lossy(&response.body)
            .to_ascii_uppercase()
            .contains("TRACE /")
            || ({ let (response, name): (&crate::HttpObservation, &str) = (response, "content-type"); response.headers.iter().filter(move |(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()) })
                .any(|value| value.to_ascii_lowercase().contains("message/http")))
    {
        endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "HTTP TRACE is enabled", "The server accepted TRACE and returned trace content", vec![format!("TRACE / returned {}", response.status)],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
    }
    endpoint.http.extend(trace);
    if !context.scan.request.security_operations {
        let origins = [
            ("arbitrary", "https://nancy-exposure.invalid".to_owned()),
            ("null", "null".to_owned()),
        ];
        let samples =
            run_cors_matrix_for_path(endpoint, scheme, "/", &origins, context, cookie_jar).await;
        add_cors_sample_findings(endpoint, &samples, false);
    }
    ({
let (endpoint, scheme, context, cookie_jar, baseline, baseline_path,): (& mut EndpointScan, & str, ProbeContext < '_ >, Option < & Mutex < EndpointCookieJar > >, Option < & HttpObservation >, & str,) = (endpoint, scheme, context, cookie_jar, baseline.as_ref(), &baseline_path,);
async move {

    let mut probes = {
let inlined_result: Vec < ExposureProbe > = {

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

};
inlined_result
};
    if context.scan.request.security_operations {
        let cap = 96usize.min(context.scan.request.crawl_max_urls);
        probes.extend(security_operations_exposure_probes().into_iter().take(cap));
    }
    let mut seen = HashSet::new();
    probes.retain(|probe| (probe.tier != ProbeTier::SecurityOperations || context.scan.request.security_operations)
        && seen.insert(probe.path.clone()));
    let chains = independent_http_chains(context, scheme, probes.iter().map(|probe| probe.path.clone()).collect(), cookie_jar).await;
    if context.scan.cancel.is_cancelled() || endpoint_health::stopped(context.ip, context.port) {
        endpoint.http.extend(chains.into_iter().flat_map(|(_, chain)| chain));
        return;
    }
    let mut chains = chains.into_iter().collect::<HashMap<_, _>>();
    let mut git_oid = None;
    let mut git_ref = None;
    for probe in probes {
        if { let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) } {
            break;
        }
        if probe.tier == ProbeTier::SecurityOperations && !context.scan.request.security_operations
        {
            continue;
        }
        let chain = chains.remove(&probe.path).unwrap_or_default();
        if let Some(response) = chain.last() {
            if matches!(response.status, 401 | 403) || ({
let (chain,): (& [HttpObservation],) = (&chain,);
{

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

}) {
                endpoint.evidence.push(format!(
                    "Protected {} endpoint evidence: {} returned {}",
                    probe.family, probe.path, response.status
                ));
            } else if (200..300).contains(&response.status)
                && ({
let (chain, requested,): (& [HttpObservation], & str,) = (&chain, &probe.path,);
{

    chain.iter().all(|response| {
        Url::parse(&response.url)
            .ok()
            .is_some_and(|url| url.path().eq_ignore_ascii_case(requested))
    })

}

})
                && !baseline.is_some_and(|baseline| {
                    looks_like_soft_404(baseline, response, baseline_path, &probe.path)
                })
                && let Some(signature) = ({
let (probe, response,): (& ExposureProbe, & HttpObservation,) = (&probe, response,);
let inlined_result: Option < String > = {
'inlined_validate_exposure_probe: {

    let body = &response.body;
    let text = std::str::from_utf8(body).ok();
    let lower = text.map(str::to_ascii_lowercase);
    let signature = match probe.signature {
        ExposureSignature::Legacy => {
            break 'inlined_validate_exposure_probe ({
let (path, response,): (& str, & HttpObservation,) = (&probe.path, response,);
let inlined_result: Option < (& 'static str , & 'static str , String) > = {

    let text = String::from_utf8_lossy(&response.body);
    let lower = text.to_ascii_lowercase();
    let content_type = ({ let (response, name): (&crate::HttpObservation, &str) = (response, "content-type"); response.headers.iter().filter(move |(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()) })
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

};
inlined_result
}).map(|item| item.2);
        }
        ExposureSignature::GitHead => text.is_some_and(|text| {
            text.trim().starts_with("ref: refs/") || ({
let (value,): (& str,) = (text.trim(),);
let inlined_result: Option < String > = {

    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))

};
inlined_result
}).is_some()
        }),
        ExposureSignature::GitConfig => lower.as_deref().is_some_and(|text| {
            text.contains("[core]") && text.contains("repositoryformatversion")
                || text.contains("[remote \"") && text.contains("url =")
        }),
        ExposureSignature::GitRefs => ({
let (body,): (& [u8],) = (body,);
{
'inlined_first_git_object_id: {

    match std::str::from_utf8(body).ok() { Some(value) => value, None => break 'inlined_first_git_object_id None }.lines().find_map(|line| {
        line.trim_start_matches('^')
            .split_ascii_whitespace()
            .next()
            .and_then(|value: & str| {
    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
})
    })

}
}

}).is_some(),
        ExposureSignature::GitIndex => body.starts_with(b"DIRC") && body.len() >= 12,
        ExposureSignature::GitLog => text.is_some_and(|text| {
            text.lines().any(|line| {
                let mut fields = line.split_ascii_whitespace();
                fields.next().and_then(|value: & str| {
    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}).is_some()
                    && fields.next().and_then(|value: & str| {
    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}).is_some()
            })
        }),
        ExposureSignature::GitPackMetadata => lower.as_deref().is_some_and(|text| {
            text.lines().any(|line| {
                line.trim_start().starts_with('p') && line.contains("pack-")
                    || line.contains("../objects")
            })
        }),
        ExposureSignature::Dotenv => text.is_some_and(|text: & str| {
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
}),
        ExposureSignature::WebConfig => lower.as_deref().is_some_and(|text| {
            text.contains("<configuration")
                && (text.contains("<system.web")
                    || text.contains("<appsettings")
                    || text.contains("<connectionstrings"))
        }),
        ExposureSignature::JsonConfig => serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .is_some_and(|json| {
let (json,): (& serde_json :: Value,) = (&json,);
{

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

}),
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
        ExposureSignature::Properties => text.is_some_and(|text: & str| {
    let lower = text.to_ascii_lowercase();
    lower
        .lines()
        .filter(|line| {
            let line = line.trim();
            line.starts_with("spring.") && (line.contains('=') || line.contains(':'))
        })
        .count()
        >= 2
}),
        ExposureSignature::RailsCredentials => {
            body.len() >= 16
                && (lower.as_deref().is_some_and(|text| {
                    text.contains("secret_key_base:")
                        || text.contains("active_record:")
                        || text.contains("adapter:") && text.contains("database:")
                }) || probe.path.ends_with(".enc") && !({
let (body,): (& [u8],) = (body,);
{

    let start = String::from_utf8_lossy(&body[..body.len().min(256)])
        .trim_start()
        .to_ascii_lowercase();
    start.starts_with("<!doctype html") || start.starts_with("<html")

}

}))
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
        ExposureSignature::Ci => text.is_some_and(|text| {
let (path, text,): (& str, & str,) = (&probe.path, text,);
{
'inlined_valid_ci: {

    let lower = text.to_ascii_lowercase();
    if path.eq_ignore_ascii_case("/Jenkinsfile") {
        break 'inlined_valid_ci lower.contains("pipeline {") || lower.contains("node {");
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
}

}),
        ExposureSignature::Archive => {
let (path, body,): (& str, & [u8],) = (&probe.path, body,);
{

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

},
        ExposureSignature::VimSwap => body.starts_with(b"b0VIM "),
        ExposureSignature::Actuator(kind) => {
let (kind, response,): (ActuatorKind, & HttpObservation,) = (kind, response,);
{
'inlined_valid_actuator: {

    if matches!(kind, ActuatorKind::Prometheus) {
        let text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
        break 'inlined_valid_actuator text.contains("# help ") && text.contains("# type ")
            || ({ let (response, name): (&crate::HttpObservation, &str) = (response, "content-type"); response.headers.iter().filter(move |(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()) })
                .any(|value| value.to_ascii_lowercase().contains("openmetrics"));
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&response.body) else {
        break 'inlined_valid_actuator false;
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
}

},
    };
    signature.then(|| format!("Validated {} content signature", probe.family))

}
};
inlined_result
})
            {
                let (title, description) = {
let (family,): (& str,) = (probe.family,);
let inlined_result: (& 'static str , & 'static str) = {

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

};
inlined_result
};
                endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, title, description, vec![
                        format!("GET {} returned {}", probe.path, response.status),
                        signature,
                    ],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
                if {
let (probe,): (& ExposureProbe,) = (&probe,);
{

    !matches!(
        probe.signature,
        ExposureSignature::Archive | ExposureSignature::GitIndex | ExposureSignature::VimSwap
    ) && (!matches!(probe.signature, ExposureSignature::RailsCredentials)
        || !probe.path.ends_with(".enc"))

}

} {
                    for issue in super::artifact_analysis::text_artifact_secret_issues(
                        &response.url,
                        &response.body,
                        None,
                    ) {
                        endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, issue.title, issue.description, vec![issue.evidence],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
                    }
                }
                match probe.signature {
                    ExposureSignature::GitHead => {
                        let text = String::from_utf8_lossy(&response.body);
                        git_oid = {
let (value,): (& str,) = (text.trim(),);
let inlined_result: Option < String > = {

    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))

};
inlined_result
};
                        git_ref = text
                            .trim()
                            .strip_prefix("ref: ")
                            .filter(|value| {
let (value,): (& str,) = (value,);
{

    value.starts_with("refs/")
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))

}

})
                            .map(|value| format!("/.git/{value}"));
                    }
                    ExposureSignature::GitRefs => {
                        git_oid = ({
let (body,): (& [u8],) = (&response.body,);
{
'inlined_first_git_object_id: {

    match std::str::from_utf8(body).ok() { Some(value) => value, None => break 'inlined_first_git_object_id None }.lines().find_map(|line| {
        line.trim_start_matches('^')
            .split_ascii_whitespace()
            .next()
            .and_then(|value: & str| {
    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
})
    })

}
}

}).or(git_oid);
                    }
                    _ => {}
                }
            }
        }
        endpoint.http.extend(chain);
    }
    if git_oid.is_none()
        && let Some(reference) = git_ref
        && !({ let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) })
    {
        let chain = request_http_chain(
            context,
            scheme,
            "GET",
            &reference,
            &[],
            MAX_HTTP_BODY_BYTES,
            cookie_jar,
        )
        .await
        .unwrap_or_default();
        if let Some(response) = chain.last()
            && (200..300).contains(&response.status)
            && ({
let (chain, requested,): (& [HttpObservation], & str,) = (&chain, &reference,);
{

    chain.iter().all(|response| {
        Url::parse(&response.url)
            .ok()
            .is_some_and(|url| url.path().eq_ignore_ascii_case(requested))
    })

}

})
            && !baseline.is_some_and(|baseline| {
                looks_like_soft_404(baseline, response, baseline_path, &reference)
            })
            && let Some(object_id) = ({
let (body,): (& [u8],) = (&response.body,);
{
'inlined_first_git_object_id: {

    match std::str::from_utf8(body).ok() { Some(value) => value, None => break 'inlined_first_git_object_id None }.lines().find_map(|line| {
        line.trim_start_matches('^')
            .split_ascii_whitespace()
            .next()
            .and_then(|value: & str| {
    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
})
    })

}
}

})
        {
            endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "Exposed Git repository metadata", "A Git reference is publicly readable", vec![
                    format!("GET {reference} returned {}", response.status),
                    "Git object identifier detected; value withheld".to_owned(),
                ],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
            git_oid = Some(object_id);
        }
        endpoint.http.extend(chain);
    }
    if let Some(object_id) = git_oid
        && !({ let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) })
    {
        let object_path = format!("/.git/objects/{}/{}", &object_id[..2], &object_id[2..]);
        let chain = request_http_chain(
            context,
            scheme,
            "GET",
            &object_path,
            &[],
            MAX_HTTP_BODY_BYTES,
            cookie_jar,
        )
        .await
        .unwrap_or_default();
        if let Some(response) = chain.last()
            && (200..300).contains(&response.status)
            && ({
let (chain, requested,): (& [HttpObservation], & str,) = (&chain, &object_path,);
{

    chain.iter().all(|response| {
        Url::parse(&response.url)
            .ok()
            .is_some_and(|url| url.path().eq_ignore_ascii_case(requested))
    })

}

})
            && ({
let (body,): (& [u8],) = (&response.body,);
{
'inlined_valid_loose_git_object: {

    let mut output = Vec::new();
    let mut decoder = ZlibDecoder::new(body).take((MAX_HTTP_BODY_BYTES + 1) as u64);
    if decoder.read_to_end(&mut output).is_err() || output.len() > MAX_HTTP_BODY_BYTES {
        break 'inlined_valid_loose_git_object false;
    }
    let Some(nul) = output.iter().position(|byte| *byte == 0) else {
        break 'inlined_valid_loose_git_object false;
    };
    let Ok(header) = std::str::from_utf8(&output[..nul]) else {
        break 'inlined_valid_loose_git_object false;
    };
    let Some((kind, size)) = header.split_once(' ') else {
        break 'inlined_valid_loose_git_object false;
    };
    matches!(kind, "blob" | "tree" | "commit" | "tag")
        && size.parse::<usize>().ok() == Some(output.len().saturating_sub(nul + 1))

}
}

})
        {
            endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "Exposed Git repository object", "One referenced loose Git object is publicly readable", vec![
                    format!("GET {object_path} returned {}", response.status),
                    "Bounded zlib output contained a valid Git object header".to_owned(),
                ],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
        }
        endpoint.http.extend(chain);
    }

}
})
    .await;
    ({
let (endpoint, scheme, context, cookie_jar,): (& mut EndpointScan, & str, ProbeContext < '_ >, Option < & Mutex < EndpointCookieJar > >,) = (endpoint, scheme, context, cookie_jar,);
async move {

    if let Some(path) = {
let (port,): (u16,) = (context.port,);
{

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

} {
        if { let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) } {
            return;
        }
        let chain = request_http_chain(
            context,
            scheme,
            "GET",
            path,
            &[],
            MAX_HTTP_BODY_BYTES,
            cookie_jar,
        )
        .await
        .unwrap_or_default();
        if let Some(response) = chain.last()
            && (200..300).contains(&response.status)
            && let Some(detection) = ({
let (port, path, response, endpoint,): (u16, & str, & HttpObservation, & EndpointScan,) = (context.port, path, response, endpoint,);
let inlined_result: Option < ManagementDetection > = {
'inlined_management_detection: {

    let json = match serde_json::from_slice::<serde_json::Value>(&response.body).ok() { Some(value) => value, None => break 'inlined_management_detection None };
    match (port, path) {
        (2375 | 2376, "/version")
            if json.get("ApiVersion").is_some() && json.get("Version").is_some() =>
        {
            Some(ManagementDetection {
                product: "Docker Engine",
                version: ({
let (value, key,): (& serde_json :: Value, & str,) = (&json, "Version",);
{
'inlined_json_string: {

    match value.get(key) { Some(value) => value, None => break 'inlined_json_string None }.as_str().map(str::to_owned)

}
}

}),
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
                version: ({
let (value, key,): (& serde_json :: Value, & str,) = (&json, "etcdserver",);
{
'inlined_json_string: {

    match value.get(key) { Some(value) => value, None => break 'inlined_json_string None }.as_str().map(str::to_owned)

}
}

}),
                title: "Unauthenticated etcd API information",
                description: "The etcd API disclosed server and cluster information without authentication",
                service_evidence: "etcd version API JSON response",
                product_evidence: "etcd /version response contains etcdserver and etcdcluster",
            })
        }
        (5984, "/_all_dbs")
            if json.is_array() && ({
let (endpoint, key, expected,): (& EndpointScan, & str, & str,) = (endpoint, "couchdb", "Welcome",);
{

    endpoint.http.iter().any(|response| {
        serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|json| json.get(key)?.as_str().map(str::to_owned))
            .is_some_and(|value| value.eq_ignore_ascii_case(expected))
    })

}

}) =>
        {
            Some(ManagementDetection {
                product: "CouchDB",
                version: ({
let (endpoint, key,): (& EndpointScan, & str,) = (endpoint, "version",);
{

    endpoint.http.iter().find_map(|response| {
        serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|json| {
let (value, key,): (& serde_json :: Value, & str,) = (&json, key,);
{
'inlined_json_string: {

    match value.get(key) { Some(value) => value, None => break 'inlined_json_string None }.as_str().map(str::to_owned)

}
}

})
    })

}

}),
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
        (8086, "/query?q=SHOW%20DATABASES") if ({
let (json,): (& serde_json :: Value,) = (&json,);
{

    json.get("results")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|result| result.get("series")?.as_array())
        .flatten()
        .any(|series| series.get("name").and_then(|value| value.as_str()) == Some("databases"))

}

}) => {
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
            if ({
let (endpoint, keys,): (& EndpointScan, & [& str],) = (endpoint, &["version", "distribution"],);
let inlined_result: Option < String > = {

    endpoint.http.iter().find_map(|response| {
        let json = serde_json::from_slice::<serde_json::Value>(&response.body).ok()?;
        keys.iter()
            .try_fold(&json, |value, key| value.get(*key))?
            .as_str()
            .map(str::to_owned)
    })

};
inlined_result
}).as_deref()
                == Some("opensearch")
            {
                break 'inlined_management_detection Some(ManagementDetection {
                    product: "OpenSearch",
                    version: ({
let (endpoint, keys,): (& EndpointScan, & [& str],) = (endpoint, &["version", "number"],);
let inlined_result: Option < String > = {

    endpoint.http.iter().find_map(|response| {
        let json = serde_json::from_slice::<serde_json::Value>(&response.body).ok()?;
        keys.iter()
            .try_fold(&json, |value, key| value.get(*key))?
            .as_str()
            .map(str::to_owned)
    })

};
inlined_result
}),
                    title: "Unauthenticated OpenSearch cluster information",
                    description: "OpenSearch returned cluster health information without authentication",
                    service_evidence: "OpenSearch cluster-health JSON response",
                    product_evidence: "Root response explicitly identifies the OpenSearch distribution",
                });
            }
            Some(ManagementDetection {
                product: "Elasticsearch",
                version: ({
let (endpoint, keys,): (& EndpointScan, & [& str],) = (endpoint, &["version", "number"],);
let inlined_result: Option < String > = {

    endpoint.http.iter().find_map(|response| {
        let json = serde_json::from_slice::<serde_json::Value>(&response.body).ok()?;
        keys.iter()
            .try_fold(&json, |value, key| value.get(*key))?
            .as_str()
            .map(str::to_owned)
    })

};
inlined_result
}),
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
};
inlined_result
})
        {
            ({
let (endpoint, kind, confidence, evidence,): (& mut EndpointScan, ServiceKind, Confidence, & str,) = (endpoint, if scheme == "https" {
                    ServiceKind::Https
                } else {
                    ServiceKind::Http
                }, Confidence::High, detection.service_evidence,);

    if confidence >= endpoint.service_confidence {
        endpoint.service = kind;
        endpoint.service_confidence = confidence;
    }
    if !endpoint.evidence.iter().any(|item| item == evidence) {
        endpoint.evidence.push(evidence.to_owned());
    }

});
            add_product(
                endpoint,
                detection.product,
                ProductLayer::Server,
                detection.version,
                Confidence::High,
                detection.product_evidence.to_owned(),
            );
            endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, detection.title, detection.description, vec![
                    format!(
                        "GET {path} returned {} without authentication",
                        response.status
                    ),
                    detection.product_evidence.to_owned(),
                ],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
        } else if let Some(response) = chain.last()
            && (matches!(response.status, 401 | 403) || ({
let (chain,): (& [HttpObservation],) = (&chain,);
{

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

}))
        {
            endpoint.evidence.push(format!(
                "Protected management endpoint evidence: {path} returned {}",
                response.status
            ));
        }
        endpoint.http.extend(chain);
    }
    if context.scan.request.security_operations && !({ let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) }) {
        ({
let (endpoint, scheme, context, cookie_jar,): (& mut EndpointScan, & str, ProbeContext < '_ >, Option < & Mutex < EndpointCookieJar > >,) = (endpoint, scheme, context, cookie_jar,);
async move {

    let mut fingerprint_chains = if cookie_jar.is_none() {
        let paths = MANAGEMENT_PRODUCT_PROBES.iter()
            .filter(|probe| !endpoint.http.iter().any(|response| management_fingerprint(probe.kind, response)))
            .map(|probe| probe.fingerprint_path.to_owned()).collect();
        independent_http_chains(context, scheme, paths, None).await.into_iter().collect::<HashMap<_, _>>()
    } else {
        HashMap::new()
    };
    for probe in MANAGEMENT_PRODUCT_PROBES {
        if { let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) } {
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
            fingerprint_chain = if let Some(chain) = fingerprint_chains.remove(probe.fingerprint_path) {
                chain
            } else if cookie_jar.is_none() {
                Vec::new()
            } else { request_http_chain(
                context,
                scheme,
                "GET",
                probe.fingerprint_path,
                &[],
                MAX_HTTP_BODY_BYTES,
                cookie_jar,
            )
            .await
            .unwrap_or_default() };
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
        let chain = request_http_chain(
            context,
            scheme,
            "GET",
            probe.listing_path,
            &[],
            MAX_HTTP_BODY_BYTES,
            cookie_jar,
        )
        .await
        .unwrap_or_default();
        if let Some(response) = chain.last() {
            if matches!(response.status, 401 | 403) || ({
let (chain,): (& [HttpObservation],) = (&chain,);
{

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

}) {
                endpoint.evidence.push(format!(
                    "Protected {} management evidence: {} returned {}",
                    probe.product, probe.listing_path, response.status
                ));
            } else if (200..300).contains(&response.status)
                && ({
let (kind, response,): (ManagementProductKind, & HttpObservation,) = (probe.kind, response,);
{
'inlined_validated_management_listing: {

    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&response.body) else {
        break 'inlined_validated_management_listing false;
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
}

})
            {
                endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, &format!("Unauthenticated {} management data", probe.product), &format!(
                        "The {} interface returned validated {} data without authentication",
                        probe.product, probe.listing_name
                    ), vec![
                        format!(
                            "GET {} returned {} without authentication",
                            probe.listing_path, response.status
                        ),
                        format!("Validated {} listing structure", probe.listing_name),
                    ],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
            }
        }
        endpoint.http.extend(chain);
    }

}
}).await;
    }

}
}).await;
    let mut cleartext_challenges = endpoint
        .http
        .iter()
        .filter(|response| response.url.starts_with("http://"))
        .flat_map(|response| {
            ({ let (response, name): (&crate::HttpObservation, &str) = (response, "www-authenticate"); response.headers.iter().filter(move |(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()) }).map(|value| {
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
        endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "Authentication offered over cleartext HTTP", "The service advertises an authentication challenge without transport encryption", cleartext_challenges,);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
    }

}
}).await;
    }
    if !negotiation_only
        && panel_listener_protocol
        && endpoint.http.is_empty()
        && (HTTP_PORTS.contains(&context.port)
            || endpoint.service == ServiceKind::Unknown
            || (HTTPS_PORTS.contains(&context.port) && !endpoint.tls.iter().any(|v| v.supported)))
    {
        ({
let (endpoint, scheme, context,): (& mut EndpointScan, & str, ProbeContext < '_ >,) = (&mut endpoint, "http", context,);
async move {

    let cookie_jar = context
        .scan
        .request
        .security_operations
        .then(|| Mutex::new(EndpointCookieJar::default()));
    let cookie_jar = cookie_jar.as_ref();
    let head = match request_http_chain(
        context,
        scheme,
        "HEAD",
        "/",
        &[],
        MAX_HTTP_BODY_BYTES,
        cookie_jar,
    )
    .await
    {
        Ok(observations) if !observations.is_empty() => observations,
        _ => return,
    };
    ({
let (endpoint, kind, confidence, evidence,): (& mut EndpointScan, ServiceKind, Confidence, & str,) = (endpoint, if scheme == "https" {
            ServiceKind::Https
        } else {
            ServiceKind::Http
        }, Confidence::High, "Valid HTTP response status and headers",);

    if confidence >= endpoint.service_confidence {
        endpoint.service = kind;
        endpoint.service_confidence = confidence;
    }
    if !endpoint.evidence.iter().any(|item| item == evidence) {
        endpoint.evidence.push(evidence.to_owned());
    }

});
    let initial_head = head.first().cloned();
    endpoint.http.extend(head);
    let root_get = request_http_chain(
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
        let continuity = request_http_chain(
            context,
            scheme,
            "GET",
            "/",
            &[],
            MAX_HTTP_BODY_BYTES,
            cookie_jar,
        )
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
                        {
let (base, location, hostname,): (& str, & str, & str,) = (&observation.url, location, context.scan.hostname,);
{

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

}
                    })
            });
        if !redirects_to_https {
            endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "Cleartext HTTP does not redirect to HTTPS", "The root HTTP response did not direct the client to HTTPS", initial_head
                    .as_ref()
                    .map(|item| format!("HEAD / returned {}", item.status))
                    .into_iter()
                    .collect(),);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
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
            endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, issue.title, issue.description, vec![issue.evidence],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
        }
        if let Some(hsts) = super::browser_policy::hsts_assessment(root, &final_scheme) {
            let (title, outcome, evidence) = match hsts.issue {
                Some(issue) => (
                    issue.title.to_owned(),
                    CheckOutcome::Vulnerable,
                    vec![issue.evidence],
                ),
                None => (
                    "HSTS policy weakness".to_owned(),
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
    let baseline_chain = request_http_chain(
        context,
        scheme,
        "GET",
        &baseline_path,
        &[],
        MAX_HTTP_BODY_BYTES,
        cookie_jar,
    )
    .await
    .unwrap_or_default();
    let baseline = baseline_chain.last().cloned();
    endpoint.http.extend(baseline_chain);
    ({
let (endpoint, root, baseline, context, cookie_jar,): (& mut EndpointScan, Option < & HttpObservation >, Option < & HttpObservation >, ProbeContext < '_ >, Option < & Mutex < EndpointCookieJar > >,) = (endpoint, final_root.as_ref(), baseline.as_ref(), context, cookie_jar,);
async move {

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
    let web_context = ProbeContext { port: port, ..(context) };
    let asset_paths = ({
let (root, base,): (& HttpObservation, & Url,) = (root, &base,);
let inlined_result: Vec < String > = {

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

};
inlined_result
})
        .into_iter()
        .take(MAX_WEB_ASSET_REQUESTS)
        .collect();
    for (_, chain) in independent_http_chains(web_context, &scheme, asset_paths, cookie_jar).await {
        endpoint.http.extend(chain);
    }

    let mut requested = HashSet::new();
    let mut discovery_count = 0usize;
    let baselines = baseline.into_iter().collect::<Vec<_>>();
    for group in [
        &["/login/index.php", "/wp-json/"][..],
        &["/wp-json/wc/store/v1/", "/rest/V1/store/storeConfigs", "/cart.js",
            "/api/storefront/store-context", "/Security/login", "/index.php?route=account/login",
            "/products", "/cart", "/checkout"][..],
    ] {
        let mut paths = Vec::new();
        for path in group {
            if discovery_count >= MAX_WEB_DISCOVERY_REQUESTS || context.scan.cancel.is_cancelled()
                || endpoint_health::stopped(context.ip, context.port) {
                break;
            }
            if requested.insert((*path).to_owned()) {
                discovery_count += 1;
                paths.push((*path).to_owned());
            }
        }
        for (path, chain) in independent_http_chains(web_context, &scheme, paths, cookie_jar).await {
            endpoint.http.extend(chain);
        if path == "/wp-json/"
            && !endpoint.http.iter().any(|response| {
                Url::parse(&response.url).is_ok_and(|url| same_origin(&base, &url))
                    && wordpress_api_response(response)
                    && !response_is_soft_404(response, &baselines)
            })
        {
            ({
let (endpoint, context, scheme, path, requested, count, cookie_jar,): (& mut EndpointScan, ProbeContext < '_ >, & str, & str, & mut HashSet < String >, & mut usize, Option < & Mutex < EndpointCookieJar > >,) = (endpoint, web_context, &scheme, "/?rest_route=/", &mut requested, &mut discovery_count, cookie_jar,);
async move {

    if ({ let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) })
        || *count >= MAX_WEB_DISCOVERY_REQUESTS
        || !requested.insert(path.to_owned())
    {
        return;
    }
    *count += 1;
    let chain = request_http_chain(
        context,
        scheme,
        "GET",
        path,
        &[],
        MAX_HTTP_BODY_BYTES,
        cookie_jar,
    )
    .await
    .unwrap_or_default();
    endpoint.http.extend(chain);

}
})
            .await;
        }
    }

    }
    let hints = {
let (responses,): (_,) = (endpoint.http.iter().filter(|response| {
        Url::parse(&response.url).is_ok_and(|url| same_origin(&base, &url))
            && !response_is_soft_404(response, &baselines)
    }),);
let inlined_result: HashSet < & 'static str > = {

    let mut hints = HashSet::new();
    for response in responses {
        if !(200..300).contains(&response.status) && !matches!(response.status, 401 | 403) {
            continue;
        }
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
            || wordpress_api_response(response)
            || wordpress_login_response(response)
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

};
inlined_result
};
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
    let mut paths = Vec::new();
    for path in targeted {
        if discovery_count >= MAX_WEB_DISCOVERY_REQUESTS || context.scan.cancel.is_cancelled()
            || endpoint_health::stopped(context.ip, context.port) {
            break;
        }
        if requested.insert(path.to_owned()) {
            discovery_count += 1;
            paths.push(path.to_owned());
        }
    }
    for (_, chain) in independent_http_chains(web_context, &scheme, paths, cookie_jar).await {
        endpoint.http.extend(chain);
    }

}
})
    .await;
    let options = request_http_chain(
        context,
        scheme,
        "OPTIONS",
        "/",
        &[],
        MAX_HTTP_BODY_BYTES,
        cookie_jar,
    )
    .await
    .unwrap_or_default();
    endpoint.http.extend(options);
    let trace = request_http_chain(
        context,
        scheme,
        "TRACE",
        "/",
        &[],
        MAX_HTTP_BODY_BYTES,
        cookie_jar,
    )
    .await
    .unwrap_or_default();
    if let Some(response) = trace.last()
        && (200..300).contains(&response.status)
        && (String::from_utf8_lossy(&response.body)
            .to_ascii_uppercase()
            .contains("TRACE /")
            || ({ let (response, name): (&crate::HttpObservation, &str) = (response, "content-type"); response.headers.iter().filter(move |(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()) })
                .any(|value| value.to_ascii_lowercase().contains("message/http")))
    {
        endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "HTTP TRACE is enabled", "The server accepted TRACE and returned trace content", vec![format!("TRACE / returned {}", response.status)],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
    }
    endpoint.http.extend(trace);
    if !context.scan.request.security_operations {
        let origins = [
            ("arbitrary", "https://nancy-exposure.invalid".to_owned()),
            ("null", "null".to_owned()),
        ];
        let samples =
            run_cors_matrix_for_path(endpoint, scheme, "/", &origins, context, cookie_jar).await;
        add_cors_sample_findings(endpoint, &samples, false);
    }
    ({
let (endpoint, scheme, context, cookie_jar, baseline, baseline_path,): (& mut EndpointScan, & str, ProbeContext < '_ >, Option < & Mutex < EndpointCookieJar > >, Option < & HttpObservation >, & str,) = (endpoint, scheme, context, cookie_jar, baseline.as_ref(), &baseline_path,);
async move {

    let mut probes = {
let inlined_result: Vec < ExposureProbe > = {

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

};
inlined_result
};
    if context.scan.request.security_operations {
        let cap = 96usize.min(context.scan.request.crawl_max_urls);
        probes.extend(security_operations_exposure_probes().into_iter().take(cap));
    }
    let mut seen = HashSet::new();
    probes.retain(|probe| (probe.tier != ProbeTier::SecurityOperations || context.scan.request.security_operations)
        && seen.insert(probe.path.clone()));
    let chains = independent_http_chains(context, scheme, probes.iter().map(|probe| probe.path.clone()).collect(), cookie_jar).await;
    if context.scan.cancel.is_cancelled() || endpoint_health::stopped(context.ip, context.port) {
        endpoint.http.extend(chains.into_iter().flat_map(|(_, chain)| chain));
        return;
    }
    let mut chains = chains.into_iter().collect::<HashMap<_, _>>();
    let mut git_oid = None;
    let mut git_ref = None;
    for probe in probes {
        if { let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) } {
            break;
        }
        if probe.tier == ProbeTier::SecurityOperations && !context.scan.request.security_operations
        {
            continue;
        }
        let chain = chains.remove(&probe.path).unwrap_or_default();
        if let Some(response) = chain.last() {
            if matches!(response.status, 401 | 403) || ({
let (chain,): (& [HttpObservation],) = (&chain,);
{

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

}) {
                endpoint.evidence.push(format!(
                    "Protected {} endpoint evidence: {} returned {}",
                    probe.family, probe.path, response.status
                ));
            } else if (200..300).contains(&response.status)
                && ({
let (chain, requested,): (& [HttpObservation], & str,) = (&chain, &probe.path,);
{

    chain.iter().all(|response| {
        Url::parse(&response.url)
            .ok()
            .is_some_and(|url| url.path().eq_ignore_ascii_case(requested))
    })

}

})
                && !baseline.is_some_and(|baseline| {
                    looks_like_soft_404(baseline, response, baseline_path, &probe.path)
                })
                && let Some(signature) = ({
let (probe, response,): (& ExposureProbe, & HttpObservation,) = (&probe, response,);
let inlined_result: Option < String > = {
'inlined_validate_exposure_probe: {

    let body = &response.body;
    let text = std::str::from_utf8(body).ok();
    let lower = text.map(str::to_ascii_lowercase);
    let signature = match probe.signature {
        ExposureSignature::Legacy => {
            break 'inlined_validate_exposure_probe ({
let (path, response,): (& str, & HttpObservation,) = (&probe.path, response,);
let inlined_result: Option < (& 'static str , & 'static str , String) > = {

    let text = String::from_utf8_lossy(&response.body);
    let lower = text.to_ascii_lowercase();
    let content_type = ({ let (response, name): (&crate::HttpObservation, &str) = (response, "content-type"); response.headers.iter().filter(move |(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()) })
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

};
inlined_result
}).map(|item| item.2);
        }
        ExposureSignature::GitHead => text.is_some_and(|text| {
            text.trim().starts_with("ref: refs/") || ({
let (value,): (& str,) = (text.trim(),);
let inlined_result: Option < String > = {

    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))

};
inlined_result
}).is_some()
        }),
        ExposureSignature::GitConfig => lower.as_deref().is_some_and(|text| {
            text.contains("[core]") && text.contains("repositoryformatversion")
                || text.contains("[remote \"") && text.contains("url =")
        }),
        ExposureSignature::GitRefs => ({
let (body,): (& [u8],) = (body,);
{
'inlined_first_git_object_id: {

    match std::str::from_utf8(body).ok() { Some(value) => value, None => break 'inlined_first_git_object_id None }.lines().find_map(|line| {
        line.trim_start_matches('^')
            .split_ascii_whitespace()
            .next()
            .and_then(|value: & str| {
    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
})
    })

}
}

}).is_some(),
        ExposureSignature::GitIndex => body.starts_with(b"DIRC") && body.len() >= 12,
        ExposureSignature::GitLog => text.is_some_and(|text| {
            text.lines().any(|line| {
                let mut fields = line.split_ascii_whitespace();
                fields.next().and_then(|value: & str| {
    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}).is_some()
                    && fields.next().and_then(|value: & str| {
    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}).is_some()
            })
        }),
        ExposureSignature::GitPackMetadata => lower.as_deref().is_some_and(|text| {
            text.lines().any(|line| {
                line.trim_start().starts_with('p') && line.contains("pack-")
                    || line.contains("../objects")
            })
        }),
        ExposureSignature::Dotenv => text.is_some_and(|text: & str| {
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
}),
        ExposureSignature::WebConfig => lower.as_deref().is_some_and(|text| {
            text.contains("<configuration")
                && (text.contains("<system.web")
                    || text.contains("<appsettings")
                    || text.contains("<connectionstrings"))
        }),
        ExposureSignature::JsonConfig => serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .is_some_and(|json| {
let (json,): (& serde_json :: Value,) = (&json,);
{

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

}),
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
        ExposureSignature::Properties => text.is_some_and(|text: & str| {
    let lower = text.to_ascii_lowercase();
    lower
        .lines()
        .filter(|line| {
            let line = line.trim();
            line.starts_with("spring.") && (line.contains('=') || line.contains(':'))
        })
        .count()
        >= 2
}),
        ExposureSignature::RailsCredentials => {
            body.len() >= 16
                && (lower.as_deref().is_some_and(|text| {
                    text.contains("secret_key_base:")
                        || text.contains("active_record:")
                        || text.contains("adapter:") && text.contains("database:")
                }) || probe.path.ends_with(".enc") && !({
let (body,): (& [u8],) = (body,);
{

    let start = String::from_utf8_lossy(&body[..body.len().min(256)])
        .trim_start()
        .to_ascii_lowercase();
    start.starts_with("<!doctype html") || start.starts_with("<html")

}

}))
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
        ExposureSignature::Ci => text.is_some_and(|text| {
let (path, text,): (& str, & str,) = (&probe.path, text,);
{
'inlined_valid_ci: {

    let lower = text.to_ascii_lowercase();
    if path.eq_ignore_ascii_case("/Jenkinsfile") {
        break 'inlined_valid_ci lower.contains("pipeline {") || lower.contains("node {");
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
}

}),
        ExposureSignature::Archive => {
let (path, body,): (& str, & [u8],) = (&probe.path, body,);
{

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

},
        ExposureSignature::VimSwap => body.starts_with(b"b0VIM "),
        ExposureSignature::Actuator(kind) => {
let (kind, response,): (ActuatorKind, & HttpObservation,) = (kind, response,);
{
'inlined_valid_actuator: {

    if matches!(kind, ActuatorKind::Prometheus) {
        let text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
        break 'inlined_valid_actuator text.contains("# help ") && text.contains("# type ")
            || ({ let (response, name): (&crate::HttpObservation, &str) = (response, "content-type"); response.headers.iter().filter(move |(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()) })
                .any(|value| value.to_ascii_lowercase().contains("openmetrics"));
    }
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&response.body) else {
        break 'inlined_valid_actuator false;
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
}

},
    };
    signature.then(|| format!("Validated {} content signature", probe.family))

}
};
inlined_result
})
            {
                let (title, description) = {
let (family,): (& str,) = (probe.family,);
let inlined_result: (& 'static str , & 'static str) = {

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

};
inlined_result
};
                endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, title, description, vec![
                        format!("GET {} returned {}", probe.path, response.status),
                        signature,
                    ],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
                if {
let (probe,): (& ExposureProbe,) = (&probe,);
{

    !matches!(
        probe.signature,
        ExposureSignature::Archive | ExposureSignature::GitIndex | ExposureSignature::VimSwap
    ) && (!matches!(probe.signature, ExposureSignature::RailsCredentials)
        || !probe.path.ends_with(".enc"))

}

} {
                    for issue in super::artifact_analysis::text_artifact_secret_issues(
                        &response.url,
                        &response.body,
                        None,
                    ) {
                        endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, issue.title, issue.description, vec![issue.evidence],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
                    }
                }
                match probe.signature {
                    ExposureSignature::GitHead => {
                        let text = String::from_utf8_lossy(&response.body);
                        git_oid = {
let (value,): (& str,) = (text.trim(),);
let inlined_result: Option < String > = {

    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))

};
inlined_result
};
                        git_ref = text
                            .trim()
                            .strip_prefix("ref: ")
                            .filter(|value| {
let (value,): (& str,) = (value,);
{

    value.starts_with("refs/")
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))

}

})
                            .map(|value| format!("/.git/{value}"));
                    }
                    ExposureSignature::GitRefs => {
                        git_oid = ({
let (body,): (& [u8],) = (&response.body,);
{
'inlined_first_git_object_id: {

    match std::str::from_utf8(body).ok() { Some(value) => value, None => break 'inlined_first_git_object_id None }.lines().find_map(|line| {
        line.trim_start_matches('^')
            .split_ascii_whitespace()
            .next()
            .and_then(|value: & str| {
    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
})
    })

}
}

}).or(git_oid);
                    }
                    _ => {}
                }
            }
        }
        endpoint.http.extend(chain);
    }
    if git_oid.is_none()
        && let Some(reference) = git_ref
        && !({ let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) })
    {
        let chain = request_http_chain(
            context,
            scheme,
            "GET",
            &reference,
            &[],
            MAX_HTTP_BODY_BYTES,
            cookie_jar,
        )
        .await
        .unwrap_or_default();
        if let Some(response) = chain.last()
            && (200..300).contains(&response.status)
            && ({
let (chain, requested,): (& [HttpObservation], & str,) = (&chain, &reference,);
{

    chain.iter().all(|response| {
        Url::parse(&response.url)
            .ok()
            .is_some_and(|url| url.path().eq_ignore_ascii_case(requested))
    })

}

})
            && !baseline.is_some_and(|baseline| {
                looks_like_soft_404(baseline, response, baseline_path, &reference)
            })
            && let Some(object_id) = ({
let (body,): (& [u8],) = (&response.body,);
{
'inlined_first_git_object_id: {

    match std::str::from_utf8(body).ok() { Some(value) => value, None => break 'inlined_first_git_object_id None }.lines().find_map(|line| {
        line.trim_start_matches('^')
            .split_ascii_whitespace()
            .next()
            .and_then(|value: & str| {
    let value = value.trim();
    matches!(value.len(), 40 | 64)
        .then(|| value.to_ascii_lowercase())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
})
    })

}
}

})
        {
            endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "Exposed Git repository metadata", "A Git reference is publicly readable", vec![
                    format!("GET {reference} returned {}", response.status),
                    "Git object identifier detected; value withheld".to_owned(),
                ],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
            git_oid = Some(object_id);
        }
        endpoint.http.extend(chain);
    }
    if let Some(object_id) = git_oid
        && !({ let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) })
    {
        let object_path = format!("/.git/objects/{}/{}", &object_id[..2], &object_id[2..]);
        let chain = request_http_chain(
            context,
            scheme,
            "GET",
            &object_path,
            &[],
            MAX_HTTP_BODY_BYTES,
            cookie_jar,
        )
        .await
        .unwrap_or_default();
        if let Some(response) = chain.last()
            && (200..300).contains(&response.status)
            && ({
let (chain, requested,): (& [HttpObservation], & str,) = (&chain, &object_path,);
{

    chain.iter().all(|response| {
        Url::parse(&response.url)
            .ok()
            .is_some_and(|url| url.path().eq_ignore_ascii_case(requested))
    })

}

})
            && ({
let (body,): (& [u8],) = (&response.body,);
{
'inlined_valid_loose_git_object: {

    let mut output = Vec::new();
    let mut decoder = ZlibDecoder::new(body).take((MAX_HTTP_BODY_BYTES + 1) as u64);
    if decoder.read_to_end(&mut output).is_err() || output.len() > MAX_HTTP_BODY_BYTES {
        break 'inlined_valid_loose_git_object false;
    }
    let Some(nul) = output.iter().position(|byte| *byte == 0) else {
        break 'inlined_valid_loose_git_object false;
    };
    let Ok(header) = std::str::from_utf8(&output[..nul]) else {
        break 'inlined_valid_loose_git_object false;
    };
    let Some((kind, size)) = header.split_once(' ') else {
        break 'inlined_valid_loose_git_object false;
    };
    matches!(kind, "blob" | "tree" | "commit" | "tag")
        && size.parse::<usize>().ok() == Some(output.len().saturating_sub(nul + 1))

}
}

})
        {
            endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "Exposed Git repository object", "One referenced loose Git object is publicly readable", vec![
                    format!("GET {object_path} returned {}", response.status),
                    "Bounded zlib output contained a valid Git object header".to_owned(),
                ],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
        }
        endpoint.http.extend(chain);
    }

}
})
    .await;
    ({
let (endpoint, scheme, context, cookie_jar,): (& mut EndpointScan, & str, ProbeContext < '_ >, Option < & Mutex < EndpointCookieJar > >,) = (endpoint, scheme, context, cookie_jar,);
async move {

    if let Some(path) = {
let (port,): (u16,) = (context.port,);
{

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

} {
        if { let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) } {
            return;
        }
        let chain = request_http_chain(
            context,
            scheme,
            "GET",
            path,
            &[],
            MAX_HTTP_BODY_BYTES,
            cookie_jar,
        )
        .await
        .unwrap_or_default();
        if let Some(response) = chain.last()
            && (200..300).contains(&response.status)
            && let Some(detection) = ({
let (port, path, response, endpoint,): (u16, & str, & HttpObservation, & EndpointScan,) = (context.port, path, response, endpoint,);
let inlined_result: Option < ManagementDetection > = {
'inlined_management_detection: {

    let json = match serde_json::from_slice::<serde_json::Value>(&response.body).ok() { Some(value) => value, None => break 'inlined_management_detection None };
    match (port, path) {
        (2375 | 2376, "/version")
            if json.get("ApiVersion").is_some() && json.get("Version").is_some() =>
        {
            Some(ManagementDetection {
                product: "Docker Engine",
                version: ({
let (value, key,): (& serde_json :: Value, & str,) = (&json, "Version",);
{
'inlined_json_string: {

    match value.get(key) { Some(value) => value, None => break 'inlined_json_string None }.as_str().map(str::to_owned)

}
}

}),
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
                version: ({
let (value, key,): (& serde_json :: Value, & str,) = (&json, "etcdserver",);
{
'inlined_json_string: {

    match value.get(key) { Some(value) => value, None => break 'inlined_json_string None }.as_str().map(str::to_owned)

}
}

}),
                title: "Unauthenticated etcd API information",
                description: "The etcd API disclosed server and cluster information without authentication",
                service_evidence: "etcd version API JSON response",
                product_evidence: "etcd /version response contains etcdserver and etcdcluster",
            })
        }
        (5984, "/_all_dbs")
            if json.is_array() && ({
let (endpoint, key, expected,): (& EndpointScan, & str, & str,) = (endpoint, "couchdb", "Welcome",);
{

    endpoint.http.iter().any(|response| {
        serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|json| json.get(key)?.as_str().map(str::to_owned))
            .is_some_and(|value| value.eq_ignore_ascii_case(expected))
    })

}

}) =>
        {
            Some(ManagementDetection {
                product: "CouchDB",
                version: ({
let (endpoint, key,): (& EndpointScan, & str,) = (endpoint, "version",);
{

    endpoint.http.iter().find_map(|response| {
        serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|json| {
let (value, key,): (& serde_json :: Value, & str,) = (&json, key,);
{
'inlined_json_string: {

    match value.get(key) { Some(value) => value, None => break 'inlined_json_string None }.as_str().map(str::to_owned)

}
}

})
    })

}

}),
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
        (8086, "/query?q=SHOW%20DATABASES") if ({
let (json,): (& serde_json :: Value,) = (&json,);
{

    json.get("results")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|result| result.get("series")?.as_array())
        .flatten()
        .any(|series| series.get("name").and_then(|value| value.as_str()) == Some("databases"))

}

}) => {
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
            if ({
let (endpoint, keys,): (& EndpointScan, & [& str],) = (endpoint, &["version", "distribution"],);
let inlined_result: Option < String > = {

    endpoint.http.iter().find_map(|response| {
        let json = serde_json::from_slice::<serde_json::Value>(&response.body).ok()?;
        keys.iter()
            .try_fold(&json, |value, key| value.get(*key))?
            .as_str()
            .map(str::to_owned)
    })

};
inlined_result
}).as_deref()
                == Some("opensearch")
            {
                break 'inlined_management_detection Some(ManagementDetection {
                    product: "OpenSearch",
                    version: ({
let (endpoint, keys,): (& EndpointScan, & [& str],) = (endpoint, &["version", "number"],);
let inlined_result: Option < String > = {

    endpoint.http.iter().find_map(|response| {
        let json = serde_json::from_slice::<serde_json::Value>(&response.body).ok()?;
        keys.iter()
            .try_fold(&json, |value, key| value.get(*key))?
            .as_str()
            .map(str::to_owned)
    })

};
inlined_result
}),
                    title: "Unauthenticated OpenSearch cluster information",
                    description: "OpenSearch returned cluster health information without authentication",
                    service_evidence: "OpenSearch cluster-health JSON response",
                    product_evidence: "Root response explicitly identifies the OpenSearch distribution",
                });
            }
            Some(ManagementDetection {
                product: "Elasticsearch",
                version: ({
let (endpoint, keys,): (& EndpointScan, & [& str],) = (endpoint, &["version", "number"],);
let inlined_result: Option < String > = {

    endpoint.http.iter().find_map(|response| {
        let json = serde_json::from_slice::<serde_json::Value>(&response.body).ok()?;
        keys.iter()
            .try_fold(&json, |value, key| value.get(*key))?
            .as_str()
            .map(str::to_owned)
    })

};
inlined_result
}),
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
};
inlined_result
})
        {
            ({
let (endpoint, kind, confidence, evidence,): (& mut EndpointScan, ServiceKind, Confidence, & str,) = (endpoint, if scheme == "https" {
                    ServiceKind::Https
                } else {
                    ServiceKind::Http
                }, Confidence::High, detection.service_evidence,);

    if confidence >= endpoint.service_confidence {
        endpoint.service = kind;
        endpoint.service_confidence = confidence;
    }
    if !endpoint.evidence.iter().any(|item| item == evidence) {
        endpoint.evidence.push(evidence.to_owned());
    }

});
            add_product(
                endpoint,
                detection.product,
                ProductLayer::Server,
                detection.version,
                Confidence::High,
                detection.product_evidence.to_owned(),
            );
            endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, detection.title, detection.description, vec![
                    format!(
                        "GET {path} returned {} without authentication",
                        response.status
                    ),
                    detection.product_evidence.to_owned(),
                ],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
        } else if let Some(response) = chain.last()
            && (matches!(response.status, 401 | 403) || ({
let (chain,): (& [HttpObservation],) = (&chain,);
{

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

}))
        {
            endpoint.evidence.push(format!(
                "Protected management endpoint evidence: {path} returned {}",
                response.status
            ));
        }
        endpoint.http.extend(chain);
    }
    if context.scan.request.security_operations && !({ let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) }) {
        ({
let (endpoint, scheme, context, cookie_jar,): (& mut EndpointScan, & str, ProbeContext < '_ >, Option < & Mutex < EndpointCookieJar > >,) = (endpoint, scheme, context, cookie_jar,);
async move {

    let mut fingerprint_chains = if cookie_jar.is_none() {
        let paths = MANAGEMENT_PRODUCT_PROBES.iter()
            .filter(|probe| !endpoint.http.iter().any(|response| management_fingerprint(probe.kind, response)))
            .map(|probe| probe.fingerprint_path.to_owned()).collect();
        independent_http_chains(context, scheme, paths, None).await.into_iter().collect::<HashMap<_, _>>()
    } else {
        HashMap::new()
    };
    for probe in MANAGEMENT_PRODUCT_PROBES {
        if { let context = context; context.scan.cancel.is_cancelled() || crate::exposure::endpoint_health::stopped(context.ip, context.port) } {
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
            fingerprint_chain = if let Some(chain) = fingerprint_chains.remove(probe.fingerprint_path) {
                chain
            } else if cookie_jar.is_none() {
                Vec::new()
            } else { request_http_chain(
                context,
                scheme,
                "GET",
                probe.fingerprint_path,
                &[],
                MAX_HTTP_BODY_BYTES,
                cookie_jar,
            )
            .await
            .unwrap_or_default() };
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
        let chain = request_http_chain(
            context,
            scheme,
            "GET",
            probe.listing_path,
            &[],
            MAX_HTTP_BODY_BYTES,
            cookie_jar,
        )
        .await
        .unwrap_or_default();
        if let Some(response) = chain.last() {
            if matches!(response.status, 401 | 403) || ({
let (chain,): (& [HttpObservation],) = (&chain,);
{

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

}) {
                endpoint.evidence.push(format!(
                    "Protected {} management evidence: {} returned {}",
                    probe.product, probe.listing_path, response.status
                ));
            } else if (200..300).contains(&response.status)
                && ({
let (kind, response,): (ManagementProductKind, & HttpObservation,) = (probe.kind, response,);
{
'inlined_validated_management_listing: {

    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&response.body) else {
        break 'inlined_validated_management_listing false;
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
}

})
            {
                endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, &format!("Unauthenticated {} management data", probe.product), &format!(
                        "The {} interface returned validated {} data without authentication",
                        probe.product, probe.listing_name
                    ), vec![
                        format!(
                            "GET {} returned {} without authentication",
                            probe.listing_path, response.status
                        ),
                        format!("Validated {} listing structure", probe.listing_name),
                    ],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
            }
        }
        endpoint.http.extend(chain);
    }

}
}).await;
    }

}
}).await;
    let mut cleartext_challenges = endpoint
        .http
        .iter()
        .filter(|response| response.url.starts_with("http://"))
        .flat_map(|response| {
            ({ let (response, name): (&crate::HttpObservation, &str) = (response, "www-authenticate"); response.headers.iter().filter(move |(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()) }).map(|value| {
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
        endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "Authentication offered over cleartext HTTP", "The service advertises an authentication challenge without transport encryption", cleartext_challenges,);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
    }

}
}).await;
    }
    product_identification::probe(&mut endpoint, context).await;
    if !context.scan.cancel.is_cancelled() {
        let mut input = endpoint.clone();
        match crate::blocking::run(context.scan.cancel, move |cancel| {
            apply_product_rules(&mut input, cancel);
            if !cancel.is_cancelled() {
                crate::product_catalog::reconcile(&mut input);
                record_observed_web_surfaces(&mut input);
            }
            input
        }).await {
            Ok(processed) => endpoint = processed,
            Err(crate::blocking::Error::Cancelled) => {}
            Err(error) => endpoint.evidence.push(error.to_string()),
        }
    }
    ({
        let (endpoint,): (&mut EndpointScan,) = (&mut endpoint,);

        if endpoint.service == ServiceKind::Unknown
            && let Some(name) = ({
                let (port,): (u16,) = (endpoint.port,);
                let inlined_result: Option<&'static str> =
                    { curated_tcp_port_metadata(port).map(|metadata| metadata.service_name) };
                inlined_result
            })
        {
            endpoint.service_confidence = Confidence::Low;
            endpoint.evidence.push(format!(
                "Conventional port association suggests {name}; service was not confirmed"
            ));
        }
    });
    endpoint
}

pub(super) fn mysql_banner_version(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 5 || bytes[3] != 0 || bytes[4] != 10 {
        return None;
    }
    let length =
        usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16);
    if length < 32 || length.checked_add(4)? > bytes.len() {
        return None;
    }
    let end = bytes[5..length + 4].iter().position(|byte| *byte == 0)? + 5;
    if end + 16 > length + 4 {
        return None;
    }
    let version = std::str::from_utf8(&bytes[5..end]).ok()?;
    (version.starts_with(|c: char| c.is_ascii_digit())
        && version.bytes().all(|b| b.is_ascii_graphic()))
    .then(|| version.to_owned())
}

pub(crate) fn add_product(
    endpoint: &mut EndpointScan,
    name: &str,
    layer: ProductLayer,
    version: Option<String>,
    confidence: Confidence,
    evidence: String,
) {
    let name = crate::product_catalog::canonical_product_name(name);
    let mut record = super::technology_evidence::observation("Supporting product detection", &evidence);
    record.endpoint = Some(std::net::SocketAddr::new(endpoint.ip, endpoint.port).to_string());
    record.extracted_version = version.as_deref().map(super::technology_evidence::safe_value);
    record.supporting_detection = Some(name.to_owned());
    if let Some(product) = endpoint.products.iter_mut().find(|product| {
        crate::product_catalog::canonical_product_name(&product.name).eq_ignore_ascii_case(name)
    }) {
        if !product.observations.contains(&record) { product.observations.push(record); }
        product.name = name.to_owned();
        if version.is_some() && (confidence > product.confidence || product.version.is_none()) {
            product.version = version;
        }
        if crate::product_catalog::panel_product_name(name).is_some() {
            product.layer = ProductLayer::Server;
        }
        product.confidence = product.confidence.max(confidence);
        if !product.evidence.contains(&evidence) {
            product.evidence.push(evidence);
        }
    } else {
        endpoint.products.push(ProductDetection {
            observations: vec![record],
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

fn security_operations_exposure_probes() -> Vec<ExposureProbe> {
    let mut probes = Vec::new();
    for base in ["/config.php"] {
        for suffix in [".bak", ".old", ".orig", "~", ".swp", ".swo"] {
            let signature = if matches!(suffix, ".swp" | ".swo") {
                ExposureSignature::VimSwap
            } else {
                ExposureSignature::PhpConfig
            };
            ({
                let (probes, family, path, signature): (
                    &mut Vec<ExposureProbe>,
                    &'static str,
                    String,
                    ExposureSignature,
                ) = (&mut probes, "Backup", format!("{base}{suffix}"), signature);

                probes.push(ExposureProbe {
                    family,
                    path,
                    signature,
                    tier: ProbeTier::SecurityOperations,
                });
            });
        }
    }
    for name in ["backup", "site", "source", "www", "dist"] {
        for extension in ["zip", "tar", "tar.gz", "tgz", "gz", "gzip", "7z"] {
            ({
                let (probes, family, path, signature): (
                    &mut Vec<ExposureProbe>,
                    &'static str,
                    String,
                    ExposureSignature,
                ) = (
                    &mut probes,
                    "Archive",
                    format!("/{name}.{extension}"),
                    ExposureSignature::Archive,
                );

                probes.push(ExposureProbe {
                    family,
                    path,
                    signature,
                    tier: ProbeTier::SecurityOperations,
                });
            });
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
        ({
            let (probes, family, path, signature): (
                &mut Vec<ExposureProbe>,
                &'static str,
                String,
                ExposureSignature,
            ) = (
                &mut probes,
                "Framework configuration",
                path.to_owned(),
                signature,
            );

            probes.push(ExposureProbe {
                family,
                path,
                signature,
                tier: ProbeTier::SecurityOperations,
            });
        });
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
        ({
            let (probes, family, path, signature): (
                &mut Vec<ExposureProbe>,
                &'static str,
                String,
                ExposureSignature,
            ) = (&mut probes, "Cloud credentials", path.to_owned(), signature);

            probes.push(ExposureProbe {
                family,
                path,
                signature,
                tier: ProbeTier::SecurityOperations,
            });
        });
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
        ({
            let (probes, family, path, signature): (
                &mut Vec<ExposureProbe>,
                &'static str,
                String,
                ExposureSignature,
            ) = (&mut probes, "Git", path.to_owned(), signature);

            probes.push(ExposureProbe {
                family,
                path,
                signature,
                tier: ProbeTier::SecurityOperations,
            });
        });
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
        ({
            let (probes, family, path, signature): (
                &mut Vec<ExposureProbe>,
                &'static str,
                String,
                ExposureSignature,
            ) = (
                &mut probes,
                "Actuator",
                path.to_owned(),
                ExposureSignature::Actuator(kind),
            );

            probes.push(ExposureProbe {
                family,
                path,
                signature,
                tier: ProbeTier::SecurityOperations,
            });
        });
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
        ({
            let (probes, family, path, signature): (
                &mut Vec<ExposureProbe>,
                &'static str,
                String,
                ExposureSignature,
            ) = (&mut probes, "CI artifact", path.to_owned(), signature);

            probes.push(ExposureProbe {
                family,
                path,
                signature,
                tier: ProbeTier::SecurityOperations,
            });
        });
    }
    probes
}

pub(super) fn security_operations_exposure_path_count(limit: usize) -> usize {
    security_operations_exposure_probes()
        .len()
        .min(96)
        .min(limit)
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

fn management_fingerprint(kind: ManagementProductKind, response: &HttpObservation) -> bool {
    let text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    let json = serde_json::from_slice::<serde_json::Value>(&response.body).ok();
    let path = Url::parse(&response.url)
        .ok()
        .map(|u| u.path().to_owned())
        .unwrap_or_default();
    match kind {
        ManagementProductKind::Jenkins => {
            ({
                let (response, name): (&crate::HttpObservation, &str) = (response, "x-jenkins");
                response
                    .headers
                    .iter()
                    .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.as_str())
            })
            .next()
            .is_some()
                || text.contains("dashboard [jenkins]")
                || text.contains("jenkins.io") && text.contains("login")
        }
        ManagementProductKind::Grafana => {
            text.contains("grafanabootdata")
                || text.contains("<title>grafana</title>")
                || json.as_ref().is_some_and(|json| {
                    path == "/api/health"
                        && !response.body_truncated
                        && json.get("database").is_some()
                        && (json.get("version").is_some() || json.get("commit").is_some())
                })
        }
        ManagementProductKind::ArgoCd => {
            text.contains("<title>argo cd</title>")
                || text.contains("argocd") && text.contains("login")
                || json.as_ref().is_some_and(|json| {
                    path == "/api/version"
                        && !response.body_truncated
                        && json.get("Version").is_some()
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
                || ({
                    let (response, name): (&crate::HttpObservation, &str) =
                        (response, "x-jupyter-version");
                    response
                        .headers
                        .iter()
                        .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.as_str())
                })
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
                    path == "/api/status"
                        && !response.body_truncated
                        && json.get("Version").is_some()
                        && json.get("InstanceID").is_some()
                })
        }
    }
}

fn management_version(kind: ManagementProductKind, response: &HttpObservation) -> Option<String> {
    match kind {
        ManagementProductKind::Jenkins => ({
            let (response, name): (&crate::HttpObservation, &str) = (response, "x-jenkins");
            response
                .headers
                .iter()
                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        })
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

struct ManagementDetection {
    product: &'static str,
    version: Option<String>,
    title: &'static str,
    description: &'static str,
    service_evidence: &'static str,
    product_evidence: &'static str,
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
        if {
            let context = context;
            context.scan.cancel.is_cancelled()
                || crate::exposure::endpoint_health::stopped(context.ip, context.port)
        } {
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
            let chain = request_http_chain(
                context,
                scheme,
                method,
                path,
                &headers,
                MAX_HTTP_BODY_BYTES,
                cookie_jar,
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
    let allow_origins = ({
        let (response, name): (&crate::HttpObservation, &str) =
            (response, "access-control-allow-origin");
        response
            .headers
            .iter()
            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
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
        url: ({
            let (value,): (&str,) = (&response.url,);
            let inlined_result: String = {
                'inlined_safe_http_url: {
                    let Ok(mut url) = Url::parse(value) else {
                        break 'inlined_safe_http_url value.chars().take(512).collect();
                    };
                    url.set_query(None);
                    url.set_fragment(None);
                    url.to_string()
                }
            };
            inlined_result
        }),
        origin_kind,
        method,
        status: response.status,
        mode,
        credentials: ({
            let (response, name): (&crate::HttpObservation, &str) =
                (response, "access-control-allow-credentials");
            response
                .headers
                .iter()
                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        })
        .any(|value| value.trim().eq_ignore_ascii_case("true")),
        methods: ({
            let (response, name): (&HttpObservation, &str) =
                (response, "access-control-allow-methods");
            let inlined_result: BTreeSet<String> = {
                ({
                    let (response, name): (&crate::HttpObservation, &str) = (response, name);
                    response
                        .headers
                        .iter()
                        .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.as_str())
                })
                .flat_map(|value| value.split(','))
                .map(|value| value.trim().to_ascii_uppercase())
                .filter(|value| !value.is_empty())
                .collect()
            };
            inlined_result
        }),
        headers: ({
            let (response, name): (&HttpObservation, &str) =
                (response, "access-control-allow-headers");
            let inlined_result: BTreeSet<String> = {
                ({
                    let (response, name): (&crate::HttpObservation, &str) = (response, name);
                    response
                        .headers
                        .iter()
                        .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.as_str())
                })
                .flat_map(|value| value.split(','))
                .map(|value| value.trim().to_ascii_uppercase())
                .filter(|value| !value.is_empty())
                .collect()
            };
            inlined_result
        }),
        vary_origin: ({
            let (response, name): (&crate::HttpObservation, &str) = (response, "vary");
            response
                .headers
                .iter()
                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        })
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case("origin")),
    }
}

fn add_cors_sample_findings(endpoint: &mut EndpointScan, samples: &[CorsSample], advanced: bool) {
    for sample in samples {
        let evidence = format!(
            "{} {} returned {}; tested {} origin",
            sample.method, sample.url, sample.status, sample.origin_kind
        );
        match sample.mode {
            CorsAllowMode::Wildcard => endpoint.findings.push({
                let (endpoint, title, description, evidence): (
                    &EndpointScan,
                    &str,
                    &str,
                    Vec<String>,
                ) = (
                    endpoint,
                    "Wildcard CORS origin is allowed",
                    "The response permits requests from every web origin",
                    vec![evidence.clone()],
                );
                {
                    ExposureFinding {
        details: Vec::new(),
                        title: title.to_owned(),
                        description: description.to_owned(),
                        ip: endpoint.ip,
                        port: endpoint.port,
                        transport: endpoint.transport,
                        evidence,
                        component_kind: None,
                    }
                }
            }),
            CorsAllowMode::Reflected if sample.origin_kind == "null" => {
                endpoint.findings.push({
                    let (endpoint, title, description, evidence): (
                        &EndpointScan,
                        &str,
                        &str,
                        Vec<String>,
                    ) = (
                        endpoint,
                        "Null CORS origin is allowed",
                        "The response permits the opaque null origin",
                        vec![evidence.clone()],
                    );
                    {
                        ExposureFinding {
        details: Vec::new(),
                            title: title.to_owned(),
                            description: description.to_owned(),
                            ip: endpoint.ip,
                            port: endpoint.port,
                            transport: endpoint.transport,
                            evidence,
                            component_kind: None,
                        }
                    }
                });
            }
            CorsAllowMode::Reflected if sample.credentials => endpoint.findings.push({
                let (endpoint, title, description, evidence): (
                    &EndpointScan,
                    &str,
                    &str,
                    Vec<String>,
                ) = (
                    endpoint,
                    "Arbitrary CORS origin reflected with credentials",
                    "The server reflects an untrusted origin while allowing credentials",
                    vec![
                        evidence.clone(),
                        "Access-Control-Allow-Credentials: true".to_owned(),
                    ],
                );
                {
                    ExposureFinding {
        details: Vec::new(),
                        title: title.to_owned(),
                        description: description.to_owned(),
                        ip: endpoint.ip,
                        port: endpoint.port,
                        transport: endpoint.transport,
                        evidence,
                        component_kind: None,
                    }
                }
            }),
            CorsAllowMode::Reflected if sample.origin_kind == "arbitrary" => {
                endpoint.findings.push({
                    let (endpoint, title, description, evidence): (
                        &EndpointScan,
                        &str,
                        &str,
                        Vec<String>,
                    ) = (
                        endpoint,
                        "Arbitrary CORS origin is reflected",
                        "The server reflects an untrusted origin without credential access",
                        vec![evidence.clone()],
                    );
                    {
                        ExposureFinding {
        details: Vec::new(),
                            title: title.to_owned(),
                            description: description.to_owned(),
                            ip: endpoint.ip,
                            port: endpoint.port,
                            transport: endpoint.transport,
                            evidence,
                            component_kind: None,
                        }
                    }
                });
            }
            _ => {}
        }
        if sample.mode == CorsAllowMode::Reflected && !sample.vary_origin {
            endpoint.findings.push({
                let (endpoint, title, description, evidence): (
                    &EndpointScan,
                    &str,
                    &str,
                    Vec<String>,
                ) = (
                    endpoint,
                    "CORS response omits Vary: Origin",
                    "A dynamic allow-origin response can be incorrectly reused by shared caches",
                    vec![evidence.clone()],
                );
                {
                    ExposureFinding {
        details: Vec::new(),
                        title: title.to_owned(),
                        description: description.to_owned(),
                        ip: endpoint.ip,
                        port: endpoint.port,
                        transport: endpoint.transport,
                        evidence,
                        component_kind: None,
                    }
                }
            });
        }
        if advanced
            && sample.mode == CorsAllowMode::Reflected
            && matches!(sample.origin_kind, "hostname-prefix" | "hostname-suffix")
        {
            endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "CORS hostname validation is bypassable", "The allow-origin policy accepted an attacker-controlled hostname containing the trusted hostname", vec![evidence],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
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
                endpoint.findings.push({
                    let (endpoint, title, description, evidence): (
                        &EndpointScan,
                        &str,
                        &str,
                        Vec<String>,
                    ) = (
                        endpoint,
                        "CORS GET and preflight policies are inconsistent",
                        "GET and preflight responses apply materially different CORS policies",
                        vec![format!(
                            "GET and OPTIONS differ at {} for {} origin",
                            get.path, get.origin_kind
                        )],
                    );
                    {
                        ExposureFinding {
        details: Vec::new(),
                            title: title.to_owned(),
                            description: description.to_owned(),
                            ip: endpoint.ip,
                            port: endpoint.port,
                            transport: endpoint.transport,
                            evidence,
                            component_kind: None,
                        }
                    }
                });
            }
        }
    }
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
    let external_origins = {
        let (indicators,): (&[CrawlExternalIndicator],) = (external_indicators,);
        let inlined_result: Vec<String> = {
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
        };
        inlined_result
    };
    for endpoint in endpoints.iter_mut() {
        if cancel.is_cancelled() {
            return;
        }
        if endpoint_health::stopped(endpoint.ip, endpoint.port) {
            continue;
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
                && ({
                    let (resource,): (&CrawledResource,) = (resource,);
                    {
                        resource
                            .content_type
                            .as_deref()
                            .is_some_and(|content_type| {
                                content_type.to_ascii_lowercase().contains("json")
                            })
                            || Url::parse(&resource.url).ok().is_some_and(|url| {
                                let path = url.path().to_ascii_lowercase();
                                [
                                    "/api/", "/api", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/",
                                ]
                                .iter()
                                .any(|marker| path.contains(marker))
                            })
                    }
                })
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
            } else if {
                let (root, candidate): (&[CorsSample], &[CorsSample]) = (&root_samples, &samples);
                {
                    candidate.iter().any(|sample| {
                        let Some(reference) = root.iter().find(|reference| {
                            reference.origin_kind == sample.origin_kind
                                && reference.method == sample.method
                        }) else {
                            return false;
                        };
                        ({
                            let (inlined_self,): (&CorsSample,) = (&(sample),);
                            {
                                matches!(
                                    inlined_self.mode,
                                    CorsAllowMode::Wildcard | CorsAllowMode::Reflected
                                )
                            }
                        }) && !({
                            let (inlined_self,): (&CorsSample,) = (&(reference),);
                            {
                                matches!(
                                    inlined_self.mode,
                                    CorsAllowMode::Wildcard | CorsAllowMode::Reflected
                                )
                            }
                        }) || sample.credentials && !reference.credentials
                            || sample.mode == CorsAllowMode::Wildcard
                                && reference.mode != CorsAllowMode::Wildcard
                            || !reference.methods.is_empty()
                                && !sample.methods.is_subset(&reference.methods)
                            || !reference.headers.is_empty()
                                && !sample.headers.is_subset(&reference.headers)
                    })
                }
            } {
                endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "CORS policy is weaker on an API endpoint", "A tested API-like endpoint applies a materially weaker policy than the origin root", vec![format!("Weaker CORS policy at {scheme}://{hostname}:{}{path}", endpoint.port)],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
            }
        }
        let api_paths = paths.iter().take(4).cloned().collect::<Vec<_>>();
        let mut checked_dns = HashSet::new();
        for origin in external_origins.iter().take(8) {
            for path in &api_paths {
                if cancel.is_cancelled() {
                    return;
                }
                let chain = request_http_chain(
                    context,
                    scheme,
                    "GET",
                    path,
                    &[("Origin", origin.as_str())],
                    MAX_HTTP_BODY_BYTES,
                    None,
                )
                .await
                .unwrap_or_default();
                let trusted = chain
                    .last()
                    .map(|response| cors_sample(path, "external", origin, "GET", response))
                    .is_some_and(|sample| {
                        let (inlined_self,): (&CorsSample,) = (&(sample),);
                        {
                            matches!(
                                inlined_self.mode,
                                CorsAllowMode::Wildcard | CorsAllowMode::Reflected
                            )
                        }
                    });
                endpoint.http.extend(chain);
                if trusted
                    && checked_dns.insert(origin.clone())
                    && let Some((host, cname, provider)) =
                        ({
let (origin, cancel,): (& str, & CancellationToken,) = (origin, cancel,);
async move {

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
}).await
                {
                    endpoint.findings.push({
let (endpoint, title, description, evidence,): (& EndpointScan, & str, & str, Vec < String >,) = (endpoint, "Potential CORS-trusted DNS takeover", "A CORS-trusted external origin terminates at a recognized dangling service-provider CNAME", vec![format!(
                            "Trusted origin {origin}; hostname {host}; provider {provider}; terminal CNAME {cname}; registration was not attempted"
                        )],);
{

    ExposureFinding {
        details: Vec::new(),
        title: title.to_owned(),
        description: description.to_owned(),
        ip: endpoint.ip,
        port: endpoint.port,
        transport: endpoint.transport,
        evidence,
        component_kind: None,
    }

}

});
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

pub(super) fn looks_like_soft_404(
    baseline: &HttpObservation,
    candidate: &HttpObservation,
    baseline_path: &str,
    candidate_path: &str,
) -> bool {
    if baseline.status != candidate.status {
        return false;
    }
    if ({
        let (response, request_path): (&HttpObservation, &str) = (baseline, baseline_path);
        let inlined_result: Option<String> = {
            'inlined_normalize_soft_redirect: {
                let location = match response.redirect_location.as_deref() {
                    Some(value) => value,
                    None => break 'inlined_normalize_soft_redirect None,
                };
                let source = match Url::parse(&response.url).ok() {
                    Some(value) => value,
                    None => break 'inlined_normalize_soft_redirect None,
                };
                let mut target = match source.join(location).ok() {
                    Some(value) => value,
                    None => break 'inlined_normalize_soft_redirect None,
                };
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
        };
        inlined_result
    }) != ({
        let (response, request_path): (&HttpObservation, &str) = (candidate, candidate_path);
        let inlined_result: Option<String> = {
            'inlined_normalize_soft_redirect: {
                let location = match response.redirect_location.as_deref() {
                    Some(value) => value,
                    None => break 'inlined_normalize_soft_redirect None,
                };
                let source = match Url::parse(&response.url).ok() {
                    Some(value) => value,
                    None => break 'inlined_normalize_soft_redirect None,
                };
                let mut target = match source.join(location).ok() {
                    Some(value) => value,
                    None => break 'inlined_normalize_soft_redirect None,
                };
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
        };
        inlined_result
    }) {
        return false;
    }
    if baseline.body == candidate.body {
        return true;
    }
    let baseline = {
        let (body, path): (&[u8], &str) = (&baseline.body, baseline_path);
        let inlined_result: String = {
            String::from_utf8_lossy(body)
                .to_ascii_lowercase()
                .replace(&path.to_ascii_lowercase(), "{path}")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        inlined_result
    };
    let candidate = {
        let (body, path): (&[u8], &str) = (&candidate.body, candidate_path);
        let inlined_result: String = {
            String::from_utf8_lossy(body)
                .to_ascii_lowercase()
                .replace(&path.to_ascii_lowercase(), "{path}")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        inlined_result
    };
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

async fn independent_http_chains(
    context: ProbeContext<'_>,
    scheme: &str,
    paths: Vec<String>,
    cookie_jar: Option<&Mutex<EndpointCookieJar>>,
) -> Vec<(String, Vec<HttpObservation>)> {
    let mut seen = HashSet::new();
    let paths = paths
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect::<Vec<_>>();
    let concurrency = if cookie_jar.is_some() {
        1
    } else {
        context.scan.request.concurrency.clamp(1, 4)
    };
    let requests = futures_util::stream::iter(paths.into_iter().enumerate())
        .map(|(index, path)| async move {
            let request = request_http_chain(
                context,
                scheme,
                "GET",
                &path,
                &[],
                MAX_HTTP_BODY_BYTES,
                cookie_jar,
            );
            let chain = if cookie_jar.is_some() {
                request.await
            } else {
                endpoint_health::independent(request).await
            }
            .unwrap_or_default();
            (index, path, chain)
        })
        .buffer_unordered(concurrency);
    tokio::pin!(requests);
    let mut results = Vec::new();
    loop {
        let result = tokio::select! {
            biased;
            _ = context.scan.cancel.cancelled() => break,
            result = requests.next() => result,
        };
        let Some(result) = result else {
            break;
        };
        results.push(result);
        if endpoint_health::stopped(context.ip, context.port) {
            break;
        }
    }
    results.sort_by_key(|(index, _, _)| *index);
    results
        .into_iter()
        .map(|(_, path, chain)| (path, chain))
        .collect()
}

async fn request_http_chain(
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
        ({
            let hostname: &str = context.scan.hostname;
            if hostname.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("[{hostname}]")
            } else {
                hostname.to_owned()
            }
        }),
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
        if {
            let context = context;
            context.scan.cancel.is_cancelled()
                || crate::exposure::endpoint_health::stopped(context.ip, context.port)
        } {
            return Err(if {
                let context = context;
                crate::exposure::endpoint_health::stopped(context.ip, context.port)
            } {
                endpoint_health::STOP_REASON
            } else {
                "Scan cancelled"
            }
            .to_owned());
        }
        let scheme = url.scheme();
        if !matches!(scheme, "http" | "https") {
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
        let request = single_http_request(
            ProbeContext {
                port: port,
                ..(context)
            },
            scheme,
            method,
            &request_path,
            extra_headers,
            body_limit,
            cookie_header.as_deref(),
        )
        .await;
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
        observations.push(response);
        let Some(location) = observations
            .last()
            .and_then(|response| response.redirect_location.as_deref())
        else {
            break;
        };
        if redirect_count == 3 {
            break;
        }
        let next = match url.join(location) {
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

pub(super) async fn single_http_request(
    context: ProbeContext<'_>,
    scheme: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body_limit: usize,
    cookie_header: Option<&str>,
) -> Result<HttpObservation, String> {
    http_exchange(context, scheme, method, body_limit, true, path == "/" && matches!(method, "GET" | "HEAD"), "HTTP probe timed out", || {
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
        request_bytes.into_bytes()
    }).await
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
    let safe_baseline = path == "/"
        && method == "GET"
        && headers.is_empty()
        && body.is_empty()
        && host_override.is_none();
    http_exchange(context, scheme, method, MAX_HTTP_BODY_BYTES, safe_baseline, safe_baseline, "Active HTTP probe timed out", || {
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
        bytes
    }).await
}

async fn http_exchange(
    context: ProbeContext<'_>,
    scheme: &str,
    method: &str,
    body_limit: usize,
    monitor: bool,
    safe_baseline: bool,
    timeout_message: &str,
    build_request: impl FnOnce() -> Vec<u8>,
) -> Result<HttpObservation, String> {
    let attempt = endpoint_health::begin(context.ip, context.port, context.scan.cancel).await?;
    let bytes = build_request();
    let result = endpoint_health::inside(http_exchange_bytes(
        context,
        scheme,
        method,
        body_limit,
        timeout_message,
        &bytes,
    ))
    .await;
    if let Some(attempt) = attempt {
        let outcome = if monitor {
            endpoint_health::outcome(
                result.as_ref().ok().map(|response| response.status),
                result.as_ref().err().map(String::as_str),
            )
        } else if let Err(error) = &result {
            endpoint_health::outcome(None, Some(error))
        } else {
            endpoint_health::Outcome::Ignored
        };
        let baseline = (monitor && safe_baseline).then(|| {
            endpoint_health::Baseline::Http(endpoint_health::HttpBaseline {
                hostname: context.scan.hostname.to_owned(),
                scheme: scheme.to_owned(),
                method: method.to_owned(),
                bytes,
                client_certificate: context.scan.client_certificate.cloned(),
                connection_timeout: context.scan.request.connection_timeout,
                probe_timeout: context.scan.request.probe_timeout,
            })
        });
        attempt
            .finish_http(outcome, baseline, context.scan.cancel)
            .await;
    }
    result
}

async fn http_exchange_bytes(
    context: ProbeContext<'_>,
    scheme: &str,
    method: &str,
    body_limit: usize,
    timeout_message: &str,
    bytes: &[u8],
) -> Result<HttpObservation, String> {
    let started = Instant::now();
    let operation = async {
        let mut stream = connect_http_stream(context, scheme).await?;
        stream
            .write_all(bytes)
            .await
            .map_err(|error| error.to_string())?;
        stream.flush().await.map_err(|error| error.to_string())?;
        let (bytes, framing) = ({
            let (stream, method, body_limit): (&mut ScanIo, &str, usize) =
                (&mut stream, method, body_limit);
            async move {
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
                        header_end = {
                            let (bytes,): (&[u8],) = (&bytes,);
                            let inlined_result: Option<usize> = {
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
                            };
                            inlined_result
                        };
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
                        let header_text =
                            String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                        let body_length = bytes.len().saturating_sub(end);
                        if let Some(content_length) = ({
                            let (headers,): (&str,) = (&header_text,);
                            let inlined_result: Option<usize> = {
                                headers.lines().find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.trim()
                                        .eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse().ok())
                                        .flatten()
                                })
                            };
                            inlined_result
                        }) && body_length >= content_length.min(body_limit + 1)
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
        })
        .await?;
        let method = method.to_owned();
        let mut response = crate::blocking::run(context.scan.cancel, move |cancel| {
            let method = method.as_str();
            {
                let (method, bytes, body_limit, mut framing): (
                    &str,
                    Vec<u8>,
                    usize,
                    ResponseFraming,
                ) = (method, bytes, body_limit, framing);
                let inlined_result: Result<HttpObservation, String> = {
                    'inlined_parse_http_response: {
                        let header_end = match ({
                            let (bytes,): (&[u8],) = (&bytes,);
                            let inlined_result: Option<usize> = {
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
                            };
                            inlined_result
                        })
                        .ok_or_else(|| "Incomplete HTTP headers".to_owned())
                        {
                            Ok(value) => value,
                            Err(error) => {
                                break 'inlined_parse_http_response Err(
                                    ::core::convert::From::from(error),
                                );
                            }
                        };
                        let header_text = String::from_utf8_lossy(&bytes[..header_end]);
                        let mut lines = header_text.lines();
                        let status_line = match lines
                            .next()
                            .ok_or_else(|| "Missing HTTP status line".to_owned())
                        {
                            Ok(value) => value,
                            Err(error) => {
                                break 'inlined_parse_http_response Err(
                                    ::core::convert::From::from(error),
                                );
                            }
                        };
                        let mut status_parts = status_line.trim_end_matches('\r').splitn(3, ' ');
                        let protocol = status_parts.next().unwrap_or_default();
                        if !protocol.starts_with("HTTP/") {
                            break 'inlined_parse_http_response Err(
                                "Response does not contain an HTTP status line".to_owned(),
                            );
                        }
                        let status = match match status_parts
                            .next()
                            .ok_or_else(|| "HTTP status code is missing".to_owned())
                        {
                            Ok(value) => value,
                            Err(error) => {
                                break 'inlined_parse_http_response Err(
                                    ::core::convert::From::from(error),
                                );
                            }
                        }
                        .parse::<u16>()
                        .map_err(|_| "HTTP status code is invalid".to_owned())
                        {
                            Ok(value) => value,
                            Err(error) => {
                                break 'inlined_parse_http_response Err(
                                    ::core::convert::From::from(error),
                                );
                            }
                        };
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
                            && let Some((decoded, chunks, complete)) = ({
                                let (bytes, body_limit): (&[u8], usize) = (&body, body_limit);
                                {
                                    'inlined_decode_chunked: {
                                        let mut position = 0usize;
                                        let mut output = Vec::new();
                                        let mut chunks = 0usize;
                                        loop {
                                            if cancel.is_cancelled() {
                                                return Err("Scan cancelled".to_owned());
                                            }
                                            if position >= bytes.len() {
                                                break 'inlined_decode_chunked (chunks > 0)
                                                    .then_some((output, chunks, false));
                                            }
                                            let Some(line_end) = bytes[position..]
                                                .windows(2)
                                                .position(|window| window == b"\r\n")
                                                .map(|line_end| line_end + position)
                                            else {
                                                break 'inlined_decode_chunked (chunks > 0)
                                                    .then_some((output, chunks, false));
                                            };
                                            let size_text = match std::str::from_utf8(
                                                &bytes[position..line_end],
                                            )
                                            .ok()
                                            {
                                                Some(value) => value,
                                                None => break 'inlined_decode_chunked None,
                                            };
                                            let size = match usize::from_str_radix(
                                                match size_text.split(';').next() {
                                                    Some(value) => value,
                                                    None => break 'inlined_decode_chunked None,
                                                }
                                                .trim(),
                                                16,
                                            )
                                            .ok()
                                            {
                                                Some(value) => value,
                                                None => break 'inlined_decode_chunked None,
                                            };
                                            position = line_end + 2;
                                            if size == 0 {
                                                break 'inlined_decode_chunked Some((
                                                    output, chunks, true,
                                                ));
                                            }
                                            let end = match position.checked_add(size) {
                                                Some(value) => value,
                                                None => break 'inlined_decode_chunked None,
                                            };
                                            if end + 2 > bytes.len() {
                                                break 'inlined_decode_chunked (chunks > 0)
                                                    .then_some((output, chunks, false));
                                            }
                                            output.extend_from_slice(&bytes[position..end]);
                                            chunks += 1;
                                            if output.len() > body_limit {
                                                break 'inlined_decode_chunked Some((
                                                    output, chunks, false,
                                                ));
                                            }
                                            position = end + 2;
                                        }
                                    }
                                }
                            })
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
                            redirect_location,
                            duration_ms: 0.0,
                            framing,
                        })
                    }
                };
                inlined_result
            }
        })
        .await
        .map_err(|error| error.to_string())??;
        response.duration_ms = started.elapsed().as_secs_f64() * 1_000.0;
        Ok(response)
    };
    tokio::select! {
        biased;
        _ = context.scan.cancel.cancelled() => Err("Scan cancelled".to_owned()),
        result = tokio::time::timeout(context.scan.request.probe_timeout, operation) => {
            result.map_err(|_| timeout_message.to_owned())?
        }
    }
}

pub(super) async fn replay_health_baseline(
    baseline: &endpoint_health::HttpBaseline,
    remote: std::net::SocketAddr,
    cancel: &CancellationToken,
) -> Result<u16, String> {
    let request = ExposureScanRequest {
        connection_timeout: baseline.connection_timeout,
        probe_timeout: baseline.probe_timeout,
        ..Default::default()
    };
    let limiter = ConnectionRateLimiter::new(1);
    let context = ProbeContext {
        ip: remote.ip(),
        port: remote.port(),
        scan: ScanContext {
            hostname: &baseline.hostname,
            request: &request,
            cancel,
            limiter: &limiter,
            client_certificate: baseline.client_certificate.as_ref(),
        },
    };
    http_exchange_bytes(
        context,
        &baseline.scheme,
        &baseline.method,
        1024,
        "Baseline request timed out",
        &baseline.bytes,
    )
    .await
    .map(|response| response.status)
}

pub(super) async fn active_raw_http_exchange(
    context: ProbeContext<'_>,
    scheme: &str,
    request: &[u8],
) -> Result<(Vec<u8>, f64, bool), String> {
    let _attempt = endpoint_health::begin(context.ip, context.port, context.scan.cancel).await?;
    endpoint_health::inside({
        let (context, scheme, request): (ProbeContext<'_>, &str, &[u8]) =
            (context, scheme, request);
        async move {
            if !matches!(scheme, "http" | "https") {
                return Err("Raw request scheme must be HTTP or HTTPS".to_owned());
            }
            if request.len() > 128 * 1024 {
                return Err("Raw request exceeds the 128 KiB limit".to_owned());
            }
            let started = Instant::now();
            let operation = async {
                let mut stream = connect_http_stream(context, scheme).await?;
                stream
                    .write_all(request)
                    .await
                    .map_err(|error| error.to_string())?;
                stream.flush().await.map_err(|error| error.to_string())?;
                let mut output = Vec::new();
                let mut buffer = [0u8; 8192];
                let mut peer_closed = false;
                loop {
                    match tokio::time::timeout(Duration::from_millis(750), stream.read(&mut buffer))
                        .await
                    {
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
    })
    .await
}

pub(super) async fn websocket_upgrade_exchange(
    context: ProbeContext<'_>,
    scheme: &str,
    request: &[u8],
) -> Result<Vec<u8>, String> {
    let _attempt = endpoint_health::begin(context.ip, context.port, context.scan.cancel).await?;
    endpoint_health::inside({
        let (context, scheme, request): (ProbeContext<'_>, &str, &[u8]) =
            (context, scheme, request);
        async move {
            let operation = async {
                let mut stream = connect_http_stream(context, scheme).await?;
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
                        return Err(
                            "WebSocket upgrade response ended before its headers".to_owned()
                        );
                    }
                    output.extend_from_slice(&buffer[..length]);
                    if let Some(end) = {
                        let (bytes,): (&[u8],) = (&output,);
                        let inlined_result: Option<usize> = {
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
                        };
                        inlined_result
                    } {
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
    })
    .await
}

async fn connect_http_stream(context: ProbeContext<'_>, scheme: &str) -> Result<ScanIo, String> {
    if scheme == "http" {
        let mut candidate = limited_connect(context).await;
        return candidate.stream.take().map(ScanIo::Plain).ok_or_else(|| {
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
        Ok(success) => Ok(ScanIo::Tls(Box::new(success.stream))),
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
                .map(|success| ScanIo::Tls(Box::new(success.stream)))
                .map_err(|fallback| {
                    format!(
                        "Validated TLS failed: {validated_error}; permissive retry failed: {}",
                        fallback.error
                    )
                })
        }
    }
}

fn host_header(hostname: &str, port: u16, scheme: &str) -> String {
    let hostname = {
        let hostname: &str = hostname;
        if hostname.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{hostname}]")
        } else {
            hostname.to_owned()
        }
    };
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
