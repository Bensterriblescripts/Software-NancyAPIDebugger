use crate::diagnostics::{DnsAttempt, DnsRecord, DnsTrace};
use futures_util::{StreamExt, stream};
use hickory_resolver::config::ProtocolConfig;
use hickory_resolver::proto::op::{Message, Query};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::stages::elapsed_ms;

const LIMITED_RECORD_TYPES: &[RecordType] = &[RecordType::A, RecordType::AAAA, RecordType::CNAME];

const EXHAUSTIVE_RECORD_TYPES: &[RecordType] = &[
    RecordType::A,
    RecordType::AAAA,
    RecordType::ANAME,
    RecordType::CAA,
    RecordType::CDS,
    RecordType::CDNSKEY,
    RecordType::CERT,
    RecordType::CNAME,
    RecordType::CSYNC,
    RecordType::DNSKEY,
    RecordType::DS,
    RecordType::HINFO,
    RecordType::HTTPS,
    RecordType::KEY,
    RecordType::MX,
    RecordType::NAPTR,
    RecordType::NS,
    RecordType::NSEC,
    RecordType::NSEC3,
    RecordType::NSEC3PARAM,
    RecordType::NULL,
    RecordType::OPENPGPKEY,
    RecordType::PTR,
    RecordType::RRSIG,
    RecordType::SIG,
    RecordType::SMIMEA,
    RecordType::SOA,
    RecordType::SRV,
    RecordType::SSHFP,
    RecordType::SVCB,
    RecordType::TLSA,
    RecordType::TXT,
];

pub(crate) async fn resolve_host(host: &str, trace: &mut DnsTrace) -> Result<(), String> {
    let Some((name, name_servers, query_timeout)) = prepare_lookup(host, trace)? else {
        return Ok(());
    };
    let mut seen_records = existing_record_keys(trace);
    let mut seen_addresses = trace.addresses.iter().copied().collect();
    for record_type in LIMITED_RECORD_TYPES.iter().copied() {
        let result = lookup_record_type(&name, record_type, &name_servers, query_timeout).await;
        merge_lookup_result(trace, result, &mut seen_records, &mut seen_addresses);
    }
    Ok(())
}

pub(crate) async fn resolve_host_exhaustive(
    host: &str,
    trace: &mut DnsTrace,
) -> Result<(), String> {
    let Some((name, name_servers, query_timeout)) = prepare_lookup(host, trace)? else {
        return Ok(());
    };
    trace.incomplete_record_types = EXHAUSTIVE_RECORD_TYPES
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut seen_records = existing_record_keys(trace);
    let mut seen_addresses = trace.addresses.iter().copied().collect();
    let lookups = stream::iter(EXHAUSTIVE_RECORD_TYPES.iter().copied())
        .map(|record_type| lookup_record_type(&name, record_type, &name_servers, query_timeout))
        .buffer_unordered(EXHAUSTIVE_RECORD_TYPES.len());
    tokio::pin!(lookups);
    while let Some(result) = lookups.next().await {
        merge_lookup_result(trace, result, &mut seen_records, &mut seen_addresses);
    }
    Ok(())
}

fn prepare_lookup(
    host: &str,
    trace: &mut DnsTrace,
) -> Result<
    Option<(
        Name,
        Vec<hickory_resolver::config::NameServerConfig>,
        Duration,
    )>,
    String,
> {
    trace.incomplete_record_types.clear();
    if let Ok(ip) = IpAddr::from_str(host.trim_matches(['[', ']'])) {
        trace.configured_resolvers = vec!["Not used (IP literal)".to_owned()];
        trace.attempts = vec![DnsAttempt {
            configured_resolver: "Not used (IP literal)".to_owned(),
            responder: None,
            transport: "Literal".to_owned(),
            duration_ms: 0.0,
            response_code: Some("LITERAL".to_owned()),
            error: None,
            record_type: if ip.is_ipv4() { "A" } else { "AAAA" }.to_owned(),
        }];
        trace.records = vec![DnsRecord {
            name: host.to_owned(),
            record_type: if ip.is_ipv4() { "A" } else { "AAAA" }.to_owned(),
            ttl: 0,
            value: ip.to_string(),
        }];
        trace.addresses = vec![ip];
        return Ok(None);
    }

    let (config, options) = hickory_resolver::system_conf::read_system_conf()
        .map_err(|error| format!("Unable to read system DNS configuration: {error}"))?;
    trace.configured_resolvers = config
        .name_servers()
        .iter()
        .map(configured_resolver_label)
        .collect();
    if config.name_servers().is_empty() {
        return Err("System DNS configuration contains no resolvers".to_owned());
    }

    let query_timeout = options.timeout.min(Duration::from_secs(2));
    let name = Name::from_ascii(host).map_err(|error| error.to_string())?;
    Ok(Some((name, config.name_servers().to_vec(), query_timeout)))
}

struct DnsLookupResult {
    record_type: RecordType,
    trace: DnsTrace,
}

async fn lookup_record_type(
    name: &Name,
    record_type: RecordType,
    name_servers: &[hickory_resolver::config::NameServerConfig],
    query_timeout: Duration,
) -> DnsLookupResult {
    let mut trace = DnsTrace::default();
    let mut seen_records = HashSet::new();
    let mut seen_addresses = HashSet::new();
    let query = match dns_query(name, record_type) {
        Ok(query) => query,
        Err(error) => {
            trace.attempts.push(DnsAttempt {
                record_type: record_type.to_string(),
                configured_resolver: "Not sent".to_owned(),
                responder: None,
                transport: "Unsupported".to_owned(),
                response_code: None,
                duration_ms: 0.0,
                error: Some(error),
            });
            return DnsLookupResult { record_type, trace };
        }
    };
    for server in name_servers {
        let configured = configured_resolver_label(server);
        let udp = server
            .connections
            .iter()
            .find(|connection| connection.protocol == ProtocolConfig::Udp);
        let tcp = server
            .connections
            .iter()
            .find(|connection| connection.protocol == ProtocolConfig::Tcp);
        if let Some(connection) = udp {
            let remote = SocketAddr::new(server.ip, connection.port);
            let (attempt_index, started) =
                start_dns_attempt(&mut trace, record_type, configured.clone(), "UDP");
            match tokio::time::timeout(query_timeout, query_dns_udp(remote, &query)).await {
                Ok(Ok((message, responder))) => {
                    let truncated = message.metadata.truncation;
                    finish_dns_attempt(
                        &mut trace,
                        attempt_index,
                        started,
                        Some(responder),
                        Some(message.metadata.response_code.to_string()),
                        truncated.then(|| "Truncated response; retrying over TCP".to_owned()),
                    );
                    if truncated {
                        let tcp_port = tcp.map_or(connection.port, |tcp| tcp.port);
                        let remote = SocketAddr::new(server.ip, tcp_port);
                        let (attempt_index, started) = start_dns_attempt(
                            &mut trace,
                            record_type,
                            configured.clone(),
                            "TCP fallback",
                        );
                        match tokio::time::timeout(query_timeout, query_dns_tcp(remote, &query))
                            .await
                        {
                            Ok(Ok((message, responder))) => {
                                let successful = dns_response_is_final(&message);
                                finish_dns_attempt(
                                    &mut trace,
                                    attempt_index,
                                    started,
                                    Some(responder),
                                    Some(message.metadata.response_code.to_string()),
                                    None,
                                );
                                collect_dns_records(
                                    &mut trace,
                                    &message,
                                    &mut seen_records,
                                    &mut seen_addresses,
                                );
                                if successful {
                                    break;
                                }
                            }
                            Ok(Err(error)) => finish_dns_attempt(
                                &mut trace,
                                attempt_index,
                                started,
                                None,
                                None,
                                Some(error),
                            ),
                            Err(_) => finish_dns_attempt(
                                &mut trace,
                                attempt_index,
                                started,
                                None,
                                None,
                                Some("Resolver attempt timed out".to_owned()),
                            ),
                        }
                    } else {
                        let successful = dns_response_is_final(&message);
                        collect_dns_records(
                            &mut trace,
                            &message,
                            &mut seen_records,
                            &mut seen_addresses,
                        );
                        if successful {
                            break;
                        }
                    }
                }
                Ok(Err(error)) => {
                    finish_dns_attempt(&mut trace, attempt_index, started, None, None, Some(error))
                }
                Err(_) => finish_dns_attempt(
                    &mut trace,
                    attempt_index,
                    started,
                    None,
                    None,
                    Some("Resolver attempt timed out".to_owned()),
                ),
            }
        } else if let Some(connection) = tcp {
            let remote = SocketAddr::new(server.ip, connection.port);
            let (attempt_index, started) =
                start_dns_attempt(&mut trace, record_type, configured.clone(), "TCP");
            match tokio::time::timeout(query_timeout, query_dns_tcp(remote, &query)).await {
                Ok(Ok((message, responder))) => {
                    let successful = dns_response_is_final(&message);
                    finish_dns_attempt(
                        &mut trace,
                        attempt_index,
                        started,
                        Some(responder),
                        Some(message.metadata.response_code.to_string()),
                        None,
                    );
                    collect_dns_records(
                        &mut trace,
                        &message,
                        &mut seen_records,
                        &mut seen_addresses,
                    );
                    if successful {
                        break;
                    }
                }
                Ok(Err(error)) => {
                    finish_dns_attempt(&mut trace, attempt_index, started, None, None, Some(error))
                }
                Err(_) => finish_dns_attempt(
                    &mut trace,
                    attempt_index,
                    started,
                    None,
                    None,
                    Some("Resolver attempt timed out".to_owned()),
                ),
            }
        } else {
            trace.attempts.push(DnsAttempt {
                record_type: record_type.to_string(),
                configured_resolver: configured,
                responder: None,
                transport: "Unsupported".to_owned(),
                response_code: None,
                duration_ms: 0.0,
                error: Some("Resolver has no UDP or TCP connection".to_owned()),
            });
        }
    }
    DnsLookupResult { record_type, trace }
}

fn existing_record_keys(trace: &DnsTrace) -> HashSet<(String, String, u32, String)> {
    trace
        .records
        .iter()
        .map(|record| {
            (
                record.name.clone(),
                record.record_type.clone(),
                record.ttl,
                record.value.clone(),
            )
        })
        .collect()
}

fn merge_lookup_result(
    trace: &mut DnsTrace,
    result: DnsLookupResult,
    seen_records: &mut HashSet<(String, String, u32, String)>,
    seen_addresses: &mut HashSet<IpAddr>,
) {
    let record_type = result.record_type.to_string();
    trace
        .incomplete_record_types
        .retain(|pending| pending != &record_type);
    trace.attempts.extend(result.trace.attempts);
    for record in result.trace.records {
        let key = (
            record.name.clone(),
            record.record_type.clone(),
            record.ttl,
            record.value.clone(),
        );
        if seen_records.insert(key) {
            trace.records.push(record);
        }
    }
    if matches!(
        result.record_type,
        RecordType::A | RecordType::AAAA | RecordType::CNAME
    ) {
        for address in result.trace.addresses {
            if seen_addresses.insert(address) {
                trace.addresses.push(address);
            }
        }
    }
}

fn start_dns_attempt(
    trace: &mut DnsTrace,
    record_type: RecordType,
    configured_resolver: String,
    transport: &str,
) -> (usize, Instant) {
    let index = trace.attempts.len();
    trace.attempts.push(DnsAttempt {
        record_type: record_type.to_string(),
        configured_resolver,
        responder: None,
        transport: transport.to_owned(),
        response_code: None,
        duration_ms: 0.0,
        error: Some("Attempt interrupted by DNS timeout or cancellation".to_owned()),
    });
    (index, Instant::now())
}

fn finish_dns_attempt(
    trace: &mut DnsTrace,
    index: usize,
    started: Instant,
    responder: Option<SocketAddr>,
    response_code: Option<String>,
    error: Option<String>,
) {
    if let Some(attempt) = trace.attempts.get_mut(index) {
        attempt.responder = responder;
        attempt.response_code = response_code;
        attempt.duration_ms = elapsed_ms(started);
        attempt.error = error;
    }
}

pub(super) fn finish_interrupted_dns_attempt(trace: &mut DnsTrace, started: Instant, reason: &str) {
    if let Some(attempt) = trace.attempts.last_mut()
        && attempt.response_code.is_none()
        && attempt.error.as_deref() == Some("Attempt interrupted by DNS timeout or cancellation")
    {
        attempt.duration_ms = elapsed_ms(started);
        attempt.error = Some(reason.to_owned());
    }
}

fn configured_resolver_label(server: &hickory_resolver::config::NameServerConfig) -> String {
    let transports = server
        .connections
        .iter()
        .map(|connection| format!("{:?}:{}", connection.protocol, connection.port))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{} ({transports})", server.ip)
}

fn dns_query(name: &Name, record_type: RecordType) -> Result<Vec<u8>, String> {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name.clone(), record_type));
    message.to_vec().map_err(|error| error.to_string())
}

async fn query_dns_udp(remote: SocketAddr, query: &[u8]) -> Result<(Message, SocketAddr), String> {
    let bind = if remote.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|error| error.to_string())?;
    socket
        .send_to(query, remote)
        .await
        .map_err(|error| error.to_string())?;
    let mut bytes = vec![0; 65_535];
    let (length, responder) = socket
        .recv_from(&mut bytes)
        .await
        .map_err(|error| error.to_string())?;
    parse_dns_response(query, &bytes[..length]).map(|message| (message, responder))
}

async fn query_dns_tcp(remote: SocketAddr, query: &[u8]) -> Result<(Message, SocketAddr), String> {
    let mut stream = TcpStream::connect(remote)
        .await
        .map_err(|error| error.to_string())?;
    let responder = stream.peer_addr().map_err(|error| error.to_string())?;
    let length = u16::try_from(query.len()).map_err(|_| "DNS query is too large".to_owned())?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(query)
        .await
        .map_err(|error| error.to_string())?;
    let length = stream.read_u16().await.map_err(|error| error.to_string())? as usize;
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|error| error.to_string())?;
    parse_dns_response(query, &bytes).map(|message| (message, responder))
}

fn parse_dns_response(query: &[u8], response: &[u8]) -> Result<Message, String> {
    let query = Message::from_vec(query).map_err(|error| error.to_string())?;
    let response = Message::from_vec(response).map_err(|error| error.to_string())?;
    if response.metadata.id != query.metadata.id {
        return Err("DNS response transaction ID does not match the query".to_owned());
    }
    Ok(response)
}

fn dns_response_is_final(message: &Message) -> bool {
    matches!(
        message.metadata.response_code,
        hickory_resolver::proto::op::ResponseCode::NoError
            | hickory_resolver::proto::op::ResponseCode::NXDomain
    )
}

fn collect_dns_records(
    trace: &mut DnsTrace,
    message: &Message,
    seen_records: &mut HashSet<(String, String, u32, String)>,
    seen_addresses: &mut HashSet<IpAddr>,
) {
    for record in message.all_sections() {
        let data = &record.data;
        let value = data.to_string();
        let key = (
            record.name.to_string(),
            record.record_type().to_string(),
            record.ttl,
            value.clone(),
        );
        if seen_records.insert(key) {
            trace.records.push(DnsRecord {
                name: record.name.to_string(),
                record_type: record.record_type().to_string(),
                ttl: record.ttl,
                value: value.clone(),
            });
        }
        if matches!(data, RData::A(_) | RData::AAAA(_))
            && let Ok(ip) = value.parse::<IpAddr>()
            && seen_addresses.insert(ip)
        {
            trace.addresses.push(ip);
        }
    }
}
