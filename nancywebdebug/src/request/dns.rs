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
    let mut seen_records = {
        let (trace,): (&DnsTrace,) = (trace,);
        let inlined_result: HashSet<(String, String, u32, String)> = {
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
        };
        inlined_result
    };
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
    let mut seen_records = {
        let (trace,): (&DnsTrace,) = (trace,);
        let inlined_result: HashSet<(String, String, u32, String)> = {
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
        };
        inlined_result
    };
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
        .map(|server: &hickory_resolver::config::NameServerConfig| {
            let transports = server
                .connections
                .iter()
                .map(|connection| format!("{:?}:{}", connection.protocol, connection.port))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} ({transports})", server.ip)
        })
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
    let query = match {
        let (name, record_type): (&Name, RecordType) = (name, record_type);
        let inlined_result: Result<Vec<u8>, String> = {
            let mut message = Message::query();
            message.metadata.recursion_desired = true;
            message.add_query(Query::query(name.clone(), record_type));
            message.to_vec().map_err(|error| error.to_string())
        };
        inlined_result
    } {
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
        let configured = {
            let (server,): (&hickory_resolver::config::NameServerConfig,) = (server,);
            let inlined_result: String = {
                let transports = server
                    .connections
                    .iter()
                    .map(|connection| format!("{:?}:{}", connection.protocol, connection.port))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{} ({transports})", server.ip)
            };
            inlined_result
        };
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
            let (attempt_index, started) = {
                let (trace, record_type, configured_resolver, transport): (
                    &mut DnsTrace,
                    RecordType,
                    String,
                    &str,
                ) = (&mut trace, record_type, configured.clone(), "UDP");
                let inlined_result: (usize, Instant) = {
                    let index = trace.attempts.len();
                    trace.attempts.push(DnsAttempt {
                        record_type: record_type.to_string(),
                        configured_resolver,
                        responder: None,
                        transport: transport.to_owned(),
                        response_code: None,
                        duration_ms: 0.0,
                        error: Some(
                            "Attempt interrupted by DNS timeout or cancellation".to_owned(),
                        ),
                    });
                    (index, Instant::now())
                };
                inlined_result
            };
            match tokio::time::timeout(query_timeout, {
                let (remote, query): (SocketAddr, &[u8]) = (remote, &query);
                async move {
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
                    ({
                        let (query, response): (&[u8], &[u8]) = (query, &bytes[..length]);
                        let inlined_result: Result<Message, String> = {
                            'inlined_parse_dns_response: {
                                let query = match Message::from_vec(query)
                                    .map_err(|error| error.to_string())
                                {
                                    Ok(value) => value,
                                    Err(error) => {
                                        break 'inlined_parse_dns_response Err(
                                            ::core::convert::From::from(error),
                                        );
                                    }
                                };
                                let response = match Message::from_vec(response)
                                    .map_err(|error| error.to_string())
                                {
                                    Ok(value) => value,
                                    Err(error) => {
                                        break 'inlined_parse_dns_response Err(
                                            ::core::convert::From::from(error),
                                        );
                                    }
                                };
                                if response.metadata.id != query.metadata.id {
                                    break 'inlined_parse_dns_response Err(
                                        "DNS response transaction ID does not match the query"
                                            .to_owned(),
                                    );
                                }
                                Ok(response)
                            }
                        };
                        inlined_result
                    })
                    .map(|message| (message, responder))
                }
            })
            .await
            {
                Ok(Ok((message, responder))) => {
                    let truncated = message.metadata.truncation;
                    ({
                        let (trace, index, started, responder, response_code, error): (
                            &mut DnsTrace,
                            usize,
                            Instant,
                            Option<SocketAddr>,
                            Option<String>,
                            Option<String>,
                        ) = (
                            &mut trace,
                            attempt_index,
                            started,
                            Some(responder),
                            Some(message.metadata.response_code.to_string()),
                            truncated.then(|| "Truncated response; retrying over TCP".to_owned()),
                        );

                        if let Some(attempt) = trace.attempts.get_mut(index) {
                            attempt.responder = responder;
                            attempt.response_code = response_code;
                            attempt.duration_ms = (started).elapsed().as_secs_f64() * 1000.0;
                            attempt.error = error;
                        }
                    });
                    if truncated {
                        let tcp_port = tcp.map_or(connection.port, |tcp| tcp.port);
                        let remote = SocketAddr::new(server.ip, tcp_port);
                        let (attempt_index, started) =
                            {
                                let (trace, record_type, configured_resolver, transport): (
                                    &mut DnsTrace,
                                    RecordType,
                                    String,
                                    &str,
                                ) = (&mut trace, record_type, configured.clone(), "TCP fallback");
                                let inlined_result: (usize, Instant) =
                                    {
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
                                    };
                                inlined_result
                            };
                        match tokio::time::timeout(query_timeout, {
let (remote, query,): (SocketAddr, & [u8],) = (remote, &query,);
async move {

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
    ({
let (query, response,): (& [u8], & [u8],) = (query, &bytes,);
let inlined_result: Result < Message , String > = {
'inlined_parse_dns_response: {

    let query = match Message::from_vec(query).map_err(|error| error.to_string()) { Ok(value) => value, Err(error) => break 'inlined_parse_dns_response Err(::core::convert::From::from(error)) };
    let response = match Message::from_vec(response).map_err(|error| error.to_string()) { Ok(value) => value, Err(error) => break 'inlined_parse_dns_response Err(::core::convert::From::from(error)) };
    if response.metadata.id != query.metadata.id {
        break 'inlined_parse_dns_response Err("DNS response transaction ID does not match the query".to_owned());
    }
    Ok(response)

}
};
inlined_result
}).map(|message| (message, responder))

}
})
                            .await
                        {
                            Ok(Ok((message, responder))) => {
                                let successful = {
let (message,): (& Message,) = (&message,);
{

    matches!(
        message.metadata.response_code,
        hickory_resolver::proto::op::ResponseCode::NoError
            | hickory_resolver::proto::op::ResponseCode::NXDomain
    )

}

};
                                ({
let (trace, index, started, responder, response_code, error,): (& mut DnsTrace, usize, Instant, Option < SocketAddr >, Option < String >, Option < String >,) = (&mut trace, attempt_index, started, Some(responder), Some(message.metadata.response_code.to_string()), None,);

    if let Some(attempt) = trace.attempts.get_mut(index) {
        attempt.responder = responder;
        attempt.response_code = response_code;
        attempt.duration_ms = (started).elapsed().as_secs_f64() * 1000.0;
        attempt.error = error;
    }

});
                                ({
let (trace, message, seen_records, seen_addresses,): (& mut DnsTrace, & Message, & mut HashSet < (String , String , u32 , String) >, & mut HashSet < IpAddr >,) = (&mut trace, &message, &mut seen_records, &mut seen_addresses,);

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

});
                                if successful {
                                    break;
                                }
                            }
                            Ok(Err(error)) => {
let (trace, index, started, responder, response_code, error,): (& mut DnsTrace, usize, Instant, Option < SocketAddr >, Option < String >, Option < String >,) = (&mut trace, attempt_index, started, None, None, Some(error),);

    if let Some(attempt) = trace.attempts.get_mut(index) {
        attempt.responder = responder;
        attempt.response_code = response_code;
        attempt.duration_ms = (started).elapsed().as_secs_f64() * 1000.0;
        attempt.error = error;
    }

},
                            Err(_) => {
let (trace, index, started, responder, response_code, error,): (& mut DnsTrace, usize, Instant, Option < SocketAddr >, Option < String >, Option < String >,) = (&mut trace, attempt_index, started, None, None, Some("Resolver attempt timed out".to_owned()),);

    if let Some(attempt) = trace.attempts.get_mut(index) {
        attempt.responder = responder;
        attempt.response_code = response_code;
        attempt.duration_ms = (started).elapsed().as_secs_f64() * 1000.0;
        attempt.error = error;
    }

},
                        }
                    } else {
                        let successful = {
                            let (message,): (&Message,) = (&message,);
                            {
                                matches!(
                                    message.metadata.response_code,
                                    hickory_resolver::proto::op::ResponseCode::NoError
                                        | hickory_resolver::proto::op::ResponseCode::NXDomain
                                )
                            }
                        };
                        ({
                            let (trace, message, seen_records, seen_addresses): (
                                &mut DnsTrace,
                                &Message,
                                &mut HashSet<(String, String, u32, String)>,
                                &mut HashSet<IpAddr>,
                            ) = (&mut trace, &message, &mut seen_records, &mut seen_addresses);

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
                        });
                        if successful {
                            break;
                        }
                    }
                }
                Ok(Err(error)) => {
                    let (trace, index, started, responder, response_code, error): (
                        &mut DnsTrace,
                        usize,
                        Instant,
                        Option<SocketAddr>,
                        Option<String>,
                        Option<String>,
                    ) = (&mut trace, attempt_index, started, None, None, Some(error));

                    if let Some(attempt) = trace.attempts.get_mut(index) {
                        attempt.responder = responder;
                        attempt.response_code = response_code;
                        attempt.duration_ms = (started).elapsed().as_secs_f64() * 1000.0;
                        attempt.error = error;
                    }
                }
                Err(_) => {
                    let (trace, index, started, responder, response_code, error): (
                        &mut DnsTrace,
                        usize,
                        Instant,
                        Option<SocketAddr>,
                        Option<String>,
                        Option<String>,
                    ) = (
                        &mut trace,
                        attempt_index,
                        started,
                        None,
                        None,
                        Some("Resolver attempt timed out".to_owned()),
                    );

                    if let Some(attempt) = trace.attempts.get_mut(index) {
                        attempt.responder = responder;
                        attempt.response_code = response_code;
                        attempt.duration_ms = (started).elapsed().as_secs_f64() * 1000.0;
                        attempt.error = error;
                    }
                }
            }
        } else if let Some(connection) = tcp {
            let remote = SocketAddr::new(server.ip, connection.port);
            let (attempt_index, started) = {
                let (trace, record_type, configured_resolver, transport): (
                    &mut DnsTrace,
                    RecordType,
                    String,
                    &str,
                ) = (&mut trace, record_type, configured.clone(), "TCP");
                let inlined_result: (usize, Instant) = {
                    let index = trace.attempts.len();
                    trace.attempts.push(DnsAttempt {
                        record_type: record_type.to_string(),
                        configured_resolver,
                        responder: None,
                        transport: transport.to_owned(),
                        response_code: None,
                        duration_ms: 0.0,
                        error: Some(
                            "Attempt interrupted by DNS timeout or cancellation".to_owned(),
                        ),
                    });
                    (index, Instant::now())
                };
                inlined_result
            };
            match tokio::time::timeout(query_timeout, {
                let (remote, query): (SocketAddr, &[u8]) = (remote, &query);
                async move {
                    let mut stream = TcpStream::connect(remote)
                        .await
                        .map_err(|error| error.to_string())?;
                    let responder = stream.peer_addr().map_err(|error| error.to_string())?;
                    let length = u16::try_from(query.len())
                        .map_err(|_| "DNS query is too large".to_owned())?;
                    stream
                        .write_all(&length.to_be_bytes())
                        .await
                        .map_err(|error| error.to_string())?;
                    stream
                        .write_all(query)
                        .await
                        .map_err(|error| error.to_string())?;
                    let length =
                        stream.read_u16().await.map_err(|error| error.to_string())? as usize;
                    let mut bytes = vec![0; length];
                    stream
                        .read_exact(&mut bytes)
                        .await
                        .map_err(|error| error.to_string())?;
                    ({
                        let (query, response): (&[u8], &[u8]) = (query, &bytes);
                        let inlined_result: Result<Message, String> = {
                            'inlined_parse_dns_response: {
                                let query = match Message::from_vec(query)
                                    .map_err(|error| error.to_string())
                                {
                                    Ok(value) => value,
                                    Err(error) => {
                                        break 'inlined_parse_dns_response Err(
                                            ::core::convert::From::from(error),
                                        );
                                    }
                                };
                                let response = match Message::from_vec(response)
                                    .map_err(|error| error.to_string())
                                {
                                    Ok(value) => value,
                                    Err(error) => {
                                        break 'inlined_parse_dns_response Err(
                                            ::core::convert::From::from(error),
                                        );
                                    }
                                };
                                if response.metadata.id != query.metadata.id {
                                    break 'inlined_parse_dns_response Err(
                                        "DNS response transaction ID does not match the query"
                                            .to_owned(),
                                    );
                                }
                                Ok(response)
                            }
                        };
                        inlined_result
                    })
                    .map(|message| (message, responder))
                }
            })
            .await
            {
                Ok(Ok((message, responder))) => {
                    let successful = {
                        let (message,): (&Message,) = (&message,);
                        {
                            matches!(
                                message.metadata.response_code,
                                hickory_resolver::proto::op::ResponseCode::NoError
                                    | hickory_resolver::proto::op::ResponseCode::NXDomain
                            )
                        }
                    };
                    ({
                        let (trace, index, started, responder, response_code, error): (
                            &mut DnsTrace,
                            usize,
                            Instant,
                            Option<SocketAddr>,
                            Option<String>,
                            Option<String>,
                        ) = (
                            &mut trace,
                            attempt_index,
                            started,
                            Some(responder),
                            Some(message.metadata.response_code.to_string()),
                            None,
                        );

                        if let Some(attempt) = trace.attempts.get_mut(index) {
                            attempt.responder = responder;
                            attempt.response_code = response_code;
                            attempt.duration_ms = (started).elapsed().as_secs_f64() * 1000.0;
                            attempt.error = error;
                        }
                    });
                    ({
                        let (trace, message, seen_records, seen_addresses): (
                            &mut DnsTrace,
                            &Message,
                            &mut HashSet<(String, String, u32, String)>,
                            &mut HashSet<IpAddr>,
                        ) = (&mut trace, &message, &mut seen_records, &mut seen_addresses);

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
                    });
                    if successful {
                        break;
                    }
                }
                Ok(Err(error)) => {
                    let (trace, index, started, responder, response_code, error): (
                        &mut DnsTrace,
                        usize,
                        Instant,
                        Option<SocketAddr>,
                        Option<String>,
                        Option<String>,
                    ) = (&mut trace, attempt_index, started, None, None, Some(error));

                    if let Some(attempt) = trace.attempts.get_mut(index) {
                        attempt.responder = responder;
                        attempt.response_code = response_code;
                        attempt.duration_ms = (started).elapsed().as_secs_f64() * 1000.0;
                        attempt.error = error;
                    }
                }
                Err(_) => {
                    let (trace, index, started, responder, response_code, error): (
                        &mut DnsTrace,
                        usize,
                        Instant,
                        Option<SocketAddr>,
                        Option<String>,
                        Option<String>,
                    ) = (
                        &mut trace,
                        attempt_index,
                        started,
                        None,
                        None,
                        Some("Resolver attempt timed out".to_owned()),
                    );

                    if let Some(attempt) = trace.attempts.get_mut(index) {
                        attempt.responder = responder;
                        attempt.response_code = response_code;
                        attempt.duration_ms = (started).elapsed().as_secs_f64() * 1000.0;
                        attempt.error = error;
                    }
                }
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

pub(super) fn finish_interrupted_dns_attempt(trace: &mut DnsTrace, started: Instant, reason: &str) {
    if let Some(attempt) = trace.attempts.last_mut()
        && attempt.response_code.is_none()
        && attempt.error.as_deref() == Some("Attempt interrupted by DNS timeout or cancellation")
    {
        attempt.duration_ms = (started).elapsed().as_secs_f64() * 1000.0;
        attempt.error = Some(reason.to_owned());
    }
}
