use crate::diagnostics::{DnsAttempt, DnsLookupStatus};
use hickory_resolver::config::{NameServerConfig, ProtocolConfig};
use hickory_resolver::proto::op::{Edns, Message, MessageType, Query, ResponseCode};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub(crate) fn transports(servers: &[NameServerConfig]) -> Vec<(SocketAddr, bool)> {
    servers
        .iter()
        .flat_map(|server| {
            [ProtocolConfig::Udp, ProtocolConfig::Tcp]
                .into_iter()
                .flat_map(move |protocol| {
                    server
                        .connections
                        .iter()
                        .filter(move |connection| connection.protocol == protocol)
                        .map(|connection| {
                            (
                                SocketAddr::new(server.ip, connection.port),
                                connection.protocol == ProtocolConfig::Tcp,
                            )
                        })
                })
        })
        .collect()
}

pub(crate) fn validate_response(query: &Message, bytes: &[u8]) -> Result<Message, String> {
    let response =
        Message::from_vec(bytes).map_err(|error| format!("Malformed DNS response: {error}"))?;
    if response.metadata.id != query.metadata.id
        || response.metadata.message_type != MessageType::Response
        || response.metadata.op_code != query.metadata.op_code
        || response.queries != query.queries
    {
        return Err("DNS response does not match the question".to_owned());
    }
    Ok(response)
}

async fn exchange(remote: SocketAddr, tcp: bool, query: &Message) -> Result<Message, String> {
    let request = query.to_vec().map_err(|error| error.to_string())?;
    let response = if tcp {
        let mut stream = TcpStream::connect(remote)
            .await
            .map_err(|error| error.to_string())?;
        stream
            .write_u16(u16::try_from(request.len()).map_err(|_| "DNS query too large")?)
            .await
            .map_err(|error| error.to_string())?;
        stream
            .write_all(&request)
            .await
            .map_err(|error| error.to_string())?;
        let length = stream.read_u16().await.map_err(|error| error.to_string())? as usize;
        let mut response = vec![0; length];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|error| error.to_string())?;
        response
    } else {
        let bind = if remote.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let socket = UdpSocket::bind(SocketAddr::new(bind, 0))
            .await
            .map_err(|error| error.to_string())?;
        socket
            .connect(remote)
            .await
            .map_err(|error| error.to_string())?;
        socket
            .send(&request)
            .await
            .map_err(|error| error.to_string())?;
        let mut response = vec![0; 65535];
        let length = socket
            .recv(&mut response)
            .await
            .map_err(|error| error.to_string())?;
        response.truncate(length);
        response
    };
    validate_response(query, &response)
}

struct AttemptObservation<'a> {
    attempt: Option<DnsAttempt>,
    started: Instant,
    observe: &'a mut (dyn FnMut(DnsAttempt) + Send),
}

impl Drop for AttemptObservation<'_> {
    fn drop(&mut self) {
        if let Some(mut attempt) = self.attempt.take() {
            attempt.duration_ms = self.started.elapsed().as_secs_f64() * 1000.0;
            (self.observe)(attempt);
        }
    }
}

pub(crate) async fn query<F, Fut>(
    owner: &str,
    kind: RecordType,
    servers: &[(SocketAddr, bool)],
    recursive: bool,
    attempt_timeout: Duration,
    network_budget: Duration,
    mut admit: F,
    mut observe: impl FnMut(DnsAttempt) + Send,
) -> Result<Message, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let mut name = Name::from_ascii(if owner.is_empty() { "." } else { owner })
        .map_err(|error| error.to_string())?;
    name.set_fqdn(true);
    let mut query = Message::query();
    query.metadata.recursion_desired = recursive;
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    edns.set_dnssec_ok(true);
    query.set_edns(edns);
    query.add_query(Query::query(name, kind));
    let mut remaining = network_budget;
    let mut failure = "No supported system DNS resolver is configured".to_owned();
    for &(remote, tcp) in servers {
        if remaining.is_zero() {
            return Err(format!("DNS network-work limit reached: {failure}"));
        }
        admit().await?;
        let started = Instant::now();
        let mut observation = AttemptObservation {
            attempt: Some(DnsAttempt {
                record_type: kind.to_string(),
                configured_resolver: remote.to_string(),
                responder: None,
                transport: if tcp { "TCP" } else { "UDP" }.to_owned(),
                response_code: None,
                duration_ms: 0.0,
                error: Some(
                    "DNS network attempt interrupted by cancellation or stage limit".to_owned(),
                ),
            }),
            started,
            observe: &mut observe,
        };
        let result = tokio::time::timeout(
            attempt_timeout.min(remaining),
            exchange(remote, tcp, &query),
        )
        .await;
        remaining = remaining.saturating_sub(started.elapsed());
        let mut attempt = observation.attempt.take().unwrap();
        attempt.duration_ms = started.elapsed().as_secs_f64() * 1000.0;
        attempt.error = None;
        let message = match result {
            Ok(Ok(message)) => {
                attempt.responder = Some(remote);
                attempt.response_code = Some(message.metadata.response_code.to_string());
                if message.metadata.truncation {
                    attempt.error = Some("Unusable truncated DNS response".to_owned());
                } else if !matches!(
                    message.metadata.response_code,
                    ResponseCode::NoError | ResponseCode::NXDomain
                ) {
                    attempt.error = Some(format!(
                        "Resolver failure: {}",
                        message.metadata.response_code
                    ));
                } else if recursive {
                    if let Err(error) = AliasPath::new(owner).consume(&message, kind)
                        && matches!(
                            error.as_str(),
                            "DNS response contains no relevant answer or negative proof"
                                | "Resolver returned an unresolved referral"
                        )
                    {
                        attempt.error = Some(error);
                    }
                }
                Some(message)
            }
            Ok(Err(error)) => {
                attempt.error = Some(error);
                None
            }
            Err(_) => {
                attempt.error = Some("DNS network attempt timed out".to_owned());
                None
            }
        };
        let successful = attempt.error.is_none();
        if let Some(error) = &attempt.error {
            failure = format!("{remote} {}: {error}", attempt.transport);
        }
        (observation.observe)(attempt);
        if successful {
            return Ok(message.unwrap());
        }
    }
    Err(failure)
}

pub(crate) fn owned_records(records: &[Record], owner: &str, kind: RecordType) -> Vec<Record> {
    let mut seen = HashSet::new();
    records
        .iter()
        .filter(|record| {
            record.dns_class == DNSClass::IN
                && record.record_type() == kind
                && record
                    .name
                    .to_string()
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(owner.trim_end_matches('.'))
        })
        .filter(|record| seen.insert(record.data.clone()))
        .cloned()
        .collect()
}

pub(crate) struct AliasPath {
    pub(crate) owner: String,
    pub(crate) aliases: Vec<(String, String)>,
    seen: HashSet<String>,
}

impl AliasPath {
    pub(crate) fn new(owner: &str) -> Self {
        let owner = owner.trim_end_matches('.').to_ascii_lowercase();
        Self {
            seen: HashSet::from([owner.clone()]),
            owner,
            aliases: Vec::new(),
        }
    }

    pub(crate) fn consume(
        &mut self,
        message: &Message,
        kind: RecordType,
    ) -> Result<Option<(DnsLookupStatus, Vec<Record>)>, String> {
        let initial_depth = self.aliases.len();
        for (owner, target) in &self.aliases {
            if owned_records(&message.answers, owner, RecordType::CNAME)
                .iter()
                .any(|record| {
                    !record
                        .data
                        .to_string()
                        .trim_end_matches('.')
                        .eq_ignore_ascii_case(target)
                })
            {
                return Err("Multiple CNAME destinations at one owner".to_owned());
            }
        }
        loop {
            let records = owned_records(&message.answers, &self.owner, kind);
            let aliases = owned_records(&message.answers, &self.owner, RecordType::CNAME);
            if aliases.len() > 1 {
                return Err("Multiple CNAME destinations at one owner".to_owned());
            }
            if kind == RecordType::CNAME && !records.is_empty() {
                return Ok(Some((DnsLookupStatus::Answer, records)));
            }
            if !aliases.is_empty() && !records.is_empty() {
                return Err("CNAME and terminal data conflict at one owner".to_owned());
            }
            if let Some(alias) = aliases.first() {
                let RData::CNAME(target) = &alias.data else {
                    unreachable!()
                };
                let target = target
                    .0
                    .to_string()
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if self.aliases.len() >= 10 {
                    return Err("CNAME depth limit (10) reached".to_owned());
                }
                self.aliases.push((self.owner.clone(), target.clone()));
                self.owner = target.clone();
                if !self.seen.insert(target) {
                    return Err("Confirmed CNAME cycle".to_owned());
                }
                continue;
            }
            if message.metadata.response_code == ResponseCode::NXDomain {
                if !records.is_empty() {
                    return Err("NXDOMAIN conflicts with terminal data".to_owned());
                }
                return Ok(Some((DnsLookupStatus::NxDomain, Vec::new())));
            }
            if !records.is_empty() {
                return Ok(Some((DnsLookupStatus::Answer, records)));
            }
            if self.aliases.len() > initial_depth {
                return Ok(None);
            }
            if message
                .authorities
                .iter()
                .any(|r| r.record_type() == RecordType::NS)
                && !message
                    .authorities
                    .iter()
                    .any(|r| r.record_type() == RecordType::SOA)
            {
                return Err("Resolver returned an unresolved referral".to_owned());
            }
            let negative_proof = message.authorities.iter().any(|record| {
                let zone = record
                    .name
                    .to_string()
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                record.dns_class == DNSClass::IN
                    && record.record_type() == RecordType::SOA
                    && (zone.is_empty()
                        || self.owner == zone
                        || self.owner.ends_with(&format!(".{zone}")))
            });
            if !negative_proof && (!message.metadata.authoritative || !message.answers.is_empty()) {
                return Err("DNS response contains no relevant answer or negative proof".to_owned());
            }
            return Ok(Some((DnsLookupStatus::NoData, Vec::new())));
        }
    }
}
