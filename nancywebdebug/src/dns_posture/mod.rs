use super::*;
use hickory_resolver::config::ProtocolConfig;
use hickory_resolver::proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::proto::serialize::binary::BinEncodable;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::UdpSocket;

mod infrastructure;
mod mail;
mod policies;

const QUERY_LIMIT: usize = 128;
const DEPTH_LIMIT: usize = 10;
type QueryKey = (String, RecordType, Option<(SocketAddr, bool)>);
type QueryResult = Result<Message, String>;

struct Collector<'a> {
    cache: Mutex<HashMap<QueryKey, QueryResult>>,
    used: AtomicUsize,
    limited: AtomicUsize,
    cancel: &'a CancellationToken,
    limiter: &'a ConnectionRateLimiter,
    timeout: Duration,
    concurrency: usize,
    servers: Vec<(SocketAddr, bool)>,
}

#[derive(Clone, Debug)]
struct Rrset {
    owner: String,
    kind: RecordType,
    records: Vec<Record>,
    aliases: Vec<String>,
    nxdomain: bool,
    error: Option<String>,
}

impl Rrset {
    fn texts(&self) -> Vec<String> {
        self.records
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(
                    String::from_utf8_lossy(
                        &txt.txt_data
                            .iter()
                            .flat_map(|chunk| chunk.iter().copied())
                            .collect::<Vec<_>>(),
                    )
                    .into_owned(),
                ),
                _ => None,
            })
            .collect()
    }

    fn addresses(&self) -> Vec<IpAddr> {
        self.records
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(address) => Some(IpAddr::V4(address.0)),
                RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                _ => None,
            })
            .collect()
    }
}

impl<'a> Collector<'a> {
    async fn rrset(&self, name: &str, kind: RecordType) -> Rrset {
        let mut result = Rrset {
            owner: (name).trim_end_matches('.').to_ascii_lowercase(),
            kind,
            records: Vec::new(),
            aliases: Vec::new(),
            nxdomain: false,
            error: None,
        };
        let mut seen = HashSet::new();
        seen.insert(result.owner.clone());
        loop {
            let message = match ({
let (inlined_self, owner, kind, direct,): (& Collector < '_ >, & str, RecordType, Option < (SocketAddr , bool) >,) = (&*self, &result.owner, kind, None,);
async move {
let inlined_result: QueryResult = {

        if inlined_self.cancel.is_cancelled() {
            return Err("Assessment cancelled".to_owned());
        }
        let key = ((owner).trim_end_matches('.').to_ascii_lowercase(), kind, direct);
        if let Some(result) = inlined_self.cache.lock().unwrap().get(&key).cloned() {
            return result;
        }
        if inlined_self.limited.load(Ordering::Relaxed) != 0 {
            return Err("128-query assessment budget exhausted".to_owned());
        }
        let lookup = async {
            let servers = direct
                .map(|server| vec![server])
                .unwrap_or_else(|| inlined_self.servers.clone());
            let mut failure = "No supported system DNS resolver is configured".to_owned();
            for (remote, tcp) in servers {
                inlined_self.limiter
                    .wait(inlined_self.cancel)
                    .await
                    .map_err(|_| "Assessment cancelled".to_owned())?;
                if inlined_self
                    .used
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                        (used < QUERY_LIMIT).then_some(used + 1)
                    })
                    .is_err()
                {
                    inlined_self.limited.store(1, Ordering::Relaxed);
                    return Err("128-query assessment budget exhausted".to_owned());
                }
                match tokio::time::timeout(Duration::from_secs(2), {
                    let (remote, owner, kind, tcp, recursive): (
                        SocketAddr,
                        &str,
                        RecordType,
                        bool,
                        bool,
                    ) = (remote, &key.0, kind, tcp, direct.is_none());
                    async move {
                        let mut query = Message::query();
                        query.metadata.recursion_desired = recursive;
                        let mut edns = hickory_resolver::proto::op::Edns::new();
                        edns.set_max_payload(1232);
                        edns.set_dnssec_ok(true);
                        query.set_edns(edns);
                        query.add_query(Query::query(
                            Name::from_ascii(if owner.is_empty() { "." } else { owner })
                                .map_err(|_| "Invalid DNS name".to_owned())?,
                            kind,
                        ));
                        let request = query
                            .to_vec()
                            .map_err(|_| "Unable to encode DNS query".to_owned())?;
                        let response = if tcp {
                            let mut stream = TcpStream::connect(remote)
                                .await
                                .map_err(|error| error.to_string())?;
                            stream
                                .write_u16(request.len() as u16)
                                .await
                                .map_err(|error| error.to_string())?;
                            stream
                                .write_all(&request)
                                .await
                                .map_err(|error| error.to_string())?;
                            let length =
                                stream.read_u16().await.map_err(|error| error.to_string())?
                                    as usize;
                            let mut response = vec![0; length];
                            stream
                                .read_exact(&mut response)
                                .await
                                .map_err(|error| error.to_string())?;
                            response
                        } else {
                            let bind = if remote.is_ipv4() {
                                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                            } else {
                                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                            };
                            let socket = UdpSocket::bind(bind)
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
                        let response = Message::from_vec(&response)
                            .map_err(|_| "Malformed DNS response".to_owned())?;
                        if response.metadata.id != query.metadata.id
                            || response.metadata.message_type != MessageType::Response
                            || response.queries != query.queries
                        {
                            return Err("DNS response does not match the question".to_owned());
                        }
                        Ok(response)
                    }
                })
                .await
                {
                    Ok(Ok(message))
                        if matches!(
                            message.metadata.response_code,
                            ResponseCode::NoError | ResponseCode::NXDomain
                        ) && !message.metadata.truncation =>
                    {
                        return Ok(message);
                    }
                    Ok(Ok(message)) => {
                        failure = format!(
                            "{} via {} {}{}",
                            message.metadata.response_code,
                            remote,
                            if tcp { "TCP" } else { "UDP" },
                            if message.metadata.truncation {
                                " (truncated)"
                            } else {
                                ""
                            }
                        )
                    }
                    Ok(Err(error)) => {
                        failure = format!("{remote} {}: {error}", if tcp { "TCP" } else { "UDP" })
                    }
                    Err(_) => {
                        failure = format!("{remote} {} timed out", if tcp { "TCP" } else { "UDP" })
                    }
                }
            }
            Err(failure)
        };
        let result = tokio::select! {
            _ = inlined_self.cancel.cancelled() => Err("Assessment cancelled".to_owned()),
            result = tokio::time::timeout(inlined_self.timeout, lookup) => result.unwrap_or_else(|_| Err("Whole DNS query timed out".to_owned())),
        };
        inlined_self.cache.lock().unwrap().insert(key, result.clone());
        result

};
inlined_result
}
}).await {
                Ok(message) => message,
                Err(error) => {
                    result.error = Some(error);
                    return result;
                }
            };
            loop {
                result.records = owned_records(&message.answers, &result.owner, kind);
                if !result.records.is_empty() {
                    return result;
                }
                let aliases = owned_records(&message.answers, &result.owner, RecordType::CNAME);
                if aliases.len() > 1 {
                    result.error = Some("Multiple CNAME destinations at one owner".to_owned());
                    return result;
                }
                let Some(alias) = aliases.first() else {
                    if message.answers.is_empty()
                        && message
                            .authorities
                            .iter()
                            .any(|record| record.record_type() == RecordType::NS)
                    {
                        result.error = Some("Resolver returned an unresolved referral".to_owned());
                        return result;
                    }
                    result.nxdomain = message.metadata.response_code == ResponseCode::NXDomain;
                    return result;
                };
                let target = (&alias.data.to_string())
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if !seen.insert(target.clone()) {
                    result.error = Some("Confirmed CNAME cycle".to_owned());
                    result.aliases.push(target);
                    return result;
                }
                if result.aliases.len() >= DEPTH_LIMIT {
                    result.error = Some("CNAME depth limit (10) reached".to_owned());
                    return result;
                }
                result.aliases.push(format!("{} → {target}", result.owner));
                result.owner = target;
                if !message.answers.iter().any(|record| {
                    (&record.name.to_string())
                        .trim_end_matches('.')
                        .to_ascii_lowercase()
                        == result.owner
                }) {
                    if message.metadata.response_code == ResponseCode::NXDomain {
                        result.nxdomain = true;
                        return result;
                    }
                    break;
                }
            }
        }
    }

    async fn address_sets(&self, name: &str) -> (Rrset, Rrset) {
        if self.concurrency > 1 {
            tokio::join!(
                self.rrset(name, RecordType::A),
                self.rrset(name, RecordType::AAAA)
            )
        } else {
            (
                self.rrset(name, RecordType::A).await,
                self.rrset(name, RecordType::AAAA).await,
            )
        }
    }
}

fn wire(value: &impl BinEncodable) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut encoder = hickory_resolver::proto::serialize::binary::BinEncoder::new(&mut bytes);
    value
        .emit(&mut encoder)
        .map_err(|_| "Unable to encode DNS record".to_owned())?;
    Ok(bytes)
}

fn owned_records(records: &[Record], owner: &str, kind: RecordType) -> Vec<Record> {
    let mut seen = HashSet::new();
    records
        .iter()
        .filter(|record| {
            record.record_type() == kind
                && (&record.name.to_string())
                    .trim_end_matches('.')
                    .to_ascii_lowercase()
                    == (owner).trim_end_matches('.').to_ascii_lowercase()
        })
        .filter(|record| seen.insert(record.data.clone()))
        .cloned()
        .collect()
}

fn unavailable(subject: &str, check: &str, set: &Rrset) -> Option<DnsObservation> {
    set.error.as_ref().map(|error| {
        let invalid_alias = matches!(error.as_str(), "Confirmed CNAME cycle" | "Multiple CNAME destinations at one owner");
        {
let (subject, check, status, summary, impact, remediation, evidence,): (& str, & str, DnsObservationStatus, & str, & str, & str, Vec < String >,) = (subject, check, if invalid_alias { DnsObservationStatus::Error } else { DnsObservationStatus::Inconclusive }, error, if invalid_alias { "The published alias configuration cannot produce a unique terminal answer." } else { "This check could not establish the DNS configuration." }, if invalid_alias { "Publish a single acyclic CNAME path to the intended destination." } else { "Retry after checking DNS reachability; increase coverage if a limit was reached." }, ({
let (inlined_self,): (& Rrset,) = (&(set),);
let inlined_result: Vec < String > = {

        let mut evidence = vec![format!(
            "Record owner: {}; type: {}; outcome: {}; {} matching record(s)",
            inlined_self.owner,
            inlined_self.kind,
            inlined_self.error
                .as_deref()
                .unwrap_or(if inlined_self.nxdomain { "NXDOMAIN" } else { "NOERROR" }),
            inlined_self.records.len()
        )];
        if !inlined_self.aliases.is_empty() {
            evidence.push(format!("Alias path: {}", inlined_self.aliases.join(" → ")));
        }
        evidence

};
inlined_result
}),);

    DnsObservation { subject: subject.to_owned(), check: check.to_owned(), status, summary: summary.to_owned(), impact: impact.to_owned(), remediation: remediation.to_owned(), evidence }

}
    })
}

pub(crate) async fn assess_dns(
    hostname: &str,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> (Vec<DnsObservation>, Vec<String>) {
    use DnsObservationStatus::*;
    send_phase_progress(
        progress,
        ExposureScanPhase::DnsAssessment,
        ExposureScanPhaseState::Running,
        0.0,
        "Collecting bounded DNS posture checks",
    );
    let Some(domain) = registrable_domain(hostname) else {
        send_phase_progress(
            progress,
            ExposureScanPhase::DnsAssessment,
            ExposureScanPhaseState::Complete,
            1.0,
            "DNS posture unavailable",
        );
        return (
            vec![{
                let (subject, check, status, summary, impact, remediation, evidence): (
                    &str,
                    &str,
                    DnsObservationStatus,
                    &str,
                    &str,
                    &str,
                    Vec<String>,
                ) = (
                    hostname,
                    "Assessment coverage",
                    Inconclusive,
                    "Target has no registrable DNS domain",
                    "Domain and email policies cannot be assessed for this target.",
                    "Assess a fully qualified public domain name.",
                    Vec::new(),
                );

                DnsObservation {
                    subject: subject.to_owned(),
                    check: check.to_owned(),
                    status,
                    summary: summary.to_owned(),
                    impact: impact.to_owned(),
                    remediation: remediation.to_owned(),
                    evidence,
                }
            }],
            Vec::new(),
        );
    };
    let collector = {
        let (request, cancel, limiter): (
            &ExposureScanRequest,
            &'_ CancellationToken,
            &'_ ConnectionRateLimiter,
        ) = (request, cancel, limiter);
        {
            let servers = hickory_resolver::system_conf::read_system_conf()
                .map(|(config, _)| {
                    config
                        .name_servers()
                        .iter()
                        .flat_map(|server| {
                            server
                                .connections
                                .iter()
                                .map(|connection| match connection.protocol {
                                    ProtocolConfig::Udp => {
                                        (SocketAddr::new(server.ip, connection.port), false)
                                    }
                                    ProtocolConfig::Tcp => {
                                        (SocketAddr::new(server.ip, connection.port), true)
                                    }
                                })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Collector {
                cache: Mutex::new(HashMap::new()),
                used: AtomicUsize::new(0),
                limited: AtomicUsize::new(0),
                cancel,
                limiter,
                timeout: request.probe_timeout.min(Duration::from_secs(5)),
                concurrency: request.concurrency.max(1),
                servers,
            }
        }
    };
    let mut observations = infrastructure::resolution(hostname, &collector).await;
    observations.extend(policies::caa(hostname, &collector).await);
    send_phase_progress(
        progress,
        ExposureScanPhase::DnsAssessment,
        ExposureScanPhaseState::Running,
        0.2,
        "Checking email authentication and routing",
    );
    observations.extend(mail::spf(&domain, &collector).await);
    observations.extend(policies::dmarc(hostname, &domain, &collector).await);
    if request.dkim_selectors.is_empty() {
        observations.push({
let (subject, check, status, summary, impact, remediation, evidence,): (& str, & str, DnsObservationStatus, & str, & str, & str, Vec < String >,) = (&domain, "DKIM", Recommendation, "No DKIM selectors supplied", "DKIM publication and key strength were not assessed.", "Supply selectors from your mail provider or a signed message; selectors are not guessed.", Vec::new(),);

    DnsObservation { subject: subject.to_owned(), check: check.to_owned(), status, summary: summary.to_owned(), impact: impact.to_owned(), remediation: remediation.to_owned(), evidence }

});
    }
    let mut selectors = HashSet::new();
    for selector in &request.dkim_selectors {
        if cancel.is_cancelled() {
            break;
        }
        if !selectors.insert(selector.to_ascii_lowercase()) {
            continue;
        }
        let owner = format!("{selector}._domainkey.{domain}");
        let set = collector.rrset(&owner, RecordType::TXT).await;
        observations.extend(policies::dkim(&owner, &set));
    }
    observations.extend(mail::routing(&domain, &collector).await);
    observations.extend(policies::transport(&domain, &collector).await);
    send_phase_progress(
        progress,
        ExposureScanPhase::DnsAssessment,
        ExposureScanPhaseState::Running,
        0.6,
        "Checking delegation, nameservers, SOA and DNSSEC structure",
    );
    observations.extend(infrastructure::authority(&domain, &collector).await);
    if cancel.is_cancelled() {
        observations.push({
            let (subject, check, status, summary, impact, remediation, evidence): (
                &str,
                &str,
                DnsObservationStatus,
                &str,
                &str,
                &str,
                Vec<String>,
            ) = (
                hostname,
                "Assessment coverage",
                Inconclusive,
                "DNS assessment cancelled; results are incomplete",
                "Only checks completed before cancellation are available.",
                "Run DNS assessment again to complete coverage.",
                Vec::new(),
            );

            DnsObservation {
                subject: subject.to_owned(),
                check: check.to_owned(),
                status,
                summary: summary.to_owned(),
                impact: impact.to_owned(),
                remediation: remediation.to_owned(),
                evidence,
            }
        });
    }
    if collector.limited.load(Ordering::Relaxed) != 0 {
        observations.push({
            let (subject, check, status, summary, impact, remediation, evidence): (
                &str,
                &str,
                DnsObservationStatus,
                &str,
                &str,
                &str,
                Vec<String>,
            ) = (
                hostname,
                "Assessment coverage",
                Inconclusive,
                "128-query budget exhausted; results are incomplete",
                "Some DNS dependencies or advertised servers were not checked.",
                "Review unassessed dependencies separately or reduce supplied selectors.",
                Vec::new(),
            );

            DnsObservation {
                subject: subject.to_owned(),
                check: check.to_owned(),
                status,
                summary: summary.to_owned(),
                impact: impact.to_owned(),
                remediation: remediation.to_owned(),
                evidence,
            }
        });
    }
    let mut indices = HashMap::<(String, String, String, String), usize>::new();
    let mut merged = Vec::<DnsObservation>::new();
    for item in observations {
        let key = (
            item.subject.clone(),
            item.check.clone(),
            item.status.to_string(),
            item.summary.clone(),
        );
        if let Some(index) = indices.get(&key) {
            for evidence in item.evidence {
                if !merged[*index].evidence.contains(&evidence) {
                    merged[*index].evidence.push(evidence);
                }
            }
        } else {
            indices.insert(key, merged.len());
            merged.push(item);
        }
    }
    let mut observations = merged;
    observations.sort_by_key(|item| match item.status {
        Error => 0,
        Warning => 1,
        Recommendation => 2,
        Inconclusive => 3,
        Informational => 4,
        Pass => 5,
    });
    if let Some(progress) = progress {
        for (index, observation) in observations.iter().enumerate() {
            let _ = progress.send(ExposureScanProgress::DnsObservationCompleted {
                completed: index + 1,
                total: observations.len(),
                observation: observation.clone(),
            });
        }
    }
    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::DnsAssessment,
            ExposureScanPhaseState::Complete,
            1.0,
            format!(
                "{} DNS findings; {} / 128 queries",
                observations.len(),
                collector.used.load(Ordering::Relaxed)
            ),
        );
    }
    (observations, Vec::new())
}

fn finding(
    subject: &str,
    check: &str,
    status: DnsObservationStatus,
    summary: &str,
    impact: &str,
    remediation: &str,
    evidence: Vec<String>,
) -> DnsObservation {
    DnsObservation {
        subject: subject.to_owned(),
        check: check.to_owned(),
        status,
        summary: summary.to_owned(),
        impact: impact.to_owned(),
        remediation: remediation.to_owned(),
        evidence,
    }
}

impl Rrset {
    fn evidence(&self) -> Vec<String> {
        let mut evidence = vec![format!(
            "Record owner: {}; type: {}; outcome: {}; {} matching record(s)",
            self.owner,
            self.kind,
            self.error
                .as_deref()
                .unwrap_or(if self.nxdomain { "NXDOMAIN" } else { "NOERROR" }),
            self.records.len()
        )];
        if !self.aliases.is_empty() {
            evidence.push(format!("Alias path: {}", self.aliases.join(" → ")));
        }
        evidence
    }
}

impl<'a> Collector<'a> {
    async fn query(
        &self,
        owner: &str,
        kind: RecordType,
        direct: Option<(SocketAddr, bool)>,
    ) -> QueryResult {
        if self.cancel.is_cancelled() {
            return Err("Assessment cancelled".to_owned());
        }
        let key = (
            (owner).trim_end_matches('.').to_ascii_lowercase(),
            kind,
            direct,
        );
        if let Some(result) = self.cache.lock().unwrap().get(&key).cloned() {
            return result;
        }
        if self.limited.load(Ordering::Relaxed) != 0 {
            return Err("128-query assessment budget exhausted".to_owned());
        }
        let lookup = async {
            let servers = direct
                .map(|server| vec![server])
                .unwrap_or_else(|| self.servers.clone());
            let mut failure = "No supported system DNS resolver is configured".to_owned();
            for (remote, tcp) in servers {
                self.limiter
                    .wait(self.cancel)
                    .await
                    .map_err(|_| "Assessment cancelled".to_owned())?;
                if self
                    .used
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                        (used < QUERY_LIMIT).then_some(used + 1)
                    })
                    .is_err()
                {
                    self.limited.store(1, Ordering::Relaxed);
                    return Err("128-query assessment budget exhausted".to_owned());
                }
                match tokio::time::timeout(Duration::from_secs(2), {
                    let (remote, owner, kind, tcp, recursive): (
                        SocketAddr,
                        &str,
                        RecordType,
                        bool,
                        bool,
                    ) = (remote, &key.0, kind, tcp, direct.is_none());
                    async move {
                        let mut query = Message::query();
                        query.metadata.recursion_desired = recursive;
                        let mut edns = hickory_resolver::proto::op::Edns::new();
                        edns.set_max_payload(1232);
                        edns.set_dnssec_ok(true);
                        query.set_edns(edns);
                        query.add_query(Query::query(
                            Name::from_ascii(if owner.is_empty() { "." } else { owner })
                                .map_err(|_| "Invalid DNS name".to_owned())?,
                            kind,
                        ));
                        let request = query
                            .to_vec()
                            .map_err(|_| "Unable to encode DNS query".to_owned())?;
                        let response = if tcp {
                            let mut stream = TcpStream::connect(remote)
                                .await
                                .map_err(|error| error.to_string())?;
                            stream
                                .write_u16(request.len() as u16)
                                .await
                                .map_err(|error| error.to_string())?;
                            stream
                                .write_all(&request)
                                .await
                                .map_err(|error| error.to_string())?;
                            let length =
                                stream.read_u16().await.map_err(|error| error.to_string())?
                                    as usize;
                            let mut response = vec![0; length];
                            stream
                                .read_exact(&mut response)
                                .await
                                .map_err(|error| error.to_string())?;
                            response
                        } else {
                            let bind = if remote.is_ipv4() {
                                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                            } else {
                                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                            };
                            let socket = UdpSocket::bind(bind)
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
                        let response = Message::from_vec(&response)
                            .map_err(|_| "Malformed DNS response".to_owned())?;
                        if response.metadata.id != query.metadata.id
                            || response.metadata.message_type != MessageType::Response
                            || response.queries != query.queries
                        {
                            return Err("DNS response does not match the question".to_owned());
                        }
                        Ok(response)
                    }
                })
                .await
                {
                    Ok(Ok(message))
                        if matches!(
                            message.metadata.response_code,
                            ResponseCode::NoError | ResponseCode::NXDomain
                        ) && !message.metadata.truncation =>
                    {
                        return Ok(message);
                    }
                    Ok(Ok(message)) => {
                        failure = format!(
                            "{} via {} {}{}",
                            message.metadata.response_code,
                            remote,
                            if tcp { "TCP" } else { "UDP" },
                            if message.metadata.truncation {
                                " (truncated)"
                            } else {
                                ""
                            }
                        )
                    }
                    Ok(Err(error)) => {
                        failure = format!("{remote} {}: {error}", if tcp { "TCP" } else { "UDP" })
                    }
                    Err(_) => {
                        failure = format!("{remote} {} timed out", if tcp { "TCP" } else { "UDP" })
                    }
                }
            }
            Err(failure)
        };
        let result = tokio::select! {
            _ = self.cancel.cancelled() => Err("Assessment cancelled".to_owned()),
            result = tokio::time::timeout(self.timeout, lookup) => result.unwrap_or_else(|_| Err("Whole DNS query timed out".to_owned())),
        };
        self.cache.lock().unwrap().insert(key, result.clone());
        result
    }
}
