use super::*;
use crate::diagnostics::DnsLookupStatus;
use crate::dns_lookup::{self, AliasPath, owned_records};
use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::proto::serialize::binary::BinEncodable;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    attempts: Mutex<HashMap<QueryKey, Vec<crate::diagnostics::DnsAttempt>>>,
}

#[derive(Clone, Debug)]
struct Rrset {
    owner: String,
    kind: RecordType,
    records: Vec<Record>,
    aliases: Vec<(String, String)>,
    nxdomain: bool,
    status: DnsLookupStatus,
    attempts: Vec<crate::diagnostics::DnsAttempt>,
    error: Option<String>,
}

impl Rrset {
    fn absent(&self) -> bool {
        matches!(
            self.status,
            DnsLookupStatus::NoData | DnsLookupStatus::NxDomain
        )
    }

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
    fn new(
        request: &ExposureScanRequest,
        cancel: &'a CancellationToken,
        limiter: &'a ConnectionRateLimiter,
    ) -> Self {
        let servers = hickory_resolver::system_conf::read_system_conf()
            .map(|(config, _)| dns_lookup::transports(config.name_servers()))
            .unwrap_or_default();
        Self {
            cache: Mutex::new(HashMap::new()),
            attempts: Mutex::new(HashMap::new()),
            used: AtomicUsize::new(0),
            limited: AtomicUsize::new(0),
            cancel,
            limiter,
            timeout: request.probe_timeout.min(Duration::from_secs(5)),
            concurrency: request.concurrency.max(1),
            servers,
        }
    }

    async fn rrset(&self, name: &str, kind: RecordType) -> Rrset {
        let mut path = AliasPath::new(name);
        let mut result = Rrset {
            owner: path.owner.clone(),
            kind,
            records: Vec::new(),
            aliases: Vec::new(),
            nxdomain: false,
            status: DnsLookupStatus::Pending,
            error: None,
            attempts: Vec::new(),
        };
        let outcome = loop {
            let reply = self.query(&path.owner, kind, None).await;
            if let Some(attempts) =
                self.attempts
                    .lock()
                    .unwrap()
                    .get(&(path.owner.clone(), kind, None))
            {
                result.attempts.extend(attempts.iter().cloned());
            }
            let message = match reply {
                Ok(message) => message,
                Err(error) => break Err(error),
            };
            match path.consume(&message, kind) {
                Ok(Some((status, records))) => {
                    result.records = records;
                    break Ok(status);
                }
                Ok(None) => {}
                Err(error) => break Err(error),
            }
        };
        result.owner = path.owner;
        result.aliases = path.aliases;
        match outcome {
            Ok(status) => {
                result.status = status;
                result.nxdomain = status == DnsLookupStatus::NxDomain;
            }
            Err(error) => {
                result.status = if self.cancel.is_cancelled() {
                    DnsLookupStatus::Cancelled
                } else if error.contains("limit") || error.contains("budget") {
                    DnsLookupStatus::LimitReached
                } else {
                    DnsLookupStatus::Failed
                };
                result.error = Some(error);
            }
        }
        result
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

fn unavailable(subject: &str, check: &str, set: &Rrset) -> Option<DnsObservation> {
    set.error.as_ref().map(|error| {
        let invalid_alias = matches!(
            error.as_str(),
            "Confirmed CNAME cycle" | "Multiple CNAME destinations at one owner"
        );
        finding(
            subject,
            check,
            if invalid_alias {
                DnsObservationStatus::Error
            } else {
                DnsObservationStatus::Inconclusive
            },
            error,
            if invalid_alias {
                "The published alias configuration cannot produce a unique terminal answer."
            } else {
                "This check could not establish the DNS configuration."
            },
            if invalid_alias {
                "Publish a single acyclic CNAME path to the intended destination."
            } else {
                "Retry after checking DNS reachability; increase coverage if a limit was reached."
            },
            set.evidence(),
        )
    })
}

pub(super) async fn resolve_asset(
    hostname: String,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
) -> (DiscoveredAsset, bool) {
    let collector = Collector::new(request, cancel, limiter);
    let (a, aaaa) = collector.address_sets(&hostname).await;
    let complete = [&a, &aaaa].iter().all(|set| {
        !matches!(
            set.status,
            DnsLookupStatus::Pending | DnsLookupStatus::Cancelled
        )
    });
    (asset_from_sets(hostname, &a, &aaaa), complete)
}

fn asset_from_sets(hostname: String, a: &Rrset, aaaa: &Rrset) -> DiscoveredAsset {
    let mut addresses = a
        .addresses()
        .into_iter()
        .chain(aaaa.addresses())
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    let mut seen = HashSet::new();
    let cname_chain = a
        .aliases
        .iter()
        .chain(&aaaa.aliases)
        .map(|(_, target)| target.clone())
        .filter(|target| seen.insert(target.clone()))
        .collect::<Vec<_>>();
    let state = if addresses
        .iter()
        .any(|address| non_public_reason(*address).is_none())
    {
        DiscoveredAssetState::Public
    } else if !addresses.is_empty() {
        DiscoveredAssetState::NonPublic
    } else if !cname_chain.is_empty() && a.absent() && aaaa.absent() {
        DiscoveredAssetState::DanglingCname
    } else {
        DiscoveredAssetState::Unresolved
    };
    let summary = match state {
        DiscoveredAssetState::Public => "One or more public DNS destinations resolved",
        DiscoveredAssetState::NonPublic => "DNS resolved only non-public destinations",
        DiscoveredAssetState::DanglingCname => {
            "CNAME chain has no A or AAAA destination; exploitability was not tested"
        }
        DiscoveredAssetState::Unresolved => "No usable A or AAAA result was obtained",
    };
    DiscoveredAsset {
        hostname,
        source: "crt.sh certificate transparency".to_owned(),
        addresses,
        cname_chain,
        state,
        detail: format!(
            "{summary}; {}",
            a.evidence()
                .into_iter()
                .chain(aaaa.evidence())
                .collect::<Vec<_>>()
                .join("; ")
        ),
    }
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
    let collector = Collector::new(request, cancel, limiter);
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
                .clone()
                .unwrap_or_else(|| self.status.to_string()),
            self.records.len()
        )];
        for attempt in &self.attempts {
            evidence.push(format!(
                "{} {}: {}{} ({:.2} ms network time)",
                attempt.configured_resolver,
                attempt.transport,
                attempt.response_code.as_deref().unwrap_or("No response"),
                attempt
                    .error
                    .as_ref()
                    .map(|error| format!("; {error}"))
                    .unwrap_or_default(),
                attempt.duration_ms
            ));
        }
        if !self.aliases.is_empty() {
            evidence.push(format!(
                "Alias path: {}",
                self.aliases
                    .iter()
                    .map(|(owner, target)| format!("{owner} → {target}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
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
        let servers = direct
            .map(|server| vec![server])
            .unwrap_or_else(|| self.servers.clone());
        let lookup = dns_lookup::query(
            &key.0,
            kind,
            &servers,
            direct.is_none(),
            Duration::from_secs(2),
            self.timeout,
            || async {
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
                Ok(())
            },
            |attempt| {
                self.attempts
                    .lock()
                    .unwrap()
                    .entry(key.clone())
                    .or_default()
                    .push(attempt)
            },
        );
        let result = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err("Assessment cancelled".to_owned()),
            result = lookup => result,
        };
        self.cache.lock().unwrap().insert(key, result.clone());
        result
    }
}
