use crate::diagnostics::{DnsAttempt, DnsLookupOutcome, DnsLookupStatus, DnsRecord, DnsTrace};
use crate::dns_lookup::{self, AliasPath};
use futures_util::{StreamExt, stream};
use hickory_resolver::proto::rr::{RData, RecordType};
use std::net::IpAddr;
use std::time::{Duration, Instant};

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
    resolve(host, trace, LIMITED_RECORD_TYPES).await
}

pub(crate) async fn resolve_host_exhaustive(
    host: &str,
    trace: &mut DnsTrace,
) -> Result<(), String> {
    resolve(host, trace, EXHAUSTIVE_RECORD_TYPES).await
}

async fn resolve(host: &str, trace: &mut DnsTrace, kinds: &[RecordType]) -> Result<(), String> {
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        trace.configured_resolvers = vec!["Not used (IP literal)".to_owned()];
        trace.addresses = vec![ip];
        let kind = if ip.is_ipv4() { "A" } else { "AAAA" }.to_owned();
        trace.records = vec![DnsRecord {
            name: host.to_owned(),
            record_type: kind.clone(),
            ttl: 0,
            value: ip.to_string(),
        }];
        trace.attempts = vec![DnsAttempt {
            record_type: kind,
            configured_resolver: "Not used (IP literal)".to_owned(),
            responder: None,
            transport: "Literal".to_owned(),
            response_code: Some("LITERAL".to_owned()),
            duration_ms: 0.0,
            error: None,
        }];
        trace.incomplete_record_types.clear();
        trace.lookup_outcomes = vec![DnsLookupOutcome {
            record_type: if ip.is_ipv4() { "A" } else { "AAAA" }.to_owned(),
            queried_name: host.to_owned(),
            terminal_name: host.to_owned(),
            aliases: Vec::new(),
            status: DnsLookupStatus::Answer,
            failure: None,
        }];
        return Ok(());
    }
    trace.lookup_outcomes = kinds
        .iter()
        .map(|kind| DnsLookupOutcome {
            record_type: kind.to_string(),
            queried_name: host.to_owned(),
            terminal_name: host.to_owned(),
            aliases: Vec::new(),
            status: DnsLookupStatus::Pending,
            failure: None,
        })
        .collect();
    trace.incomplete_record_types = kinds.iter().map(ToString::to_string).collect();
    let (config, options) = match hickory_resolver::system_conf::read_system_conf() {
        Ok(config) => config,
        Err(error) => {
            let error = format!("Unable to read system DNS configuration: {error}");
            for outcome in &mut trace.lookup_outcomes {
                outcome.status = DnsLookupStatus::Failed;
                outcome.failure = Some(error.clone());
            }
            return Err(error);
        }
    };
    let servers = dns_lookup::transports(config.name_servers());
    trace.configured_resolvers = servers
        .iter()
        .map(|(remote, tcp)| format!("{remote} ({})", if *tcp { "TCP" } else { "UDP" }))
        .collect();
    let timeout = options.timeout.min(Duration::from_secs(2));
    collect_lookups(host, trace, kinds, &servers, timeout).await;
    Ok(())
}

async fn collect_lookups(
    host: &str,
    trace: &mut DnsTrace,
    kinds: &[RecordType],
    servers: &[(std::net::SocketAddr, bool)],
    timeout: Duration,
) {
    let attempts = std::sync::Mutex::new(&mut trace.attempts);
    let lookups = stream::iter(kinds.iter().copied().zip(trace.lookup_outcomes.iter_mut()))
        .map(|(kind, outcome)| lookup(host, kind, &servers, timeout, outcome, &attempts))
        .buffer_unordered(kinds.len());
    tokio::pin!(lookups);
    while let Some(result) = lookups.next().await {
        if result.status.conclusive() {
            trace
                .incomplete_record_types
                .retain(|pending| pending != &result.kind.to_string());
        }
        for address in result.addresses {
            if !trace.addresses.contains(&address) {
                trace.addresses.push(address);
            }
        }
        for record in result.records {
            let record = DnsRecord {
                name: record.name.to_string(),
                record_type: record.record_type().to_string(),
                ttl: record.ttl,
                value: record.data.to_string(),
            };
            if !trace.records.iter().any(|existing| {
                existing.name == record.name
                    && existing.record_type == record.record_type
                    && existing.ttl == record.ttl
                    && existing.value == record.value
            }) {
                trace.records.push(record);
            }
        }
    }
}

struct LookupResult {
    kind: RecordType,
    status: DnsLookupStatus,
    records: Vec<hickory_resolver::proto::rr::Record>,
    addresses: Vec<IpAddr>,
}

async fn lookup(
    host: &str,
    kind: RecordType,
    servers: &[(std::net::SocketAddr, bool)],
    timeout: Duration,
    outcome: &mut DnsLookupOutcome,
    attempts: &std::sync::Mutex<&mut Vec<DnsAttempt>>,
) -> LookupResult {
    let mut path = AliasPath::new(host);
    let mut records = Vec::new();
    let mut addresses = Vec::new();
    let result =
        loop {
            let message = match dns_lookup::query(
                &path.owner,
                kind,
                servers,
                true,
                timeout,
                Duration::MAX,
                || async { Ok(()) },
                |attempt| attempts.lock().unwrap().push(attempt),
            )
            .await
            {
                Ok(message) => message,
                Err(error) => break Err(error),
            };
            records.extend(message.all_sections().cloned());
            let consumed = path.consume(&message, kind);
            outcome.terminal_name = path.owner.clone();
            outcome.aliases = path.aliases.clone();
            match consumed {
                Ok(Some((status, terminal_records))) => {
                    addresses.extend(terminal_records.iter().filter_map(
                        |record| match &record.data {
                            RData::A(address) => Some(IpAddr::V4(address.0)),
                            RData::AAAA(address) => Some(IpAddr::V6(address.0)),
                            _ => None,
                        },
                    ));
                    break Ok(status);
                }
                Ok(None) => {}
                Err(error) => break Err(error),
            }
        };
    let (status, failure) = match result {
        Ok(status) => (status, None),
        Err(error) => (
            if error.contains("limit") {
                DnsLookupStatus::LimitReached
            } else {
                DnsLookupStatus::Failed
            },
            Some(error),
        ),
    };
    outcome.status = status;
    outcome.failure = failure;
    LookupResult {
        kind,
        status,
        records,
        addresses,
    }
}

pub(super) fn finish_interrupted_dns_attempt(
    trace: &mut DnsTrace,
    _started: Instant,
    reason: &str,
) {
    for outcome in &mut trace.lookup_outcomes {
        if outcome.status == DnsLookupStatus::Pending {
            outcome.status = if reason.to_ascii_lowercase().contains("cancel") {
                DnsLookupStatus::Cancelled
            } else {
                DnsLookupStatus::LimitReached
            };
            outcome.failure = Some(format!(
                "{reason}; DNS coverage interrupted, not evidence of record absence"
            ));
        }
    }
}
