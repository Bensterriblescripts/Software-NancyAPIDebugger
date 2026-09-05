use super::*;
use hickory_resolver::proto::op::{Message, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RecordType};
use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

const CT_RESPONSE_LIMIT: usize = 4 * 1024 * 1024;
const DNS_RESPONSE_LIMIT: usize = 16 * 1024;

#[derive(Deserialize)]
struct CtEntry {
    #[serde(default)]
    name_value: String,
}

pub(super) fn registrable_domain(hostname: &str) -> Option<String> {
    if hostname.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        return None;
    }
    let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    psl::domain_str(&hostname).map(str::to_owned)
}

pub(super) async fn discover_assets(
    hostname: &str,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: Arc<ConnectionRateLimiter>,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> (Vec<DiscoveredAsset>, Vec<String>) {
    send_phase_progress(
        progress,
        ExposureScanPhase::AssetDiscovery,
        ExposureScanPhaseState::Running,
        0.0,
        "Deriving registrable domain",
    );
    let Some(domain) = registrable_domain(hostname) else {
        send_phase_progress(
            progress,
            ExposureScanPhase::AssetDiscovery,
            ExposureScanPhaseState::Complete,
            1.0,
            "Asset discovery unavailable",
        );
        return (
            Vec::new(),
            vec![
                "CT asset discovery was disabled because the target has no valid registrable domain boundary"
                    .to_owned(),
            ],
        );
    };
    let names = match fetch_ct_names(&domain, request, cancel, limiter.as_ref()).await {
        Ok(names) => names,
        Err(error) => {
            send_phase_progress(
                progress,
                ExposureScanPhase::AssetDiscovery,
                ExposureScanPhaseState::Complete,
                1.0,
                "CT provider unavailable",
            );
            return (
                Vec::new(),
                vec![format!("CT asset discovery was nonfatal: {error}")],
            );
        }
    };
    let total = names.len();
    let mut pending = FuturesUnordered::new();
    let mut next = 0usize;
    let mut assets = Vec::with_capacity(total);
    while next < names.len() || !pending.is_empty() {
        while next < names.len() && pending.len() < request.concurrency && !cancel.is_cancelled() {
            let name = names[next].clone();
            next += 1;
            pending.push(resolve_asset(name, cancel, limiter.clone()));
        }
        let Some(asset) = pending.next().await else {
            break;
        };
        if let Some(progress) = progress {
            let _ = progress.send(ExposureScanProgress::AssetDiscovered {
                completed: assets.len() + 1,
                total,
                asset: asset.clone(),
            });
        }
        assets.push(asset);
        send_phase_progress(
            progress,
            ExposureScanPhase::AssetDiscovery,
            ExposureScanPhaseState::Running,
            assets.len() as f32 / total.max(1) as f32,
            format!("Resolved {} / {total} CT hostnames", assets.len()),
        );
        if cancel.is_cancelled() {
            break;
        }
    }
    assets.sort_by(|left, right| left.hostname.cmp(&right.hostname));
    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::AssetDiscovery,
            ExposureScanPhaseState::Complete,
            1.0,
            format!("{} inventory-only CT assets", assets.len()),
        );
    }
    (assets, Vec::new())
}

async fn fetch_ct_names(
    domain: &str,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
) -> Result<Vec<String>, String> {
    let mut dns = DnsTrace::default();
    tokio::select! {
        _ = cancel.cancelled() => return Err("cancelled".to_owned()),
        result = resolve_host("crt.sh", &mut dns) => result?,
    }
    let mut bounded_request = request.clone();
    bounded_request.connection_timeout = bounded_request
        .connection_timeout
        .min(Duration::from_secs(5));
    bounded_request.probe_timeout = bounded_request.probe_timeout.min(Duration::from_secs(15));
    let path = format!("/?q=%25.{domain}&output=json");
    let mut last_error = "crt.sh has no public address".to_owned();
    for ip in dns.addresses {
        if non_public_reason(ip).is_some() {
            continue;
        }
        let context = ProbeContext {
            ip,
            port: 443,
            scan: ScanContext {
                hostname: "crt.sh",
                request: &bounded_request,
                cancel,
                limiter,
                client_certificate: None,
            },
        };
        match single_http_request_with_limit(
            context,
            "https",
            "GET",
            &path,
            &[("Accept", "application/json")],
            CT_RESPONSE_LIMIT,
        )
        .await
        {
            Ok(response) if response.status == 200 && !response.body_truncated => {
                let entries = serde_json::from_slice::<Vec<CtEntry>>(&response.body)
                    .map_err(|error| format!("crt.sh returned invalid JSON: {error}"))?;
                let mut names = entries
                    .iter()
                    .flat_map(|entry| entry.name_value.lines())
                    .filter_map(normalize_ct_name)
                    .filter(|name| within_domain(name, domain))
                    .collect::<Vec<_>>();
                names.sort();
                names.dedup();
                names.truncate(request.ct_hostname_limit);
                return Ok(names);
            }
            Ok(response) if response.body_truncated => {
                last_error = "crt.sh response exceeded the 4 MiB limit".to_owned();
            }
            Ok(response) => {
                last_error = format!("crt.sh returned HTTP {}", response.status);
            }
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn normalize_ct_name(value: &str) -> Option<String> {
    let value = value
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || value.parse::<IpAddr>().is_ok()
        || !value.is_ascii()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        None
    } else {
        Some(value)
    }
}

fn within_domain(name: &str, domain: &str) -> bool {
    name == domain
        || name
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

async fn resolve_asset(
    hostname: String,
    cancel: &CancellationToken,
    limiter: Arc<ConnectionRateLimiter>,
) -> DiscoveredAsset {
    let mut trace = DnsTrace::default();
    let resolution = if limiter.wait(cancel).await.is_err() {
        Err("cancelled".to_owned())
    } else {
        tokio::select! {
            _ = cancel.cancelled() => Err("cancelled".to_owned()),
            result = resolve_host(&hostname, &mut trace) => result,
        }
    };
    let mut addresses = trace.addresses;
    addresses.sort();
    addresses.dedup();
    let mut cname_chain = trace
        .records
        .iter()
        .filter(|record| record.record_type == "CNAME")
        .map(|record| record.value.trim_end_matches('.').to_ascii_lowercase())
        .collect::<Vec<_>>();
    cname_chain.dedup();
    let final_dns_answer = trace.attempts.iter().any(|attempt| {
        matches!(attempt.record_type.as_str(), "A" | "AAAA")
            && attempt.error.is_none()
            && attempt.response_code.as_deref().is_some_and(|code| {
                let normalized = code
                    .chars()
                    .filter(|character| !character.is_ascii_whitespace())
                    .collect::<String>();
                normalized.eq_ignore_ascii_case("NoError")
                    || normalized.eq_ignore_ascii_case("NXDomain")
            })
    });
    let state = if addresses
        .iter()
        .any(|address| non_public_reason(*address).is_none())
    {
        DiscoveredAssetState::Public
    } else if !addresses.is_empty() {
        DiscoveredAssetState::NonPublic
    } else if !cname_chain.is_empty() && final_dns_answer {
        DiscoveredAssetState::DanglingCname
    } else {
        DiscoveredAssetState::Unresolved
    };
    let detail = match state {
        DiscoveredAssetState::Public => "One or more public DNS destinations resolved",
        DiscoveredAssetState::NonPublic => "DNS resolved only non-public destinations",
        DiscoveredAssetState::DanglingCname => {
            "CNAME chain has no usable destination; exploitability was not tested"
        }
        DiscoveredAssetState::Unresolved => "No usable A or AAAA result was obtained",
    }
    .to_owned();
    DiscoveredAsset {
        hostname,
        source: "crt.sh certificate transparency".to_owned(),
        addresses,
        cname_chain,
        state,
        detail: if let Err(error) = resolution {
            format!("{detail}: {error}")
        } else {
            detail
        },
    }
}

pub(super) async fn assess_dns(
    hostname: &str,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> (Vec<DnsObservation>, Vec<String>) {
    send_phase_progress(
        progress,
        ExposureScanPhase::DnsAssessment,
        ExposureScanPhaseState::Running,
        0.0,
        "Collecting public DNS records",
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
            Vec::new(),
            vec![
                "DNS posture assessment was disabled because the target has no valid registrable domain boundary"
                    .to_owned(),
            ],
        );
    };
    let mut domain_trace = DnsTrace::default();
    let mut host_trace = DnsTrace::default();
    let domain_result = tokio::select! {
        _ = cancel.cancelled() => Err("cancelled".to_owned()),
        result = crate::request::resolve_host_exhaustive(&domain, &mut domain_trace) => result,
    };
    if cancel.is_cancelled() {
        return (Vec::new(), Vec::new());
    }
    let host_result = tokio::select! {
        _ = cancel.cancelled() => Err("cancelled".to_owned()),
        result = crate::request::resolve_host_exhaustive(hostname, &mut host_trace) => result,
    };
    let mut observations = Vec::new();
    if let Err(error) = domain_result {
        observations.push(observation(
            &domain,
            "DNS collection",
            DnsObservationStatus::Inconclusive,
            "Domain record collection failed",
            vec![error],
        ));
    }
    if let Err(error) = host_result {
        observations.push(observation(
            hostname,
            "DNS collection",
            DnsObservationStatus::Inconclusive,
            "Hostname record collection failed",
            vec![error],
        ));
    }
    observations.extend(cname_observations(hostname, &host_trace));
    observations.extend(caa_observations(&domain, &domain_trace));
    observations.extend(dnssec_observations(&domain, &domain_trace));
    observations.extend(spf_observations(&domain, &domain_trace));

    send_phase_progress(
        progress,
        ExposureScanPhase::DnsAssessment,
        ExposureScanPhaseState::Running,
        0.4,
        "Checking DMARC and supplied DKIM selectors",
    );
    observations.extend(dmarc_observations(
        &domain,
        query_trace(&format!("_dmarc.{domain}"), cancel).await,
    ));
    for selector in &request.dkim_selectors {
        if cancel.is_cancelled() {
            break;
        }
        let subject = format!("{selector}._domainkey.{domain}");
        observations.extend(dkim_observations(
            &subject,
            selector,
            query_trace(&subject, cancel).await,
        ));
    }

    send_phase_progress(
        progress,
        ExposureScanPhase::DnsAssessment,
        ExposureScanPhaseState::Running,
        0.7,
        "Checking authoritative DNS service",
    );
    observations.extend(authority_observations(&domain, &domain_trace, cancel).await);
    if let Some(progress) = progress {
        let total = observations.len();
        for (index, observation) in observations.iter().enumerate() {
            let _ = progress.send(ExposureScanProgress::DnsObservationCompleted {
                completed: index + 1,
                total,
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
            format!("{} DNS observations", observations.len()),
        );
    }
    (observations, Vec::new())
}

async fn query_trace(name: &str, cancel: &CancellationToken) -> DnsTrace {
    let mut trace = DnsTrace::default();
    let _ = tokio::select! {
        _ = cancel.cancelled() => Err("cancelled".to_owned()),
        result = crate::request::resolve_host_exhaustive(name, &mut trace) => result,
    };
    trace
}

fn records(trace: &DnsTrace, kind: &str) -> Vec<String> {
    trace
        .records
        .iter()
        .filter(|record| record.record_type.eq_ignore_ascii_case(kind))
        .map(|record| record.value.clone())
        .collect()
}

fn cname_observations(hostname: &str, trace: &DnsTrace) -> Vec<DnsObservation> {
    let cnames = records(trace, "CNAME")
        .into_iter()
        .map(|value| value.trim_end_matches('.').to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut seen = HashSet::new();
    let looped = cnames.iter().any(|name| !seen.insert(name.clone()));
    let broken = !cnames.is_empty() && trace.addresses.is_empty() && !looped;
    if looped {
        vec![observation(
            hostname,
            "CNAME chain",
            DnsObservationStatus::Warning,
            "CNAME loop detected",
            cnames,
        )]
    } else if broken {
        vec![observation(
            hostname,
            "CNAME chain",
            DnsObservationStatus::Warning,
            "CNAME chain has no usable A or AAAA destination",
            cnames,
        )]
    } else {
        vec![observation(
            hostname,
            "CNAME chain",
            DnsObservationStatus::Pass,
            "No CNAME loop or broken chain was observed",
            cnames,
        )]
    }
}

fn caa_observations(domain: &str, trace: &DnsTrace) -> Vec<DnsObservation> {
    let caa = records(trace, "CAA");
    if caa.is_empty() {
        return vec![observation(
            domain,
            "CAA",
            DnsObservationStatus::Informational,
            "No CAA record was observed",
            Vec::new(),
        )];
    }
    let malformed = caa.iter().any(|value| {
        let lower = value.to_ascii_lowercase();
        !lower.contains(" issue ") && !lower.contains(" issuewild ") && !lower.contains(" iodef ")
    });
    let denies_all = caa.iter().any(|value| {
        let lower = value.to_ascii_lowercase();
        lower.contains(" issue ") && lower.contains("\";\"")
    });
    let permits_issuer = caa.iter().any(|value| {
        let lower = value.to_ascii_lowercase();
        lower.contains(" issue ") && !lower.contains("\";\"")
    });
    let conflicting = denies_all && permits_issuer;
    vec![observation(
        domain,
        "CAA",
        if malformed || conflicting {
            DnsObservationStatus::Warning
        } else {
            DnsObservationStatus::Pass
        },
        if malformed {
            "CAA records contain an unrecognized or malformed property"
        } else if conflicting {
            "CAA issuer restrictions appear conflicting"
        } else {
            "CAA issuer policy is present"
        },
        caa,
    )]
}

fn dnssec_observations(domain: &str, trace: &DnsTrace) -> Vec<DnsObservation> {
    let ds = records(trace, "DS");
    let dnskey = records(trace, "DNSKEY");
    let rrsig = records(trace, "RRSIG");
    let mismatch = (!ds.is_empty() && (dnskey.is_empty() || rrsig.is_empty()))
        || (ds.is_empty() && !dnskey.is_empty());
    vec![observation(
        domain,
        "DNSSEC structure",
        if mismatch {
            DnsObservationStatus::Warning
        } else if ds.is_empty() && dnskey.is_empty() {
            DnsObservationStatus::Informational
        } else {
            DnsObservationStatus::Pass
        },
        if mismatch {
            "DNSSEC delegation material has an obvious structural mismatch"
        } else if ds.is_empty() {
            "No DNSSEC delegation was observed"
        } else {
            "DS, DNSKEY, and RRSIG structure was observed"
        },
        vec![
            format!("DS records: {}", ds.len()),
            format!("DNSKEY records: {}", dnskey.len()),
            format!("RRSIG records: {}", rrsig.len()),
        ],
    )]
}

fn txt_records(trace: &DnsTrace) -> Vec<String> {
    records(trace, "TXT")
        .into_iter()
        .map(|value| value.trim_matches('"').replace("\" \"", ""))
        .collect()
}

fn spf_observations(domain: &str, trace: &DnsTrace) -> Vec<DnsObservation> {
    let spf = txt_records(trace)
        .into_iter()
        .filter(|value| value.to_ascii_lowercase().starts_with("v=spf1"))
        .collect::<Vec<_>>();
    if spf.is_empty() {
        return vec![observation(
            domain,
            "SPF",
            DnsObservationStatus::Warning,
            "SPF record is absent",
            Vec::new(),
        )];
    }
    if spf.len() > 1 {
        return vec![observation(
            domain,
            "SPF",
            DnsObservationStatus::Warning,
            "Multiple SPF records were observed",
            vec![format!("SPF record count: {}", spf.len())],
        )];
    }
    let value = &spf[0];
    let mechanisms = value.split_ascii_whitespace().skip(1).collect::<Vec<_>>();
    let lookups = mechanisms
        .iter()
        .filter(|item| {
            let item = item
                .trim_start_matches(['+', '-', '~', '?'])
                .to_ascii_lowercase();
            item == "a"
                || item.starts_with("a:")
                || item == "mx"
                || item.starts_with("mx:")
                || item.starts_with("include:")
                || item.starts_with("exists:")
                || item.starts_with("redirect=")
                || item == "ptr"
                || item.starts_with("ptr:")
        })
        .count();
    let permissive = mechanisms
        .iter()
        .any(|item| matches!(item.to_ascii_lowercase().as_str(), "+all" | "all"));
    let malformed = mechanisms.iter().any(|item| malformed_spf_term(item));
    vec![observation(
        domain,
        "SPF",
        if permissive || malformed || lookups > 10 {
            DnsObservationStatus::Warning
        } else {
            DnsObservationStatus::Pass
        },
        if permissive {
            "SPF contains permissive +all"
        } else if lookups > 10 {
            "SPF exceeds the ten-lookup processing limit"
        } else if malformed {
            "SPF contains a malformed mechanism"
        } else {
            "A single structurally valid SPF policy was observed"
        },
        vec![format!("Estimated DNS lookup mechanisms: {lookups}")],
    )]
}

fn malformed_spf_term(term: &str) -> bool {
    let term = term.trim_start_matches(['+', '-', '~', '?']);
    let lower = term.to_ascii_lowercase();
    if matches!(lower.as_str(), "all" | "a" | "mx" | "ptr")
        || lower.starts_with("a:") && lower.len() > 2
        || lower.starts_with("mx:") && lower.len() > 3
        || lower.starts_with("include:") && lower.len() > 8
        || lower.starts_with("exists:") && lower.len() > 7
        || lower.starts_with("redirect=") && lower.len() > 9
        || lower.starts_with("exp=") && lower.len() > 4
        || lower.starts_with("ptr:") && lower.len() > 4
    {
        return false;
    }
    if let Some(value) = lower.strip_prefix("ip4:") {
        return value
            .split('/')
            .next()
            .and_then(|value| value.parse::<std::net::Ipv4Addr>().ok())
            .is_none();
    }
    if let Some(value) = lower.strip_prefix("ip6:") {
        return value
            .split('/')
            .next()
            .and_then(|value| value.parse::<std::net::Ipv6Addr>().ok())
            .is_none();
    }
    true
}

fn dmarc_observations(domain: &str, trace: DnsTrace) -> Vec<DnsObservation> {
    let subject = format!("_dmarc.{domain}");
    let records = txt_records(&trace)
        .into_iter()
        .filter(|value| value.to_ascii_lowercase().starts_with("v=dmarc1"))
        .collect::<Vec<_>>();
    let Some(value) = records.first() else {
        return vec![observation(
            &subject,
            "DMARC",
            DnsObservationStatus::Warning,
            "DMARC policy is absent",
            Vec::new(),
        )];
    };
    if records.len() > 1 {
        return vec![observation(
            &subject,
            "DMARC",
            DnsObservationStatus::Warning,
            "Multiple DMARC policy records were observed",
            vec![format!("DMARC record count: {}", records.len())],
        )];
    }
    let tags = value
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .map(|(name, value)| {
            (
                name.trim().to_ascii_lowercase(),
                value.trim().to_ascii_lowercase(),
            )
        })
        .collect::<HashMap<_, _>>();
    let policy = tags.get("p").map(String::as_str);
    let invalid_pct = tags
        .get("pct")
        .is_some_and(|value| value.parse::<u8>().map_or(true, |value| value > 100));
    let malformed = !matches!(policy, Some("none" | "quarantine" | "reject"));
    let missing_alignment = !tags.contains_key("adkim") || !tags.contains_key("aspf");
    let invalid_alignment = tags
        .get("adkim")
        .into_iter()
        .chain(tags.get("aspf"))
        .any(|value| !matches!(value.as_str(), "r" | "s"));
    vec![observation(
        &subject,
        "DMARC",
        if malformed
            || invalid_pct
            || invalid_alignment
            || policy == Some("none")
            || missing_alignment
        {
            DnsObservationStatus::Warning
        } else {
            DnsObservationStatus::Pass
        },
        if malformed {
            "DMARC record is malformed or lacks a valid policy"
        } else if invalid_pct {
            "DMARC pct value is invalid"
        } else if invalid_alignment {
            "DMARC alignment policy is invalid"
        } else if policy == Some("none") {
            "DMARC uses monitoring-only p=none"
        } else if missing_alignment {
            "DMARC does not explicitly specify both alignment policies"
        } else {
            "DMARC enforcement and alignment policy are present"
        },
        vec!["DMARC value redacted; structural tags only were evaluated".to_owned()],
    )]
}

fn dkim_observations(subject: &str, selector: &str, trace: DnsTrace) -> Vec<DnsObservation> {
    let values = txt_records(&trace);
    let value = values
        .iter()
        .find(|value| value.to_ascii_lowercase().contains("v=dkim1"));
    let (status, summary) = match value {
        None => (
            DnsObservationStatus::Warning,
            "No DKIM key was found for the explicitly supplied selector",
        ),
        Some(value) => {
            let tags = value
                .split(';')
                .filter_map(|part| part.trim().split_once('='))
                .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim()))
                .collect::<HashMap<_, _>>();
            let valid_kind = tags
                .get("k")
                .is_none_or(|kind| matches!(kind.to_ascii_lowercase().as_str(), "rsa" | "ed25519"));
            let key = tags.get("p").copied().unwrap_or_default();
            let decoded = base64::engine::general_purpose::STANDARD.decode(key.as_bytes());
            let valid_key = decoded.as_ref().is_ok_and(|key| {
                if tags
                    .get("k")
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("ed25519"))
                {
                    key.len() == 32
                } else {
                    key.len() >= 64
                }
            });
            if !valid_key || !valid_kind {
                (
                    DnsObservationStatus::Warning,
                    "DKIM key syntax is invalid or revoked",
                )
            } else {
                (
                    DnsObservationStatus::Pass,
                    "DKIM key syntax is valid for the supplied selector",
                )
            }
        }
    };
    vec![observation(
        subject,
        "DKIM",
        status,
        summary,
        vec![format!("Selector: {selector}; key material redacted")],
    )]
}

async fn authority_observations(
    domain: &str,
    trace: &DnsTrace,
    cancel: &CancellationToken,
) -> Vec<DnsObservation> {
    let mut delegated = records(trace, "NS")
        .into_iter()
        .map(|value| value.trim_end_matches('.').to_ascii_lowercase())
        .collect::<Vec<_>>();
    delegated.sort();
    delegated.dedup();
    let Some(server_name) = delegated.first() else {
        return vec![observation(
            domain,
            "Authoritative DNS",
            DnsObservationStatus::Warning,
            "No delegated authoritative name server was found",
            Vec::new(),
        )];
    };
    let mut server_trace = DnsTrace::default();
    let _ = resolve_host(server_name, &mut server_trace).await;
    let Some(ip) = server_trace
        .addresses
        .iter()
        .copied()
        .find(|address| non_public_reason(*address).is_none())
    else {
        return vec![observation(
            domain,
            "Authoritative DNS",
            DnsObservationStatus::Warning,
            "Delegated authoritative name servers have no public destination",
            delegated,
        )];
    };
    if cancel.is_cancelled() {
        return Vec::new();
    }
    let probes = async {
        tokio::join!(
            direct_dns(ip, domain, RecordType::NS, false),
            direct_dns(ip, domain, RecordType::SOA, false),
            direct_dns(ip, domain, RecordType::SOA, true),
        )
    };
    let (ns_udp, soa_udp, soa_tcp) = tokio::select! {
        _ = cancel.cancelled() => return Vec::new(),
        probes = probes => probes,
    };
    let authoritative_ns = ns_udp
        .as_ref()
        .ok()
        .map(|message| {
            let mut values = message
                .answers
                .iter()
                .filter(|record| record.record_type() == RecordType::NS)
                .map(|record| {
                    record
                        .data
                        .to_string()
                        .trim_end_matches('.')
                        .to_ascii_lowercase()
                })
                .collect::<Vec<_>>();
            values.sort();
            values.dedup();
            values
        })
        .unwrap_or_default();
    let consistent = !authoritative_ns.is_empty() && authoritative_ns == delegated;
    let udp_authoritative_soa = soa_udp.as_ref().is_ok_and(|message| {
        message.metadata.authoritative
            && message
                .answers
                .iter()
                .any(|record| record.record_type() == RecordType::SOA)
    });
    let tcp_authoritative_soa = soa_tcp.as_ref().is_ok_and(|message| {
        message.metadata.authoritative
            && message
                .answers
                .iter()
                .any(|record| record.record_type() == RecordType::SOA)
    });
    vec![
        observation(
            domain,
            "Delegation consistency",
            if consistent {
                DnsObservationStatus::Pass
            } else {
                DnsObservationStatus::Warning
            },
            if consistent {
                "Delegated and authoritative NS sets are consistent"
            } else {
                "Delegated and authoritative NS sets differ or could not be compared"
            },
            vec![
                format!("Delegated NS count: {}", delegated.len()),
                format!("Authoritative NS count: {}", authoritative_ns.len()),
            ],
        ),
        observation(
            domain,
            "Authoritative DNS reachability",
            if udp_authoritative_soa && tcp_authoritative_soa {
                DnsObservationStatus::Pass
            } else {
                DnsObservationStatus::Warning
            },
            if udp_authoritative_soa && tcp_authoritative_soa {
                "An authoritative SOA answer was reachable over UDP and TCP"
            } else {
                "An authoritative SOA answer was not confirmed over both UDP and TCP"
            },
            vec![
                format!("Server checked: {server_name} ({ip})"),
                format!("UDP authoritative SOA: {udp_authoritative_soa}"),
                format!("TCP authoritative SOA: {tcp_authoritative_soa}"),
            ],
        ),
    ]
}

async fn direct_dns(
    ip: IpAddr,
    domain: &str,
    record_type: RecordType,
    tcp: bool,
) -> Result<Message, String> {
    let name = Name::from_ascii(domain).map_err(|error| error.to_string())?;
    let mut query = Message::query();
    query.metadata.recursion_desired = false;
    query.add_query(Query::query(name, record_type));
    let request = query.to_vec().map_err(|error| error.to_string())?;
    let remote = SocketAddr::new(ip, 53);
    let response = if tcp {
        let mut stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(remote))
            .await
            .map_err(|_| "TCP DNS connection timed out".to_owned())?
            .map_err(|error| error.to_string())?;
        stream
            .write_all(&(request.len() as u16).to_be_bytes())
            .await
            .map_err(|error| error.to_string())?;
        stream
            .write_all(&request)
            .await
            .map_err(|error| error.to_string())?;
        let length = tokio::time::timeout(Duration::from_secs(2), stream.read_u16())
            .await
            .map_err(|_| "TCP DNS response timed out".to_owned())?
            .map_err(|error| error.to_string())? as usize;
        if length > DNS_RESPONSE_LIMIT {
            return Err("TCP DNS response exceeded 16 KiB".to_owned());
        }
        let mut response = vec![0u8; length];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|error| error.to_string())?;
        response
    } else {
        let bind = if ip.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|error| error.to_string())?;
        socket
            .send_to(&request, remote)
            .await
            .map_err(|error| error.to_string())?;
        let mut response = vec![0u8; DNS_RESPONSE_LIMIT];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut response))
                .await
                .map_err(|_| "UDP DNS response timed out".to_owned())?
                .map_err(|error| error.to_string())?;
        if source != remote {
            return Err("UDP DNS response came from an unexpected source".to_owned());
        }
        response.truncate(length);
        response
    };
    let response = Message::from_vec(&response).map_err(|error| error.to_string())?;
    if response.metadata.id != query.metadata.id
        || !matches!(
            response.metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        )
    {
        return Err("DNS response did not match the request".to_owned());
    }
    Ok(response)
}

fn observation(
    subject: &str,
    check: &str,
    status: DnsObservationStatus,
    summary: &str,
    evidence: Vec<String>,
) -> DnsObservation {
    DnsObservation {
        subject: subject.to_owned(),
        check: check.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }
}
