use super::*;

use serde::Deserialize;
use std::net::SocketAddr;

const CT_RESPONSE_LIMIT: usize = 4 * 1024 * 1024;

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
    let names = match {
        let (domain, request, cancel, limiter): (
            &str,
            &ExposureScanRequest,
            &CancellationToken,
            &ConnectionRateLimiter,
        ) = (&domain, request, cancel, limiter.as_ref());
        async move {
            let mut dns = DnsTrace::default();
            tokio::select! {
                _ = cancel.cancelled() => return Err("cancelled".to_owned()),
                result = resolve_host("crt.sh", &mut dns) => {
                    result.map_err(|error| format!("crt.sh DNS lookup failed: {error}"))?;
                }
            }
            let mut bounded_request = request.clone();
            bounded_request.connection_timeout = bounded_request
                .connection_timeout
                .min(Duration::from_secs(5));
            bounded_request.probe_timeout =
                bounded_request.probe_timeout.min(Duration::from_secs(15));
            let path = format!("/?q=%25.{domain}&output=json");
            let mut errors = Vec::new();
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
                let error = match single_http_request(
                    context,
                    "https",
                    "GET",
                    &path,
                    &[("Accept", "application/json")],
                    CT_RESPONSE_LIMIT,
                    None,
                )
                .await
                {
                    Ok(response) if response.status == 200 && !response.body_truncated => {
                        match serde_json::from_slice::<Vec<CtEntry>>(&response.body) {
                            Ok(entries) => {
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
                            Err(error) => format!("returned invalid JSON: {error}"),
                        }
                    }
                    Ok(response) if response.body_truncated => {
                        "response exceeded the 4 MiB limit".to_owned()
                    }
                    Ok(response) => format!("returned HTTP {}", response.status),
                    Err(error) => error,
                };
                let family = if ip.is_ipv4() { "IPv4" } else { "IPv6" };
                let remote = SocketAddr::new(ip, 443);
                errors.push(format!("crt.sh {remote} ({family}): {error}"));
            }
            if errors.is_empty() {
                Err(
            "crt.sh has no eligible public IPv4 or IPv6 address; no HTTPS connection attempted"
                .to_owned(),
        )
            } else {
                Err(format!(
                    "all crt.sh HTTPS attempts failed: {}",
                    errors.join("; ")
                ))
            }
        }
    }
    .await
    {
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
            pending.push({
                let (hostname, cancel, limiter): (
                    String,
                    &CancellationToken,
                    Arc<ConnectionRateLimiter>,
                ) = (name, cancel, limiter.clone());
                async move {
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
                        DiscoveredAssetState::Public => {
                            "One or more public DNS destinations resolved"
                        }
                        DiscoveredAssetState::NonPublic => {
                            "DNS resolved only non-public destinations"
                        }
                        DiscoveredAssetState::DanglingCname => {
                            "CNAME chain has no usable destination; exploitability was not tested"
                        }
                        DiscoveredAssetState::Unresolved => {
                            "No usable A or AAAA result was obtained"
                        }
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
            });
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

#[path = "dns_posture/mod.rs"]
mod posture;
pub(super) use posture::assess_dns;
