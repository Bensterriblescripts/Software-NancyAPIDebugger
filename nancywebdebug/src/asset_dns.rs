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
) -> (Vec<DiscoveredAsset>, Vec<String>, DiscoveryCoverage) {
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
        let coverage = DiscoveryCoverage {
            status: DiscoveryCoverageStatus::Unavailable,
            detail: "Target has no valid registrable domain boundary".to_owned(),
            ..Default::default()
        };
        publish_coverage(progress, &coverage);
        return (Vec::new(), vec![coverage.summary()], coverage);
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
                                let names = eligible_ct_names(&entries, domain);
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
            let coverage = DiscoveryCoverage {
                status: if cancel.is_cancelled() {
                    DiscoveryCoverageStatus::Cancelled
                } else {
                    DiscoveryCoverageStatus::Unavailable
                },
                detail: error,
                ..Default::default()
            };
            publish_coverage(progress, &coverage);
            return (Vec::new(), vec![coverage.summary()], coverage);
        }
    };
    resolve_names(names, request, cancel, limiter, progress).await
}

async fn resolve_names(
    mut names: Vec<String>,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: Arc<ConnectionRateLimiter>,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> (Vec<DiscoveredAsset>, Vec<String>, DiscoveryCoverage) {
    let mut coverage = DiscoveryCoverage {
        status: DiscoveryCoverageStatus::Running,
        eligible: Some(names.len()),
        selected: names.len().min(request.ct_hostname_limit),
        omitted: names.len().saturating_sub(request.ct_hostname_limit),
        completed: 0,
        detail: "CT inventory only; not an exhaustive domain inventory".to_owned(),
    };
    names.truncate(request.ct_hostname_limit);
    publish_coverage(progress, &coverage);
    let total = names.len();
    let mut pending = FuturesUnordered::new();
    let mut next = 0usize;
    let mut assets = Vec::with_capacity(total);
    while next < names.len() || !pending.is_empty() {
        while next < names.len() && pending.len() < request.concurrency && !cancel.is_cancelled() {
            let name = names[next].clone();
            next += 1;
            let limiter = limiter.clone();
            pending.push(async move {
                posture::resolve_asset(name, request, cancel, limiter.as_ref()).await
            });
        }
        let Some((asset, complete)) = pending.next().await else {
            break;
        };
        if let Some(progress) = progress {
            let _ = progress.send(ExposureScanProgress::AssetDiscovered {
                completed: coverage.completed + usize::from(complete),
                total,
                asset: asset.clone(),
            });
        }
        assets.push(asset);
        if complete {
            coverage.completed += 1;
        }
        publish_coverage(progress, &coverage);
        send_phase_progress(
            progress,
            ExposureScanPhase::AssetDiscovery,
            ExposureScanPhaseState::Running,
            coverage.completed as f32 / total.max(1) as f32,
            format!("Checked {} / {total} CT hostnames", coverage.completed),
        );
    }
    assets.sort_by(|left, right| left.hostname.cmp(&right.hostname));
    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::AssetDiscovery,
            ExposureScanPhaseState::Complete,
            1.0,
            format!(
                "{} inventory-only CT assets; {}",
                assets.len(),
                if coverage.omitted > 0 {
                    "limited coverage"
                } else {
                    "selected discovery complete"
                }
            ),
        );
    }
    coverage.status = if cancel.is_cancelled() {
        DiscoveryCoverageStatus::Cancelled
    } else if coverage.omitted > 0 {
        DiscoveryCoverageStatus::Limited
    } else {
        DiscoveryCoverageStatus::Complete
    };
    let warnings = if coverage.omitted > 0 || cancel.is_cancelled() {
        vec![coverage.summary()]
    } else {
        Vec::new()
    };
    publish_coverage(progress, &coverage);
    (assets, warnings, coverage)
}

fn eligible_ct_names(entries: &[CtEntry], domain: &str) -> Vec<String> {
    let mut names = entries
        .iter()
        .flat_map(|entry| entry.name_value.lines())
        .filter_map(normalize_ct_name)
        .filter(|name| within_domain(name, domain))
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn publish_coverage(progress: &Option<Sender<ExposureScanProgress>>, coverage: &DiscoveryCoverage) {
    if let Some(progress) = progress {
        let _ = progress.send(ExposureScanProgress::DiscoveryCoverageUpdated(
            coverage.clone(),
        ));
    }
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
