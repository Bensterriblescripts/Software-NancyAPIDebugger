use crate::diagnostics::{
    DiagnosticProgress, DiagnosticTrace, FingerprintStatus, FingerprintTrace,
};
use futures_util::stream::{FuturesUnordered, StreamExt};
use roxmltree::{Document, Node};
use std::collections::BTreeMap;
use std::env;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::mpsc::Sender;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use url::Url;

const SCRIPT_EXPRESSION: &str = "(default or safe) and not (auth or broadcast or brute or dos or exploit or external or fuzzer or intrusive or malware or vuln)";
const HARD_DEADLINE: Duration = Duration::from_secs(120);
const UBUNTU_HINT: &str =
    "Install Nmap with 'sudo apt install nmap' and run Nancy Web Debugger as root.";

#[derive(Clone)]
struct FingerprintTarget {
    origin: String,
    host: String,
    port: u16,
    ip: IpAddr,
    trace_positions: Vec<usize>,
}

struct TargetBuilder {
    host: String,
    port: u16,
    ip: Option<IpAddr>,
    trace_positions: Vec<usize>,
}

#[derive(Clone)]
struct ScanResult {
    status: FingerprintStatus,
    identity: Option<String>,
    confidence: Option<u8>,
    detection_source: Option<String>,
    evidence: Vec<String>,
}

enum ProcessResult {
    Completed { success: bool, output: Vec<u8> },
    TimedOut,
    Cancelled,
    Unavailable(String),
}

pub(super) fn prepare_trace(trace: &mut DiagnosticTrace) {
    let status = if trace.request.fingerprint_server {
        FingerprintStatus::Pending
    } else {
        FingerprintStatus::Disabled
    };
    trace.fingerprint = baseline(trace, status);
}

pub(super) async fn run(
    traces: &mut [DiagnosticTrace],
    cancel: CancellationToken,
    progress: &Sender<DiagnosticProgress>,
) {
    if !traces.iter().any(|trace| trace.request.fingerprint_server) {
        return;
    }
    if cancel.is_cancelled() {
        update_pending(
            traces,
            FingerprintStatus::Cancelled,
            "Fingerprinting was cancelled before scanning started",
            progress,
        );
        return;
    }
    if !is_root() {
        update_pending(
            traces,
            FingerprintStatus::Unavailable,
            &format!("SYN scanning requires root privileges. {UBUNTU_HINT}"),
            progress,
        );
        return;
    }
    let Some(nmap_path) = find_nmap() else {
        update_pending(
            traces,
            FingerprintStatus::Unavailable,
            &format!("Nmap was not found. {UBUNTU_HINT}"),
            progress,
        );
        return;
    };

    let mut builders = BTreeMap::<String, TargetBuilder>::new();
    for (position, trace) in traces.iter().enumerate() {
        if !trace.request.fingerprint_server {
            continue;
        }
        let Ok(url) = Url::parse(&trace.url.normalized) else {
            continue;
        };
        let origin = url.origin().ascii_serialization();
        let selected_ip = trace
            .connections
            .iter()
            .find(|attempt| attempt.selected)
            .map(|attempt| attempt.remote.ip());
        let builder = builders.entry(origin).or_insert_with(|| TargetBuilder {
            host: trace.url.host.clone(),
            port: trace.url.port,
            ip: selected_ip,
            trace_positions: Vec::new(),
        });
        if builder.ip.is_none() {
            builder.ip = selected_ip;
        }
        builder.trace_positions.push(position);
    }

    let mut assigned = vec![false; traces.len()];
    let mut targets = Vec::new();
    for (origin, builder) in builders {
        for &position in &builder.trace_positions {
            assigned[position] = true;
        }
        if let Some(ip) = builder.ip {
            targets.push(FingerprintTarget {
                origin,
                host: builder.host,
                port: builder.port,
                ip,
                trace_positions: builder.trace_positions,
            });
        } else {
            for position in builder.trace_positions {
                set_terminal_without_scan(
                    &mut traces[position],
                    FingerprintStatus::Unavailable,
                    "No remote IP was selected by the connection diagnostics",
                );
                publish(&traces[position], progress);
            }
        }
    }
    for (position, trace) in traces.iter_mut().enumerate() {
        if trace.request.fingerprint_server && !assigned[position] {
            set_terminal_without_scan(
                trace,
                FingerprintStatus::Unavailable,
                "No normalized HTTP origin was available to scan",
            );
            publish(trace, progress);
        }
    }

    let mut scans = FuturesUnordered::new();
    for target in targets {
        for &position in &target.trace_positions {
            traces[position].fingerprint.status = FingerprintStatus::Running;
            traces[position]
                .fingerprint
                .evidence
                .push("Nmap scan started".to_owned());
            publish(&traces[position], progress);
        }
        let path = nmap_path.clone();
        let scan_cancel = cancel.clone();
        scans.push(async move {
            let result = scan_target(&path, &target, &scan_cancel).await;
            (target, result)
        });
    }

    while let Some((target, result)) = scans.next().await {
        for &position in &target.trace_positions {
            apply_result(&mut traces[position], &target, &result);
            publish(&traces[position], progress);
        }
    }
}

fn baseline(trace: &DiagnosticTrace, status: FingerprintStatus) -> FingerprintTrace {
    let response_server = response_server_header(trace);
    let mut evidence = Vec::new();
    if let Ok(url) = Url::parse(&trace.url.normalized) {
        let origin = url.origin().ascii_serialization();
        if let Some(ip) = trace
            .connections
            .iter()
            .find(|attempt| attempt.selected)
            .map(|attempt| attempt.remote.ip())
        {
            evidence.push(format!("Target: {origin} via {ip}"));
        } else {
            evidence.push(format!("Target origin: {origin}"));
        }
    }
    if let Some(server) = &response_server {
        evidence.push(format!("Original response Server header: {server}"));
    }
    FingerprintTrace {
        status,
        web_server: response_server
            .clone()
            .unwrap_or_else(|| "Unknown".to_owned()),
        confidence: if response_server.is_some() {
            "Unverified response header".to_owned()
        } else {
            "None".to_owned()
        },
        evidence,
    }
}

fn update_pending(
    traces: &mut [DiagnosticTrace],
    status: FingerprintStatus,
    detail: &str,
    progress: &Sender<DiagnosticProgress>,
) {
    for trace in traces {
        if trace.request.fingerprint_server
            && matches!(
                trace.fingerprint.status,
                FingerprintStatus::Pending | FingerprintStatus::Running
            )
        {
            set_terminal_without_scan(trace, status, detail);
            publish(trace, progress);
        }
    }
}

fn set_terminal_without_scan(trace: &mut DiagnosticTrace, status: FingerprintStatus, detail: &str) {
    trace.fingerprint.status = status;
    trace.fingerprint.evidence.push(detail.to_owned());
}

fn publish(trace: &DiagnosticTrace, progress: &Sender<DiagnosticProgress>) {
    let _ = progress.send(DiagnosticProgress::FingerprintUpdated(trace.clone()));
}

async fn scan_target(
    nmap_path: &PathBuf,
    target: &FingerprintTarget,
    cancel: &CancellationToken,
) -> ScanResult {
    match run_nmap(nmap_path, target, cancel).await {
        ProcessResult::Completed { success, output } => {
            if !success {
                return scan_failure(FingerprintStatus::Unavailable, "Nmap exited unsuccessfully");
            }
            parse_nmap_xml(&output, target.port).unwrap_or_else(|error| {
                scan_failure(
                    FingerprintStatus::Unavailable,
                    &format!("Nmap returned invalid XML: {error}"),
                )
            })
        }
        ProcessResult::TimedOut => scan_failure(
            FingerprintStatus::TimedOut,
            "Nmap exceeded the two-minute process deadline and was terminated",
        ),
        ProcessResult::Cancelled => scan_failure(
            FingerprintStatus::Cancelled,
            "Nmap was terminated because the diagnostic session was cancelled",
        ),
        ProcessResult::Unavailable(error) => scan_failure(
            FingerprintStatus::Unavailable,
            &format!("Unable to start Nmap: {error}. {UBUNTU_HINT}"),
        ),
    }
}

async fn run_nmap(
    nmap_path: &PathBuf,
    target: &FingerprintTarget,
    cancel: &CancellationToken,
) -> ProcessResult {
    let mut command = Command::new(nmap_path);
    command
        .args([
            "-Pn",
            "-sS",
            "-p-",
            "-sV",
            "--version-all",
            "-O",
            "--osscan-guess",
            "--traceroute",
            "-T4",
            "--max-retries",
            "1",
            "--script-timeout",
            "20s",
            "--script",
            SCRIPT_EXPRESSION,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if target.ip.is_ipv6() {
        command.arg("-6");
    }
    if safe_script_hostname(&target.host) && target.host.parse::<IpAddr>().is_err() {
        command.arg("--script-args").arg(format!(
            "http.host={},tls.servername={}",
            target.host, target.host
        ));
    }
    command.args(["-oX", "-"]).arg(target.ip.to_string());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return ProcessResult::Unavailable(error.to_string()),
    };
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return ProcessResult::Unavailable("Nmap stdout was unavailable".to_owned());
    };
    let output_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.map(|_| output)
    });
    let wait = tokio::select! {
        _ = cancel.cancelled() => None,
        result = tokio::time::timeout(HARD_DEADLINE, child.wait()) => Some(result),
    };
    match wait {
        None => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = output_task.await;
            ProcessResult::Cancelled
        }
        Some(Err(_)) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = output_task.await;
            ProcessResult::TimedOut
        }
        Some(Ok(Err(error))) => {
            let _ = output_task.await;
            ProcessResult::Unavailable(error.to_string())
        }
        Some(Ok(Ok(status))) => match output_task.await {
            Ok(Ok(output)) => ProcessResult::Completed {
                success: status.success(),
                output,
            },
            Ok(Err(error)) => ProcessResult::Unavailable(error.to_string()),
            Err(error) => ProcessResult::Unavailable(error.to_string()),
        },
    }
}

fn parse_nmap_xml(output: &[u8], web_port: u16) -> Result<ScanResult, String> {
    let xml = std::str::from_utf8(output).map_err(|error| error.to_string())?;
    let document = Document::parse(xml).map_err(|error| error.to_string())?;
    let mut identity = None;
    let mut confidence = None;
    let mut detection_source = None;
    let mut web_service = None;
    let mut server_header = None;
    let mut http_scripts = Vec::new();
    let mut other_services = Vec::new();

    for port in document
        .descendants()
        .filter(|node| node.has_tag_name("port") && node.attribute("protocol") == Some("tcp"))
    {
        let Some(port_number) = port
            .attribute("portid")
            .and_then(|value| value.parse::<u16>().ok())
        else {
            continue;
        };
        if port
            .children()
            .find(|node| node.has_tag_name("state"))
            .and_then(|node| node.attribute("state"))
            != Some("open")
        {
            continue;
        }
        let service = port.children().find(|node| node.has_tag_name("service"));
        if port_number == web_port {
            if let Some(service) = service {
                let product = service.attribute("product").unwrap_or("").trim();
                let service_identity = product_identity(service);
                let service_name = service.attribute("name").unwrap_or("unknown");
                web_service = Some(format!(
                    "Nmap service on tcp/{web_port}: {service_name}{}",
                    service_identity
                        .as_ref()
                        .map(|value| format!(" — {value}"))
                        .unwrap_or_default()
                ));
                if !product.is_empty() && service.attribute("method") == Some("probed") {
                    identity = service_identity;
                    confidence = service
                        .attribute("conf")
                        .and_then(|value| value.parse::<u8>().ok());
                    detection_source = Some(format!(
                        "Nmap service probe (method: probed, confidence: {})",
                        confidence
                            .map(|value| format!("{value}/10"))
                            .unwrap_or_else(|| "not reported".to_owned())
                    ));
                }
            }
            for script in port.children().filter(|node| node.has_tag_name("script")) {
                let id = script.attribute("id").unwrap_or("unknown");
                let output = concise(script.attribute("output").unwrap_or(""));
                if id == "http-server-header" && !output.is_empty() {
                    server_header = Some(server_identity_from_script(&output));
                }
                if id.starts_with("http-") && !output.is_empty() && http_scripts.len() < 8 {
                    http_scripts.push(format!("HTTP script {id}: {output}"));
                }
            }
        } else if let Some(service) = service {
            let name = service.attribute("name").unwrap_or("");
            if name.to_ascii_lowercase().contains("http") && other_services.len() < 12 {
                let detected = product_identity(service)
                    .map(|value| format!(" — {value}"))
                    .unwrap_or_default();
                other_services.push(format!(
                    "Other HTTP(S) service: tcp/{port_number} {name}{detected}"
                ));
            }
        }
    }

    if identity.is_none()
        && let Some(header) = server_header.filter(|value| !value.is_empty())
    {
        identity = Some(header);
        detection_source = Some("Nmap http-server-header script".to_owned());
    }

    let best_os = document
        .descendants()
        .filter(|node| node.has_tag_name("osmatch"))
        .filter_map(|node| {
            let accuracy = node.attribute("accuracy")?.parse::<u8>().ok()?;
            let name = node.attribute("name")?.to_owned();
            Some((accuracy, name))
        })
        .max_by_key(|(accuracy, _)| *accuracy)
        .map(|(accuracy, name)| format!("Best OS match: {name} ({accuracy}% accuracy)"));

    let status = if identity.is_some() {
        FingerprintStatus::Detected
    } else {
        FingerprintStatus::Unknown
    };
    let mut evidence = Vec::new();
    if let Some(source) = &detection_source {
        evidence.push(format!("Detection source: {source}"));
    } else {
        evidence.push("Detection source: no Nmap web-server identity".to_owned());
    }
    if let Some(service) = web_service {
        evidence.push(service);
    }
    evidence.extend(http_scripts);
    if let Some(os) = best_os {
        evidence.push(os);
    }
    evidence.extend(other_services);
    Ok(ScanResult {
        status,
        identity,
        confidence,
        detection_source,
        evidence,
    })
}

fn product_identity(service: Node<'_, '_>) -> Option<String> {
    let product = service.attribute("product")?.trim();
    if product.is_empty() {
        return None;
    }
    let mut identity = product.to_owned();
    if let Some(version) = service.attribute("version").map(str::trim)
        && !version.is_empty()
    {
        identity.push(' ');
        identity.push_str(version);
    }
    if let Some(extra) = service.attribute("extrainfo").map(str::trim)
        && !extra.is_empty()
    {
        identity.push_str(" (");
        identity.push_str(extra);
        identity.push(')');
    }
    Some(identity)
}

fn apply_result(trace: &mut DiagnosticTrace, target: &FingerprintTarget, result: &ScanResult) {
    let response_server = response_server_header(trace);
    trace.fingerprint.status = result.status;
    trace.fingerprint.web_server = result
        .identity
        .clone()
        .or_else(|| response_server.clone())
        .unwrap_or_else(|| "Unknown".to_owned());
    trace.fingerprint.confidence = if result.identity.is_some() {
        result
            .confidence
            .map(|value| format!("{value}/10 (Nmap)"))
            .unwrap_or_else(|| "Not reported by Nmap".to_owned())
    } else if response_server.is_some() {
        "Unverified response header".to_owned()
    } else {
        "None".to_owned()
    };
    trace.fingerprint.evidence = vec![format!("Target: {} via {}", target.origin, target.ip)];
    trace.fingerprint.evidence.extend(result.evidence.clone());
    if let Some(server) = &response_server {
        trace
            .fingerprint
            .evidence
            .push(format!("Original response Server header: {server}"));
    }
    if let (Some(nmap), Some(header)) = (&result.identity, &response_server)
        && !identities_agree(nmap, header)
    {
        trace.fingerprint.evidence.push(format!(
            "Identity conflict: Nmap reported '{nmap}' while the response header reported '{header}'"
        ));
    }
    if result.detection_source.is_none() && response_server.is_some() {
        trace
            .fingerprint
            .evidence
            .push("Displayed identity source: original response Server header".to_owned());
    }
}

fn scan_failure(status: FingerprintStatus, detail: &str) -> ScanResult {
    ScanResult {
        status,
        identity: None,
        confidence: None,
        detection_source: None,
        evidence: vec![detail.to_owned()],
    }
}

fn response_server_header(trace: &DiagnosticTrace) -> Option<String> {
    trace
        .http
        .response_headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("server"))
        .map(|header| header.display_value().into_owned())
        .filter(|value| !value.trim().is_empty())
}

fn server_identity_from_script(output: &str) -> String {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| {
            line.split_once(':')
                .filter(|(prefix, _)| prefix.contains("/tcp"))
                .map(|(_, value)| value.trim())
                .unwrap_or(line)
                .to_owned()
        })
        .unwrap_or_default()
}

fn concise(value: &str) -> String {
    let flattened = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = flattened.chars();
    let shortened = chars.by_ref().take(300).collect::<String>();
    if chars.next().is_some() {
        format!("{shortened}…")
    } else {
        shortened
    }
}

fn identities_agree(left: &str, right: &str) -> bool {
    let left = left.to_ascii_lowercase();
    let right = right.to_ascii_lowercase();
    left.contains(&right) || right.contains(&left)
}

fn safe_script_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("Uid:")?
                    .split_whitespace()
                    .nth(1)?
                    .parse::<u32>()
                    .ok()
            })
        })
        == Some(0)
}

fn find_nmap() -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).find_map(|directory| {
        if directory.as_os_str().is_empty() {
            return None;
        }
        let candidate = directory.join("nmap");
        let metadata = candidate.metadata().ok()?;
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            Some(candidate)
        } else {
            None
        }
    })
}
