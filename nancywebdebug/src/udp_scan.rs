use super::*;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

const RESPONSE_LIMIT: usize = 4096;
const STUN_TRANSACTION_ID: &[u8; 12] = b"NANCYSTUN001";

pub(super) async fn run(
    addresses: &[IpAddr],
    hostname: &str,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: Arc<ConnectionRateLimiter>,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> (Vec<UdpEndpointScan>, Vec<ExposureFinding>) {
    let ports = request
        .udp_ports
        .ports(TransportProtocol::Udp)
        .unwrap_or_default();
    let total = addresses.len().saturating_mul(ports.len());
    send_phase_progress(
        progress,
        ExposureScanPhase::UdpScanning,
        ExposureScanPhaseState::Running,
        0.0,
        format!("0 / {total} UDP endpoints"),
    );
    let mut pending = FuturesUnordered::new();
    let mut next = 0usize;
    let jobs = addresses
        .iter()
        .flat_map(|address| ports.iter().map(move |port| (*address, *port)))
        .collect::<Vec<_>>();
    let mut results = Vec::with_capacity(total);
    let mut findings = Vec::new();
    while next < jobs.len() || !pending.is_empty() {
        while next < jobs.len() && pending.len() < request.concurrency && !cancel.is_cancelled() {
            let (ip, port) = jobs[next];
            next += 1;
            pending.push(scan_one(
                ip,
                port,
                hostname,
                request.probe_timeout,
                cancel,
                limiter.as_ref(),
            ));
        }
        let Some((result, finding)) = pending.next().await else {
            break;
        };
        if let Some(progress) = progress {
            let _ = progress.send(ExposureScanProgress::UdpEndpointCompleted {
                completed: results.len() + 1,
                total,
                endpoint: result.clone(),
            });
        }
        findings.extend(finding);
        results.push(result);
        send_phase_progress(
            progress,
            ExposureScanPhase::UdpScanning,
            ExposureScanPhaseState::Running,
            results.len() as f32 / total.max(1) as f32,
            format!("{} / {total} UDP endpoints", results.len()),
        );
        if cancel.is_cancelled() {
            break;
        }
    }
    results.sort_by(|left, right| left.ip.cmp(&right.ip).then(left.port.cmp(&right.port)));
    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::UdpScanning,
            ExposureScanPhaseState::Complete,
            1.0,
            format!("{} / {total} UDP endpoints", results.len()),
        );
    }
    (results, findings)
}

async fn scan_one(
    ip: IpAddr,
    port: u16,
    hostname: &str,
    timeout: Duration,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
) -> (UdpEndpointScan, Option<ExposureFinding>) {
    let started = Instant::now();
    let service = udp_service(port);
    let mut result = UdpEndpointScan {
        ip,
        port,
        transport: TransportProtocol::Udp,
        state: UdpEndpointState::OpenOrFiltered,
        service,
        elapsed_ms: 0.0,
        evidence: Vec::new(),
        error: None,
    };
    let Some(payload) = probe_payload(port, hostname, ip) else {
        result.evidence.push(
            "No datagram sent because this protocol would require a community, content request, allocation, media request, multicast, broadcast, or application message"
                .to_owned(),
        );
        return (result, None);
    };
    if limiter.wait(cancel).await.is_err() {
        result.state = UdpEndpointState::Cancelled;
        result.elapsed_ms = elapsed_ms(started);
        return (result, None);
    }
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) => {
            result.state = UdpEndpointState::Error;
            result.error = Some(error.to_string());
            result.elapsed_ms = elapsed_ms(started);
            return (result, None);
        }
    };
    let remote = SocketAddr::new(ip, port);
    let operation = async {
        socket.send_to(&payload, remote).await?;
        let deadline = tokio::time::Instant::now() + timeout;
        let mut response = [0u8; RESPONSE_LIMIT];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok::<_, std::io::Error>(None);
            }
            match tokio::time::timeout(remaining, socket.recv_from(&mut response)).await {
                Ok(Ok((length, source))) if source == remote => {
                    return Ok(Some(response[..length].to_vec()));
                }
                Ok(Ok(_)) => continue,
                Ok(Err(error)) => return Err(error),
                Err(_) => return Ok(None),
            }
        }
    };
    let outcome = tokio::select! {
        _ = cancel.cancelled() => {
            result.state = UdpEndpointState::Cancelled;
            None
        }
        outcome = operation => Some(outcome),
    };
    let mut finding = None;
    if let Some(outcome) = outcome {
        match outcome {
            Ok(Some(response)) => {
                result.state = UdpEndpointState::Responsive;
                result
                    .evidence
                    .push(response_evidence(port, &response, hostname));
                if port == 3478 {
                    finding = stun_finding(ip, port, &response, result.evidence.clone());
                } else if port == 5353 && mdns_response(&response, hostname).is_ok() {
                    finding = Some(public_stream_finding(
                        ip,
                        port,
                        TransportProtocol::Udp,
                        "mDNS",
                        "target-specific unicast mDNS question",
                        result.evidence.clone(),
                    ));
                }
            }
            Ok(None) => {
                result.state = UdpEndpointState::OpenOrFiltered;
                result.evidence.push(
                    "The bounded discovery handshake timed out; UDP openness is not confirmed"
                        .to_owned(),
                );
            }
            Err(error) if connection_refused(&error) => {
                result.state = UdpEndpointState::Closed;
                result.error = Some(error.to_string());
            }
            Err(error) => {
                result.state = UdpEndpointState::Error;
                result.error = Some(error.to_string());
            }
        }
    }
    result.elapsed_ms = elapsed_ms(started);
    (result, finding)
}

fn connection_refused(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(61 | 111 | 10054 | 10061))
        || error.to_string().to_ascii_lowercase().contains("refused")
}

fn udp_service(port: u16) -> ServiceKind {
    match port {
        53 => ServiceKind::Dns,
        69 => ServiceKind::Tftp,
        123 => ServiceKind::Ntp,
        137 => ServiceKind::NetBiosName,
        161 => ServiceKind::Snmp,
        500 | 4500 => ServiceKind::Ike,
        443 | 784 => ServiceKind::Quic,
        1884 => ServiceKind::MqttSn,
        1900 => ServiceKind::Ssdp,
        3478 => ServiceKind::Stun,
        3702 => ServiceKind::WsDiscovery,
        5004 => ServiceKind::Rtp,
        5005 => ServiceKind::Rtcp,
        5060 => ServiceKind::Sip,
        5353 => ServiceKind::Mdns,
        5683 => ServiceKind::Coap,
        5684 => ServiceKind::Dtls,
        9000 => ServiceKind::Srt,
        _ => ServiceKind::Unknown,
    }
}

fn probe_payload(port: u16, hostname: &str, ip: IpAddr) -> Option<Vec<u8>> {
    match port {
        53 => Some(dns_query(hostname, 0x4e44)),
        123 => {
            let mut payload = vec![0u8; 48];
            payload[0] = 0x23;
            Some(payload)
        }
        500 => Some(ike_init(false)),
        4500 => Some(ike_init(true)),
        443 | 784 => Some(quic_version_probe()),
        1884 => Some(vec![3, 1, 1]),
        1900 => Some(
            format!(
                "M-SEARCH * HTTP/1.1\r\nHOST: {ip}:{port}\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
            )
            .into_bytes(),
        ),
        3478 => Some(stun_binding()),
        3702 => Some(ws_discovery()),
        5060 => Some(sip_options(hostname, ip)),
        5353 => Some(mdns_query(hostname)),
        5683 => Some(vec![0x40, 0x00, 0x4e, 0x44]),
        9000 => Some(srt_handshake()),
        _ => None,
    }
}

fn mdns_query(hostname: &str) -> Vec<u8> {
    let mut query = dns_query(hostname, 0);
    if query.len() >= 2 {
        let class = query.len() - 2;
        query[class..].copy_from_slice(&0x8001u16.to_be_bytes());
    }
    query
}

fn dns_query(hostname: &str, id: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[if id == 0 { 0 } else { 0x01 }, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in hostname.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Vec::new();
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

fn ike_init(nat_t: bool) -> Vec<u8> {
    let mut value = Vec::with_capacity(76);
    if nat_t {
        value.extend_from_slice(&[0, 0, 0, 0]);
    }
    value.extend_from_slice(&[0x4e, 0x41, 0x4e, 0x43, 0x59, 0x49, 0x4b, 0x45]);
    value.extend_from_slice(&[0; 8]);
    value.extend_from_slice(&[33, 0x20, 34, 0x08]);
    value.extend_from_slice(&[0; 4]);
    value.extend_from_slice(&72u32.to_be_bytes());
    value.extend_from_slice(&[0, 0]);
    value.extend_from_slice(&44u16.to_be_bytes());
    value.extend_from_slice(&[0, 0]);
    value.extend_from_slice(&40u16.to_be_bytes());
    value.extend_from_slice(&[1, 1, 0, 4]);
    for (index, (transform_type, transform_id)) in [(1u8, 3u16), (2, 2), (3, 2), (4, 14)]
        .into_iter()
        .enumerate()
    {
        value.push(if index == 3 { 0 } else { 3 });
        value.push(0);
        value.extend_from_slice(&8u16.to_be_bytes());
        value.extend_from_slice(&[transform_type, 0]);
        value.extend_from_slice(&transform_id.to_be_bytes());
    }
    value
}

fn quic_version_probe() -> Vec<u8> {
    let mut value = vec![0xc0];
    value.extend_from_slice(&0xface_b00cu32.to_be_bytes());
    value.push(8);
    value.extend_from_slice(b"NANCYQIC");
    value.push(8);
    value.extend_from_slice(b"DISCOVER");
    value.resize(1200, 0);
    value
}

fn stun_binding() -> Vec<u8> {
    let mut value = Vec::with_capacity(20);
    value.extend_from_slice(&[0, 1, 0, 0]);
    value.extend_from_slice(&0x2112_a442u32.to_be_bytes());
    value.extend_from_slice(STUN_TRANSACTION_ID);
    value
}

fn ws_discovery() -> Vec<u8> {
    b"<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action><a:MessageID>uuid:4e414e43-5900-4000-8000-000000000001</a:MessageID><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header><s:Body><d:Probe/></s:Body></s:Envelope>".to_vec()
}

fn sip_options(hostname: &str, ip: IpAddr) -> Vec<u8> {
    format!(
        "OPTIONS sip:{hostname} SIP/2.0\r\nVia: SIP/2.0/UDP scanner.invalid;branch=z9hG4bKnancy\r\nFrom: <sip:scanner@scanner.invalid>;tag=nancy\r\nTo: <sip:{hostname}>\r\nCall-ID: nancy@scanner.invalid\r\nCSeq: 1 OPTIONS\r\nContact: <sip:scanner@{ip}>\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

fn srt_handshake() -> Vec<u8> {
    let mut value = vec![0u8; 64];
    value[0..4].copy_from_slice(&0x8000_0000u32.to_be_bytes());
    value[16..20].copy_from_slice(&4u32.to_be_bytes());
    value[20..24].copy_from_slice(&2u32.to_be_bytes());
    value[24..28].copy_from_slice(&0x0100_0000u32.to_be_bytes());
    value[28..32].copy_from_slice(&1500u32.to_be_bytes());
    value[32..36].copy_from_slice(&8192u32.to_be_bytes());
    value[36..40].copy_from_slice(&1u32.to_be_bytes());
    value[44..48].copy_from_slice(&u32::from(Ipv4Addr::UNSPECIFIED).to_be_bytes());
    value
}

fn response_evidence(port: u16, response: &[u8], hostname: &str) -> String {
    let protocol = udp_service(port).to_string();
    let valid = match port {
        53 => {
            response.len() >= 12
                && response[0..2] == 0x4e44u16.to_be_bytes()
                && response[2] & 0x80 != 0
        }
        5353 => mdns_response(response, hostname).is_ok(),
        123 => response.len() >= 48 && response[0] & 7 == 4 && (response[0] >> 3) & 7 >= 3,
        500 => response.len() >= 28 && response[18] == 34,
        4500 => response.len() >= 32 && response[..4] == [0, 0, 0, 0] && response[22] == 34,
        443 | 784 => {
            response.len() >= 5 && response[0] & 0x80 != 0 && response[1..5] == [0, 0, 0, 0]
        }
        1884 => {
            response.len() >= 3
                && response[0] as usize == response.len()
                && matches!(response[1], 0 | 2)
        }
        1900 => response.starts_with(b"HTTP/1.1"),
        3478 => stun_binding_response(response).is_some(),
        3702 => String::from_utf8_lossy(response).contains("Envelope"),
        5060 => response.starts_with(b"SIP/2.0"),
        5683 => {
            response.len() >= 4
                && response[0] >> 6 == 1
                && response[2..4] == 0x4e44u16.to_be_bytes()
        }
        9000 => response.len() >= 64 && response[0] & 0x80 != 0,
        _ => false,
    };
    if port == 5353 {
        return match mdns_response(response, hostname) {
            Ok(()) => format!(
                "Valid target-specific mDNS response received from the selected endpoint ({} bytes)",
                response.len()
            ),
            Err(error) => format!("mDNS protocol mismatch: {error} ({} bytes)", response.len()),
        };
    }
    if valid {
        format!(
            "Bounded {protocol} discovery response received ({} bytes)",
            response.len()
        )
    } else {
        format!(
            "UDP response received from the selected endpoint but did not match expected {protocol} framing ({} bytes)",
            response.len()
        )
    }
}

fn mdns_response(response: &[u8], expected_hostname: &str) -> Result<(), String> {
    if response.len() < 12 {
        return Err("DNS header is truncated".to_owned());
    }
    if response[0..2] != [0, 0] {
        return Err("transaction ID is not zero".to_owned());
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0
        || flags & 0x0400 == 0
        || flags & 0x7800 != 0
        || flags & 0x0200 != 0
        || flags & 0x000f != 0
    {
        return Err("response flags are invalid for mDNS".to_owned());
    }
    let counts = [
        u16::from_be_bytes([response[4], response[5]]) as usize,
        u16::from_be_bytes([response[6], response[7]]) as usize,
        u16::from_be_bytes([response[8], response[9]]) as usize,
        u16::from_be_bytes([response[10], response[11]]) as usize,
    ];
    if counts[0] > 64 || counts[1..].iter().sum::<usize>() > 256 {
        return Err("record counts exceed the bounded parser limits".to_owned());
    }
    if counts[1..].iter().sum::<usize>() == 0 {
        return Err("response contains no resource records".to_owned());
    }
    let expected = expected_hostname.trim_end_matches('.').to_ascii_lowercase();
    let mut offset = 12usize;
    let mut question_correlated = expected.is_empty();
    for _ in 0..counts[0] {
        let (name, next) = dns_name(response, offset)?;
        offset = next;
        if offset + 4 > response.len() {
            return Err("question is truncated".to_owned());
        }
        let query_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let query_class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) & 0x7fff;
        offset += 4;
        if name.eq_ignore_ascii_case(&expected) && query_type == 1 && query_class == 1 {
            question_correlated = true;
        }
    }
    let mut answer_correlated = false;
    for section in 1..=3 {
        for _ in 0..counts[section] {
            let (name, next) = dns_name(response, offset)?;
            offset = next;
            if offset + 10 > response.len() {
                return Err("resource record header is truncated".to_owned());
            }
            let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let record_class =
                u16::from_be_bytes([response[offset + 2], response[offset + 3]]) & 0x7fff;
            let length = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
            offset += 10;
            if offset
                .checked_add(length)
                .is_none_or(|end| end > response.len())
            {
                return Err("resource record data is truncated".to_owned());
            }
            if section == 1
                && name.eq_ignore_ascii_case(&expected)
                && record_type == 1
                && record_class == 1
            {
                answer_correlated = true;
            }
            offset += length;
        }
    }
    if offset != response.len() {
        return Err("trailing bytes follow the declared DNS sections".to_owned());
    }
    if !expected.is_empty() && !question_correlated && !answer_correlated {
        return Err("response does not correlate to the requested A question".to_owned());
    }
    Ok(())
}

fn dns_name(packet: &[u8], start: usize) -> Result<(String, usize), String> {
    if start >= packet.len() {
        return Err("DNS name starts beyond the packet".to_owned());
    }
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = None;
    let mut jumps = 0usize;
    loop {
        let length = *packet
            .get(offset)
            .ok_or_else(|| "DNS name is truncated".to_owned())?;
        if length & 0xc0 == 0xc0 {
            let second = *packet
                .get(offset + 1)
                .ok_or_else(|| "DNS compression pointer is truncated".to_owned())?;
            let pointer = (((length & 0x3f) as usize) << 8) | second as usize;
            if pointer >= packet.len() || pointer >= offset {
                return Err("DNS compression pointer is invalid".to_owned());
            }
            next.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            if jumps > 32 {
                return Err("DNS compression pointer chain is too deep".to_owned());
            }
            continue;
        }
        if length & 0xc0 != 0 {
            return Err("DNS label uses reserved framing".to_owned());
        }
        offset += 1;
        if length == 0 {
            return Ok((labels.join("."), next.unwrap_or(offset)));
        }
        let end = offset + length as usize;
        let label = packet
            .get(offset..end)
            .ok_or_else(|| "DNS label is truncated".to_owned())?;
        if !label.iter().all(|byte| byte.is_ascii()) {
            return Err("DNS label is not ASCII".to_owned());
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        if labels.len() > 128 {
            return Err("DNS name contains too many labels".to_owned());
        }
        offset = end;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StunResponse {
    Success,
    Error,
}

fn stun_finding(
    ip: IpAddr,
    port: u16,
    response: &[u8],
    evidence: Vec<String>,
) -> Option<ExposureFinding> {
    (stun_binding_response(response) == Some(StunResponse::Success)).then(|| {
        public_stream_finding(
            ip,
            port,
            TransportProtocol::Udp,
            "STUN",
            "STUN Binding request",
            evidence,
        )
    })
}

fn stun_binding_response(response: &[u8]) -> Option<StunResponse> {
    if response.len() < 20
        || response[4..8] != 0x2112_a442u32.to_be_bytes()
        || &response[8..20] != STUN_TRANSACTION_ID
    {
        return None;
    }
    let kind = match u16::from_be_bytes([response[0], response[1]]) {
        0x0101 => StunResponse::Success,
        0x0111 => StunResponse::Error,
        _ => return None,
    };
    let declared_length = u16::from_be_bytes([response[2], response[3]]) as usize;
    if declared_length % 4 != 0 || response.len() != 20 + declared_length {
        return None;
    }
    let mut offset = 20;
    while offset < response.len() {
        if offset + 4 > response.len() {
            return None;
        }
        let attribute_length =
            u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
        let padded_length = (attribute_length + 3) & !3;
        offset += 4;
        if offset + padded_length > response.len() {
            return None;
        }
        offset += padded_length;
    }
    (offset == response.len()).then_some(kind)
}
