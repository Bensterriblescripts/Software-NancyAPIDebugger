use super::*;
use std::borrow::Cow;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

const IKE_PAYLOAD: [u8; 72] = [
    0x4e, 0x41, 0x4e, 0x43, 0x59, 0x49, 0x4b, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 33, 0x20, 34, 0x08, 0,
    0, 0, 0, 0, 0, 0, 72, 0, 0, 0, 44, 0, 0, 0, 40, 1, 1, 0, 4, 3, 0, 0, 8, 1, 0, 0, 3, 3, 0, 0, 8,
    2, 0, 0, 2, 3, 0, 0, 8, 3, 0, 0, 2, 0, 0, 0, 8, 4, 0, 0, 14,
];

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
            pending.push({
let (ip, port, hostname, timeout, cancel, limiter,): (IpAddr, u16, & str, Duration, & CancellationToken, & ConnectionRateLimiter,) = (ip, port, hostname, request.probe_timeout, cancel, limiter.as_ref(),);
async move {
let inlined_result: (UdpEndpointScan , Option < ExposureFinding >) = {

    let started = Instant::now();
    let service = {

let inlined_result: ServiceKind = {

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

};
inlined_result
};
    let mut result = UdpEndpointScan {
        ip,
        port,
        transport: TransportProtocol::Udp,
        state: UdpEndpointState::OpenOrFiltered,
        attempted: false,
        service,
        elapsed_ms: 0.0,
        evidence: Vec::new(),
        error: None,
    };
    let Some(payload) = ({
let (port, hostname, ip,): (u16, & str, IpAddr,) = (port, hostname, ip,);
let inlined_result: Option<Cow<'static, [u8]>> = {

    match port {
        53 => Some(Cow::Owned({
let (hostname, id,): (& str, u16,) = (hostname, 0x4e44,);
let inlined_result: Vec < u8 > = {
'inlined_dns_query: {

    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[if id == 0 { 0 } else { 0x01 }, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in hostname.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            break 'inlined_dns_query Vec::new();
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query

}
};
inlined_result
})),
        123 => Some(Cow::Borrowed(&const {
            let mut payload = [0u8; 48];
            payload[0] = 0x23;
            payload
        })),
        500 => Some(Cow::Borrowed(&IKE_PAYLOAD)),
        4500 => Some(Cow::Borrowed(&const {
            let mut payload = [0u8; 76];
            let mut index = 0;
            while index < IKE_PAYLOAD.len() {
                payload[index + 4] = IKE_PAYLOAD[index];
                index += 1;
            }
            payload
        })),
        443 | 784 => Some(Cow::Borrowed(&const {
            let mut value = [0u8; 1200];
            let header = b"\xc0\xfa\xce\xb0\x0c\x08NANCYQIC\x08DISCOVER";
            let mut index = 0;
            while index < header.len() {
                value[index] = header[index];
                index += 1;
            }
            value
        })),
        1884 => Some(Cow::Borrowed(&[3, 1, 1])),
        1900 => Some(Cow::Owned(
            format!(
                "M-SEARCH * HTTP/1.1\r\nHOST: {ip}:{port}\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
            )
            .into_bytes(),
        )),
        3478 => Some(Cow::Borrowed(&const {
            let mut value = [0u8; 20];
            value[1] = 1;
            let cookie = 0x2112_a442u32.to_be_bytes();
            let mut index = 0;
            while index < cookie.len() {
                value[index + 4] = cookie[index];
                index += 1;
            }
            index = 0;
            while index < STUN_TRANSACTION_ID.len() {
                value[index + 8] = STUN_TRANSACTION_ID[index];
                index += 1;
            }
            value
        })),
        3702 => Some(Cow::Borrowed(b"<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action><a:MessageID>uuid:4e414e43-5900-4000-8000-000000000001</a:MessageID><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header><s:Body><d:Probe/></s:Body></s:Envelope>")),
        5060 => Some(Cow::Owned({
let (hostname, ip,): (& str, IpAddr,) = (hostname, ip,);
let inlined_result: Vec < u8 > = {

    format!(
        "OPTIONS sip:{hostname} SIP/2.0\r\nVia: SIP/2.0/UDP scanner.invalid;branch=z9hG4bKnancy\r\nFrom: <sip:scanner@scanner.invalid>;tag=nancy\r\nTo: <sip:{hostname}>\r\nCall-ID: nancy@scanner.invalid\r\nCSeq: 1 OPTIONS\r\nContact: <sip:scanner@{ip}>\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
    )
    .into_bytes()

};
inlined_result
})),
        5353 => Some(Cow::Owned({
let (hostname,): (& str,) = (hostname,);
let inlined_result: Vec < u8 > = {

    let mut query = {
let (hostname, id,): (& str, u16,) = (hostname, 0,);
let inlined_result: Vec < u8 > = {
'inlined_dns_query: {

    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[if id == 0 { 0 } else { 0x01 }, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in hostname.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            break 'inlined_dns_query Vec::new();
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query

}
};
inlined_result
};
    if query.len() >= 2 {
        let class = query.len() - 2;
        query[class..].copy_from_slice(&0x8001u16.to_be_bytes());
    }
    query

};
inlined_result
})),
        5683 => Some(Cow::Borrowed(&[0x40, 0x00, 0x4e, 0x44])),
        9000 => Some(Cow::Borrowed(&const {
            let mut value = [0u8; 64];
            let fields = [
                (0, 0x8000_0000u32),
                (16, 4),
                (20, 2),
                (24, 0x0100_0000),
                (28, 1500),
                (32, 8192),
                (36, 1),
            ];
            let mut index = 0;
            while index < fields.len() {
                let (offset, field) = fields[index];
                let bytes = field.to_be_bytes();
                let mut byte = 0;
                while byte < bytes.len() {
                    value[offset + byte] = bytes[byte];
                    byte += 1;
                }
                index += 1;
            }
            value
        })),
        _ => None,
    }

};
inlined_result
}) else {
        result.evidence.push(
            "No datagram sent because this protocol would require a community, content request, allocation, media request, multicast, broadcast, or application message"
                .to_owned(),
        );
        return (result, None);
    };
    if limiter.wait(cancel).await.is_err() {
        result.state = UdpEndpointState::Cancelled;
        result.elapsed_ms = (started).elapsed().as_secs_f64() * 1000.0;
        return (result, None);
    }
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) => {
            result.state = UdpEndpointState::Error;
            result.error = Some(error.to_string());
            result.elapsed_ms = (started).elapsed().as_secs_f64() * 1000.0;
            return (result, None);
        }
    };
    let remote = SocketAddr::new(ip, port);
    let mut attempted = false;
    let operation = async {
        attempted = true;
        socket.send_to(payload.as_ref(), remote).await?;
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
        biased;
        _ = cancel.cancelled() => {
            result.state = UdpEndpointState::Cancelled;
            None
        }
        outcome = operation => Some(outcome),
    };
    result.attempted = attempted;
    let mut finding = None;
    if let Some(outcome) = outcome {
        match outcome {
            Ok(Some(response)) => {
                result.state = UdpEndpointState::Responsive;
                result
                    .evidence
                    .push({
let (port, response, hostname,): (u16, & [u8], & str,) = (port, &response, hostname,);
{
'inlined_response_evidence: {

    let protocol = ({

let inlined_result: ServiceKind = {

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

};
inlined_result
}).to_string();
    let valid = match port {
        53 => {
            response.len() >= 12
                && response[0..2] == 0x4e44u16.to_be_bytes()
                && response[2] & 0x80 != 0
        }
        5353 => ({
let (response, expected_hostname,): (& [u8], & str,) = (response, hostname,);
let inlined_result: Result < () , String > = {
'inlined_mdns_response: {

    if response.len() < 12 {
        break 'inlined_mdns_response Err("DNS header is truncated".to_owned());
    }
    if response[0..2] != [0, 0] {
        break 'inlined_mdns_response Err("transaction ID is not zero".to_owned());
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0
        || flags & 0x0400 == 0
        || flags & 0x7800 != 0
        || flags & 0x0200 != 0
        || flags & 0x000f != 0
    {
        break 'inlined_mdns_response Err("response flags are invalid for mDNS".to_owned());
    }
    let counts = [
        u16::from_be_bytes([response[4], response[5]]) as usize,
        u16::from_be_bytes([response[6], response[7]]) as usize,
        u16::from_be_bytes([response[8], response[9]]) as usize,
        u16::from_be_bytes([response[10], response[11]]) as usize,
    ];
    if counts[0] > 64 || counts[1..].iter().sum::<usize>() > 256 {
        break 'inlined_mdns_response Err("record counts exceed the bounded parser limits".to_owned());
    }
    if counts[1..].iter().sum::<usize>() == 0 {
        break 'inlined_mdns_response Err("response contains no resource records".to_owned());
    }
    let expected = expected_hostname.trim_end_matches('.').to_ascii_lowercase();
    let mut offset = 12usize;
    let mut question_correlated = expected.is_empty();
    for _ in 0..counts[0] {
        let (name, next) = match {
let (packet, start,): (& [u8], usize,) = (response, offset,);
let inlined_result: Result < (String , usize) , String > = {
'inlined_dns_name: {

    if start >= packet.len() {
        break 'inlined_dns_name Err("DNS name starts beyond the packet".to_owned());
    }
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = None;
    let mut jumps = 0usize;
    loop {
        let length = *match packet
            .get(offset)
            .ok_or_else(|| "DNS name is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
        if length & 0xc0 == 0xc0 {
            let second = *match packet
                .get(offset + 1)
                .ok_or_else(|| "DNS compression pointer is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
            let pointer = (((length & 0x3f) as usize) << 8) | second as usize;
            if pointer >= packet.len() || pointer >= offset {
                break 'inlined_dns_name Err("DNS compression pointer is invalid".to_owned());
            }
            next.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            if jumps > 32 {
                break 'inlined_dns_name Err("DNS compression pointer chain is too deep".to_owned());
            }
            continue;
        }
        if length & 0xc0 != 0 {
            break 'inlined_dns_name Err("DNS label uses reserved framing".to_owned());
        }
        offset += 1;
        if length == 0 {
            break 'inlined_dns_name Ok((labels.join("."), next.unwrap_or(offset)));
        }
        let end = offset + length as usize;
        let label = match packet
            .get(offset..end)
            .ok_or_else(|| "DNS label is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
        if !label.iter().all(|byte| byte.is_ascii()) {
            break 'inlined_dns_name Err("DNS label is not ASCII".to_owned());
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        if labels.len() > 128 {
            break 'inlined_dns_name Err("DNS name contains too many labels".to_owned());
        }
        offset = end;
    }

}
};
inlined_result
} { Ok(value) => value, Err(error) => break 'inlined_mdns_response Err(::core::convert::From::from(error)) };
        offset = next;
        if offset + 4 > response.len() {
            break 'inlined_mdns_response Err("question is truncated".to_owned());
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
            let (name, next) = match {
let (packet, start,): (& [u8], usize,) = (response, offset,);
let inlined_result: Result < (String , usize) , String > = {
'inlined_dns_name: {

    if start >= packet.len() {
        break 'inlined_dns_name Err("DNS name starts beyond the packet".to_owned());
    }
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = None;
    let mut jumps = 0usize;
    loop {
        let length = *match packet
            .get(offset)
            .ok_or_else(|| "DNS name is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
        if length & 0xc0 == 0xc0 {
            let second = *match packet
                .get(offset + 1)
                .ok_or_else(|| "DNS compression pointer is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
            let pointer = (((length & 0x3f) as usize) << 8) | second as usize;
            if pointer >= packet.len() || pointer >= offset {
                break 'inlined_dns_name Err("DNS compression pointer is invalid".to_owned());
            }
            next.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            if jumps > 32 {
                break 'inlined_dns_name Err("DNS compression pointer chain is too deep".to_owned());
            }
            continue;
        }
        if length & 0xc0 != 0 {
            break 'inlined_dns_name Err("DNS label uses reserved framing".to_owned());
        }
        offset += 1;
        if length == 0 {
            break 'inlined_dns_name Ok((labels.join("."), next.unwrap_or(offset)));
        }
        let end = offset + length as usize;
        let label = match packet
            .get(offset..end)
            .ok_or_else(|| "DNS label is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
        if !label.iter().all(|byte| byte.is_ascii()) {
            break 'inlined_dns_name Err("DNS label is not ASCII".to_owned());
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        if labels.len() > 128 {
            break 'inlined_dns_name Err("DNS name contains too many labels".to_owned());
        }
        offset = end;
    }

}
};
inlined_result
} { Ok(value) => value, Err(error) => break 'inlined_mdns_response Err(::core::convert::From::from(error)) };
            offset = next;
            if offset + 10 > response.len() {
                break 'inlined_mdns_response Err("resource record header is truncated".to_owned());
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
                break 'inlined_mdns_response Err("resource record data is truncated".to_owned());
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
        break 'inlined_mdns_response Err("trailing bytes follow the declared DNS sections".to_owned());
    }
    if !expected.is_empty() && !question_correlated && !answer_correlated {
        break 'inlined_mdns_response Err("response does not correlate to the requested A question".to_owned());
    }
    Ok(())

}
};
inlined_result
}).is_ok(),
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
        3478 => ({
let (response,): (& [u8],) = (response,);
let inlined_result: Option < StunResponse > = {
'inlined_stun_binding_response: {

    if response.len() < 20
        || response[4..8] != 0x2112_a442u32.to_be_bytes()
        || &response[8..20] != STUN_TRANSACTION_ID
    {
        break 'inlined_stun_binding_response None;
    }
    let kind = match u16::from_be_bytes([response[0], response[1]]) {
        0x0101 => StunResponse::Success,
        0x0111 => StunResponse::Error,
        _ => break 'inlined_stun_binding_response None,
    };
    let declared_length = u16::from_be_bytes([response[2], response[3]]) as usize;
    if declared_length % 4 != 0 || response.len() != 20 + declared_length {
        break 'inlined_stun_binding_response None;
    }
    let mut offset = 20;
    while offset < response.len() {
        if offset + 4 > response.len() {
            break 'inlined_stun_binding_response None;
        }
        let attribute_length =
            u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
        let padded_length = (attribute_length + 3) & !3;
        offset += 4;
        if offset + padded_length > response.len() {
            break 'inlined_stun_binding_response None;
        }
        offset += padded_length;
    }
    (offset == response.len()).then_some(kind)

}
};
inlined_result
}).is_some(),
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
        break 'inlined_response_evidence match {
let (response, expected_hostname,): (& [u8], & str,) = (response, hostname,);
let inlined_result: Result < () , String > = {
'inlined_mdns_response: {

    if response.len() < 12 {
        break 'inlined_mdns_response Err("DNS header is truncated".to_owned());
    }
    if response[0..2] != [0, 0] {
        break 'inlined_mdns_response Err("transaction ID is not zero".to_owned());
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0
        || flags & 0x0400 == 0
        || flags & 0x7800 != 0
        || flags & 0x0200 != 0
        || flags & 0x000f != 0
    {
        break 'inlined_mdns_response Err("response flags are invalid for mDNS".to_owned());
    }
    let counts = [
        u16::from_be_bytes([response[4], response[5]]) as usize,
        u16::from_be_bytes([response[6], response[7]]) as usize,
        u16::from_be_bytes([response[8], response[9]]) as usize,
        u16::from_be_bytes([response[10], response[11]]) as usize,
    ];
    if counts[0] > 64 || counts[1..].iter().sum::<usize>() > 256 {
        break 'inlined_mdns_response Err("record counts exceed the bounded parser limits".to_owned());
    }
    if counts[1..].iter().sum::<usize>() == 0 {
        break 'inlined_mdns_response Err("response contains no resource records".to_owned());
    }
    let expected = expected_hostname.trim_end_matches('.').to_ascii_lowercase();
    let mut offset = 12usize;
    let mut question_correlated = expected.is_empty();
    for _ in 0..counts[0] {
        let (name, next) = match {
let (packet, start,): (& [u8], usize,) = (response, offset,);
let inlined_result: Result < (String , usize) , String > = {
'inlined_dns_name: {

    if start >= packet.len() {
        break 'inlined_dns_name Err("DNS name starts beyond the packet".to_owned());
    }
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = None;
    let mut jumps = 0usize;
    loop {
        let length = *match packet
            .get(offset)
            .ok_or_else(|| "DNS name is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
        if length & 0xc0 == 0xc0 {
            let second = *match packet
                .get(offset + 1)
                .ok_or_else(|| "DNS compression pointer is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
            let pointer = (((length & 0x3f) as usize) << 8) | second as usize;
            if pointer >= packet.len() || pointer >= offset {
                break 'inlined_dns_name Err("DNS compression pointer is invalid".to_owned());
            }
            next.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            if jumps > 32 {
                break 'inlined_dns_name Err("DNS compression pointer chain is too deep".to_owned());
            }
            continue;
        }
        if length & 0xc0 != 0 {
            break 'inlined_dns_name Err("DNS label uses reserved framing".to_owned());
        }
        offset += 1;
        if length == 0 {
            break 'inlined_dns_name Ok((labels.join("."), next.unwrap_or(offset)));
        }
        let end = offset + length as usize;
        let label = match packet
            .get(offset..end)
            .ok_or_else(|| "DNS label is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
        if !label.iter().all(|byte| byte.is_ascii()) {
            break 'inlined_dns_name Err("DNS label is not ASCII".to_owned());
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        if labels.len() > 128 {
            break 'inlined_dns_name Err("DNS name contains too many labels".to_owned());
        }
        offset = end;
    }

}
};
inlined_result
} { Ok(value) => value, Err(error) => break 'inlined_mdns_response Err(::core::convert::From::from(error)) };
        offset = next;
        if offset + 4 > response.len() {
            break 'inlined_mdns_response Err("question is truncated".to_owned());
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
            let (name, next) = match {
let (packet, start,): (& [u8], usize,) = (response, offset,);
let inlined_result: Result < (String , usize) , String > = {
'inlined_dns_name: {

    if start >= packet.len() {
        break 'inlined_dns_name Err("DNS name starts beyond the packet".to_owned());
    }
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = None;
    let mut jumps = 0usize;
    loop {
        let length = *match packet
            .get(offset)
            .ok_or_else(|| "DNS name is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
        if length & 0xc0 == 0xc0 {
            let second = *match packet
                .get(offset + 1)
                .ok_or_else(|| "DNS compression pointer is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
            let pointer = (((length & 0x3f) as usize) << 8) | second as usize;
            if pointer >= packet.len() || pointer >= offset {
                break 'inlined_dns_name Err("DNS compression pointer is invalid".to_owned());
            }
            next.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            if jumps > 32 {
                break 'inlined_dns_name Err("DNS compression pointer chain is too deep".to_owned());
            }
            continue;
        }
        if length & 0xc0 != 0 {
            break 'inlined_dns_name Err("DNS label uses reserved framing".to_owned());
        }
        offset += 1;
        if length == 0 {
            break 'inlined_dns_name Ok((labels.join("."), next.unwrap_or(offset)));
        }
        let end = offset + length as usize;
        let label = match packet
            .get(offset..end)
            .ok_or_else(|| "DNS label is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
        if !label.iter().all(|byte| byte.is_ascii()) {
            break 'inlined_dns_name Err("DNS label is not ASCII".to_owned());
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        if labels.len() > 128 {
            break 'inlined_dns_name Err("DNS name contains too many labels".to_owned());
        }
        offset = end;
    }

}
};
inlined_result
} { Ok(value) => value, Err(error) => break 'inlined_mdns_response Err(::core::convert::From::from(error)) };
            offset = next;
            if offset + 10 > response.len() {
                break 'inlined_mdns_response Err("resource record header is truncated".to_owned());
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
                break 'inlined_mdns_response Err("resource record data is truncated".to_owned());
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
        break 'inlined_mdns_response Err("trailing bytes follow the declared DNS sections".to_owned());
    }
    if !expected.is_empty() && !question_correlated && !answer_correlated {
        break 'inlined_mdns_response Err("response does not correlate to the requested A question".to_owned());
    }
    Ok(())

}
};
inlined_result
} {
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
}

});
                if port == 3478 {
                    finding = {
let (ip, port, response, evidence,): (IpAddr, u16, & [u8], Vec < String >,) = (ip, port, &response, result.evidence.clone(),);
{

    (({
let (response,): (& [u8],) = (response,);
let inlined_result: Option < StunResponse > = {
'inlined_stun_binding_response: {

    if response.len() < 20
        || response[4..8] != 0x2112_a442u32.to_be_bytes()
        || &response[8..20] != STUN_TRANSACTION_ID
    {
        break 'inlined_stun_binding_response None;
    }
    let kind = match u16::from_be_bytes([response[0], response[1]]) {
        0x0101 => StunResponse::Success,
        0x0111 => StunResponse::Error,
        _ => break 'inlined_stun_binding_response None,
    };
    let declared_length = u16::from_be_bytes([response[2], response[3]]) as usize;
    if declared_length % 4 != 0 || response.len() != 20 + declared_length {
        break 'inlined_stun_binding_response None;
    }
    let mut offset = 20;
    while offset < response.len() {
        if offset + 4 > response.len() {
            break 'inlined_stun_binding_response None;
        }
        let attribute_length =
            u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
        let padded_length = (attribute_length + 3) & !3;
        offset += 4;
        if offset + padded_length > response.len() {
            break 'inlined_stun_binding_response None;
        }
        offset += padded_length;
    }
    (offset == response.len()).then_some(kind)

}
};
inlined_result
}) == Some(StunResponse::Success)).then(|| {
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

};
                } else if port == 5353 && ({
let (response, expected_hostname,): (& [u8], & str,) = (&response, hostname,);
let inlined_result: Result < () , String > = {
'inlined_mdns_response: {

    if response.len() < 12 {
        break 'inlined_mdns_response Err("DNS header is truncated".to_owned());
    }
    if response[0..2] != [0, 0] {
        break 'inlined_mdns_response Err("transaction ID is not zero".to_owned());
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0
        || flags & 0x0400 == 0
        || flags & 0x7800 != 0
        || flags & 0x0200 != 0
        || flags & 0x000f != 0
    {
        break 'inlined_mdns_response Err("response flags are invalid for mDNS".to_owned());
    }
    let counts = [
        u16::from_be_bytes([response[4], response[5]]) as usize,
        u16::from_be_bytes([response[6], response[7]]) as usize,
        u16::from_be_bytes([response[8], response[9]]) as usize,
        u16::from_be_bytes([response[10], response[11]]) as usize,
    ];
    if counts[0] > 64 || counts[1..].iter().sum::<usize>() > 256 {
        break 'inlined_mdns_response Err("record counts exceed the bounded parser limits".to_owned());
    }
    if counts[1..].iter().sum::<usize>() == 0 {
        break 'inlined_mdns_response Err("response contains no resource records".to_owned());
    }
    let expected = expected_hostname.trim_end_matches('.').to_ascii_lowercase();
    let mut offset = 12usize;
    let mut question_correlated = expected.is_empty();
    for _ in 0..counts[0] {
        let (name, next) = match {
let (packet, start,): (& [u8], usize,) = (response, offset,);
let inlined_result: Result < (String , usize) , String > = {
'inlined_dns_name: {

    if start >= packet.len() {
        break 'inlined_dns_name Err("DNS name starts beyond the packet".to_owned());
    }
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = None;
    let mut jumps = 0usize;
    loop {
        let length = *match packet
            .get(offset)
            .ok_or_else(|| "DNS name is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
        if length & 0xc0 == 0xc0 {
            let second = *match packet
                .get(offset + 1)
                .ok_or_else(|| "DNS compression pointer is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
            let pointer = (((length & 0x3f) as usize) << 8) | second as usize;
            if pointer >= packet.len() || pointer >= offset {
                break 'inlined_dns_name Err("DNS compression pointer is invalid".to_owned());
            }
            next.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            if jumps > 32 {
                break 'inlined_dns_name Err("DNS compression pointer chain is too deep".to_owned());
            }
            continue;
        }
        if length & 0xc0 != 0 {
            break 'inlined_dns_name Err("DNS label uses reserved framing".to_owned());
        }
        offset += 1;
        if length == 0 {
            break 'inlined_dns_name Ok((labels.join("."), next.unwrap_or(offset)));
        }
        let end = offset + length as usize;
        let label = match packet
            .get(offset..end)
            .ok_or_else(|| "DNS label is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
        if !label.iter().all(|byte| byte.is_ascii()) {
            break 'inlined_dns_name Err("DNS label is not ASCII".to_owned());
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        if labels.len() > 128 {
            break 'inlined_dns_name Err("DNS name contains too many labels".to_owned());
        }
        offset = end;
    }

}
};
inlined_result
} { Ok(value) => value, Err(error) => break 'inlined_mdns_response Err(::core::convert::From::from(error)) };
        offset = next;
        if offset + 4 > response.len() {
            break 'inlined_mdns_response Err("question is truncated".to_owned());
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
            let (name, next) = match {
let (packet, start,): (& [u8], usize,) = (response, offset,);
let inlined_result: Result < (String , usize) , String > = {
'inlined_dns_name: {

    if start >= packet.len() {
        break 'inlined_dns_name Err("DNS name starts beyond the packet".to_owned());
    }
    let mut labels = Vec::new();
    let mut offset = start;
    let mut next = None;
    let mut jumps = 0usize;
    loop {
        let length = *match packet
            .get(offset)
            .ok_or_else(|| "DNS name is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
        if length & 0xc0 == 0xc0 {
            let second = *match packet
                .get(offset + 1)
                .ok_or_else(|| "DNS compression pointer is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
            let pointer = (((length & 0x3f) as usize) << 8) | second as usize;
            if pointer >= packet.len() || pointer >= offset {
                break 'inlined_dns_name Err("DNS compression pointer is invalid".to_owned());
            }
            next.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            if jumps > 32 {
                break 'inlined_dns_name Err("DNS compression pointer chain is too deep".to_owned());
            }
            continue;
        }
        if length & 0xc0 != 0 {
            break 'inlined_dns_name Err("DNS label uses reserved framing".to_owned());
        }
        offset += 1;
        if length == 0 {
            break 'inlined_dns_name Ok((labels.join("."), next.unwrap_or(offset)));
        }
        let end = offset + length as usize;
        let label = match packet
            .get(offset..end)
            .ok_or_else(|| "DNS label is truncated".to_owned()) { Ok(value) => value, Err(error) => break 'inlined_dns_name Err(::core::convert::From::from(error)) };
        if !label.iter().all(|byte| byte.is_ascii()) {
            break 'inlined_dns_name Err("DNS label is not ASCII".to_owned());
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        if labels.len() > 128 {
            break 'inlined_dns_name Err("DNS name contains too many labels".to_owned());
        }
        offset = end;
    }

}
};
inlined_result
} { Ok(value) => value, Err(error) => break 'inlined_mdns_response Err(::core::convert::From::from(error)) };
            offset = next;
            if offset + 10 > response.len() {
                break 'inlined_mdns_response Err("resource record header is truncated".to_owned());
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
                break 'inlined_mdns_response Err("resource record data is truncated".to_owned());
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
        break 'inlined_mdns_response Err("trailing bytes follow the declared DNS sections".to_owned());
    }
    if !expected.is_empty() && !question_correlated && !answer_correlated {
        break 'inlined_mdns_response Err("response does not correlate to the requested A question".to_owned());
    }
    Ok(())

}
};
inlined_result
}).is_ok() {
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
            Err(error) if ({
let (error,): (& std :: io :: Error,) = (&error,);
{

    matches!(error.raw_os_error(), Some(61 | 111 | 10054 | 10061))
        || error.to_string().to_ascii_lowercase().contains("refused")

}

}) => {
                result.state = UdpEndpointState::Closed;
                result.error = Some(error.to_string());
            }
            Err(error) => {
                result.state = UdpEndpointState::Error;
                result.error = Some(error.to_string());
            }
        }
    }
    result.elapsed_ms = (started).elapsed().as_secs_f64() * 1000.0;
    (result, finding)

};
inlined_result
}
});
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum StunResponse {
    Success,
    Error,
}
