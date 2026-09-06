use super::*;

const READ_LIMIT: usize = 4096;

pub(super) async fn run(
    endpoints: &[EndpointScan],
    hostname: &str,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: Arc<ConnectionRateLimiter>,
    progress: &Option<Sender<ExposureScanProgress>>,
) -> (Vec<ServiceAccessResult>, Vec<ExposureFinding>) {
    let jobs = endpoints
        .iter()
        .filter(|endpoint| endpoint.state == PortState::Open)
        .filter(|endpoint| !endpoint_health::stopped(endpoint.ip, endpoint.port))
        .filter_map(|endpoint| {
            let service = {
                let (endpoint,): (&EndpointScan,) = (endpoint,);
                let inlined_result: ServiceKind = {
                    let associated = match endpoint.port {
                        21 => ServiceKind::Ftp,
                        25 | 465 | 587 => ServiceKind::Smtp,
                        110 | 995 => ServiceKind::Pop3,
                        111 => ServiceKind::Rpcbind,
                        139 | 445 => ServiceKind::Smb,
                        143 | 993 => ServiceKind::Imap,
                        389 | 636 | 3268 | 3269 => ServiceKind::Ldap,
                        554 | 8554 => ServiceKind::Rtsp,
                        873 => ServiceKind::Rsync,
                        1883 | 8883 => ServiceKind::Mqtt,
                        1935 => ServiceKind::Rtmp,
                        2049 => ServiceKind::Nfs,
                        3306 => ServiceKind::Mysql,
                        3389 => ServiceKind::Rdp,
                        5432 => ServiceKind::PostgreSql,
                        5900..=5903 => ServiceKind::Vnc,
                        6379 => ServiceKind::Redis,
                        11211 => ServiceKind::Memcached,
                        27017 => ServiceKind::MongoDb,
                        _ => ServiceKind::Unknown,
                    };
                    if associated != ServiceKind::Unknown {
                        associated
                    } else {
                        endpoint.service
                    }
                };
                inlined_result
            };
            (service != ServiceKind::Unknown || !endpoint.http.is_empty()).then_some((
                endpoint.ip,
                endpoint.port,
                service,
                !endpoint.http.is_empty(),
            ))
        })
        .collect::<Vec<_>>();
    let total = jobs.len();
    send_phase_progress(
        progress,
        ExposureScanPhase::ServiceAccess,
        ExposureScanPhaseState::Running,
        0.0,
        format!("0 / {total} service checks"),
    );
    let mut pending = FuturesUnordered::new();
    let mut next = 0usize;
    let mut completed_jobs = 0usize;
    let mut results = Vec::new();
    while next < jobs.len() || !pending.is_empty() {
        while next < jobs.len() && pending.len() < request.concurrency && !cancel.is_cancelled() {
            let (ip, port, service, has_http) = jobs[next];
            next += 1;
            pending.push({
let (ip, port, service, has_http, hostname, request, cancel, limiter,): (IpAddr, u16, ServiceKind, bool, & str, & ExposureScanRequest, & CancellationToken, & ConnectionRateLimiter,) = (ip, port, service, has_http, hostname, request, cancel, limiter.as_ref(),);
async move {

    let mut results = Vec::new();
    if has_http {
        results.push({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, service, "Bounded HTTP metadata read", ServiceAccessStatus::Offered, "HTTP metadata reads are reported separately from handshake-only service checks", Vec::new(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

});
    }
    if matches!(service, ServiceKind::Http | ServiceKind::Https) {
        return results;
    }
    if matches!(
        service,
        ServiceKind::Rpcbind | ServiceKind::Nfs | ServiceKind::MongoDb | ServiceKind::Rsync
    ) {
        results.push({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, service, "Pre-authentication observation", if service == ServiceKind::Rsync {
                ServiceAccessStatus::Offered
            } else {
                ServiceAccessStatus::Inconclusive
            }, "The exposed service was recorded without enumeration or a data command", Vec::new(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

});
        return results;
    }
    if service == ServiceKind::Unknown || cancel.is_cancelled() {
        return results;
    }
    if matches!(port, 465 | 636 | 993 | 995 | 3269 | 8883) {
        results.push({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, service, "TLS-wrapped pre-authentication observation", ServiceAccessStatus::Inconclusive, "TLS exposure was recorded, but no plaintext protocol message was sent to the encrypted listener", Vec::new(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

});
        return results;
    }
    if limiter.wait(cancel).await.is_err() {
        results.push({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, service, "Handshake-only check", ServiceAccessStatus::Inconclusive, "Check cancelled before connection", Vec::new(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

});
        return results;
    }
    let mut candidate = connect_tcp_endpoint(ip, port, request.connection_timeout, cancel).await;
    let Some(mut stream) = candidate.stream.take() else {
        results.push({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, service, "Handshake-only check", ServiceAccessStatus::Inconclusive, "Unable to establish the bounded negotiation session", candidate.attempt.error.into_iter().collect(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

});
        return results;
    };
    let checked = tokio::select! {
        _ = cancel.cancelled() => Err("Check cancelled".to_owned()),
        checked = tokio::time::timeout(request.probe_timeout, negotiate(&mut stream, ip, port, service, hostname)) => {
            checked.map_err(|_| "Negotiation timed out".to_owned()).and_then(|value| value)
        }
    };
    let _ = stream.shutdown().await;
    results.push(checked.unwrap_or_else(|error| {
        {
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, service, "Handshake-only check", ServiceAccessStatus::Inconclusive, "The bounded negotiation did not produce a conclusive result", vec![error],);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

}
    }));
    results

}
});
        }
        let Some(result) = pending.next().await else {
            break;
        };
        completed_jobs += 1;
        let completed = completed_jobs;
        if let Some(progress) = progress {
            for access in &result {
                let _ = progress.send(ExposureScanProgress::ServiceAccessCompleted {
                    completed,
                    total,
                    result: access.clone(),
                });
            }
        }
        results.extend(result);
        send_phase_progress(
            progress,
            ExposureScanPhase::ServiceAccess,
            ExposureScanPhaseState::Running,
            completed as f32 / total.max(1) as f32,
            format!("{completed} / {total} service checks"),
        );
        if cancel.is_cancelled() {
            break;
        }
    }
    results.sort_by(|left, right| {
        left.ip
            .cmp(&right.ip)
            .then(left.port.cmp(&right.port))
            .then(left.method.cmp(&right.method))
    });
    let findings = results.iter().filter_map(access_finding).collect();
    if !cancel.is_cancelled() {
        send_phase_progress(
            progress,
            ExposureScanPhase::ServiceAccess,
            ExposureScanPhaseState::Complete,
            1.0,
            format!("{} service observations", results.len()),
        );
    }
    (results, findings)
}

async fn negotiate(
    stream: &mut TcpStream,
    ip: IpAddr,
    port: u16,
    service: ServiceKind,
    hostname: &str,
) -> Result<ServiceAccessResult, String> {
    match service {
        ServiceKind::Ftp => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {
let inlined_result: Result < ServiceAccessResult , String > = {

    let greeting = {
let (value,): (Vec < u8 >,) = (({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?,);
{

    String::from_utf8_lossy(&value).into_owned()

}

};
    stream
        .write_all(b"USER anonymous\r\n")
        .await
        .map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let user = {
let (value,): (Vec < u8 >,) = (({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?,);
{

    String::from_utf8_lossy(&value).into_owned()

}

};
    let status = {
let (value,): (& str,) = (&user,);
{
'inlined_ftp_status: {

    match value.get(..3) { Some(value) => value, None => break 'inlined_ftp_status None }.parse().ok()

}
}

};
    let accepted = if status == Some(230) {
        true
    } else if status == Some(331) {
        stream
            .write_all(b"PASS nancywebdebug@invalid\r\n")
            .await
            .map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
        ({
let (value,): (& str,) = (&({
let (value,): (Vec < u8 >,) = (({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?,);
{

    String::from_utf8_lossy(&value).into_owned()

}

}),);
{
'inlined_ftp_status: {

    match value.get(..3) { Some(value) => value, None => break 'inlined_ftp_status None }.parse().ok()

}
}

}) == Some(230)
    } else {
        false
    };
    let _ = stream.write_all(b"QUIT\r\n").await;
    Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, ServiceKind::Ftp, "Anonymous login", if accepted {
            ServiceAccessStatus::Confirmed
        } else {
            ServiceAccessStatus::Protected
        }, if accepted {
            "FTP accepted an anonymous session; no directory or file command was sent"
        } else {
            "FTP did not accept the bounded anonymous login"
        }, vec![greeting, user],);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

})

};
inlined_result
}
}).await,
        ServiceKind::Ldap => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {

    stream
        .write_all(&[
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ])
        .await
        .map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let response = ({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?;
    let code = response
        .windows(3)
        .find(|value| value[0] == 0x0a && value[1] == 1)
        .map(|value| value[2]);
    let _ = stream
        .write_all(&[0x30, 0x05, 0x02, 0x01, 0x02, 0x42, 0x00])
        .await;
    Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, ServiceKind::Ldap, "LDAP v3 anonymous bind", match code {
            Some(0) => ServiceAccessStatus::Confirmed,
            Some(_) => ServiceAccessStatus::Protected,
            None => ServiceAccessStatus::Inconclusive,
        }, match code {
            Some(0) => "LDAP accepted an anonymous bind; no directory query was sent",
            Some(_) => "LDAP rejected or restricted the anonymous bind",
            None => "LDAP bind response was not recognized",
        }, code.map(|value| vec![format!("LDAP bind result code {value}")])
            .unwrap_or_default(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

})

}
}).await,
        ServiceKind::Smb => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {
let inlined_result: Result < ServiceAccessResult , String > = {

    let negotiate = {
let inlined_result: [u8; 106] = {

    let mut packet = [0u8; 106];
    let length = packet.len() as u32 - 4;
    packet[0..4].copy_from_slice(&length.to_be_bytes());
    packet[4..8].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
    packet[8..10].copy_from_slice(&64u16.to_le_bytes());
    packet[10..12].copy_from_slice(&1u16.to_le_bytes());
    packet[18..20].copy_from_slice(&1u16.to_le_bytes());
    packet[68..70].copy_from_slice(&36u16.to_le_bytes());
    packet[70..72].copy_from_slice(&1u16.to_le_bytes());
    packet[72..74].copy_from_slice(&1u16.to_le_bytes());
    packet[76..80].copy_from_slice(&1u32.to_le_bytes());
    packet[84..100].copy_from_slice(b"NANCY-SMB-CLIENT");
    packet[104..106].copy_from_slice(&0x0202u16.to_le_bytes());
    packet

};
inlined_result
};
    stream.write_all(&negotiate).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let response = ({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?;
    if response.len() < 72 || response.get(4..8) != Some(&[0xfe, b'S', b'M', b'B']) {
        return Err("SMB2 negotiate response was not recognized".to_owned());
    }
    let session = {
let inlined_result: [u8; 92] = {

    let mut packet = [0u8; 92];
    let length = packet.len() as u32 - 4;
    packet[0..4].copy_from_slice(&length.to_be_bytes());
    packet[4..8].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
    packet[8..10].copy_from_slice(&64u16.to_le_bytes());
    packet[10..12].copy_from_slice(&1u16.to_le_bytes());
    packet[16..18].copy_from_slice(&1u16.to_le_bytes());
    packet[18..20].copy_from_slice(&1u16.to_le_bytes());
    packet[28] = 1;
    packet[68..70].copy_from_slice(&25u16.to_le_bytes());
    packet[70] = 0;
    packet[71] = 1;
    packet[80..82].copy_from_slice(&88u16.to_le_bytes());
    packet

};
inlined_result
};
    stream.write_all(&session).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let response = ({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?;
    let status = response
        .get(12..16)
        .map(|value| u32::from_le_bytes([value[0], value[1], value[2], value[3]]));
    Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, ServiceKind::Smb, "SMB2 negotiate and anonymous session setup", if status == Some(0) {
            ServiceAccessStatus::Confirmed
        } else if status.is_some() {
            ServiceAccessStatus::Protected
        } else {
            ServiceAccessStatus::Inconclusive
        }, if status == Some(0) {
            "SMB accepted an anonymous session; no share enumeration was performed"
        } else {
            "SMB did not accept the empty anonymous session setup"
        }, status
            .map(|value| vec![format!("SMB status 0x{value:08X}")])
            .unwrap_or_default(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

})

};
inlined_result
}
}).await,
        ServiceKind::Redis => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {

    stream.write_all(b"PING\r\n").await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let response = {
let (value,): (Vec < u8 >,) = (({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?,);
{

    String::from_utf8_lossy(&value).into_owned()

}

};
    let confirmed = response.to_ascii_lowercase().starts_with("+pong");
    Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, ServiceKind::Redis, "Unauthenticated PING", if confirmed {
            ServiceAccessStatus::Confirmed
        } else if response.to_ascii_lowercase().contains("noauth") {
            ServiceAccessStatus::Protected
        } else {
            ServiceAccessStatus::Inconclusive
        }, if confirmed {
            "Redis accepted an unauthenticated command"
        } else {
            "Redis did not confirm unauthenticated command access"
        }, vec!["Response content redacted".to_owned()],);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

})

}
}).await,
        ServiceKind::Memcached => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {

    stream.write_all(b"version\r\n").await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let confirmed = ({
let (value,): (Vec < u8 >,) = (({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?,);
{

    String::from_utf8_lossy(&value).into_owned()

}

})
        .to_ascii_lowercase()
        .starts_with("version ");
    let _ = stream.write_all(b"quit\r\n").await;
    Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, ServiceKind::Memcached, "Unauthenticated version command", if confirmed {
            ServiceAccessStatus::Confirmed
        } else {
            ServiceAccessStatus::Inconclusive
        }, if confirmed {
            "Memcached accepted an unauthenticated command; returned values were redacted"
        } else {
            "Memcached command acceptance was not confirmed"
        }, Vec::new(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

})

}
}).await,
        ServiceKind::Mqtt => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {

    let client = b"nancy-access-check";
    let mut packet = [0u8; 32];
    packet[..12].copy_from_slice(&[0x10, 30, 0, 4, b'M', b'Q', b'T', b'T', 4, 2, 0, 10]);
    packet[12..14].copy_from_slice(&(client.len() as u16).to_be_bytes());
    packet[14..].copy_from_slice(client);
    stream.write_all(&packet).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let response = ({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?;
    let code = response.get(3).copied();
    if code == Some(0) {
        let _ = stream.write_all(&[0xe0, 0]).await;
    }
    Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, ServiceKind::Mqtt, "Anonymous CONNECT", match code {
            Some(0) => ServiceAccessStatus::Confirmed,
            Some(4 | 5) => ServiceAccessStatus::Protected,
            Some(_) => ServiceAccessStatus::Inconclusive,
            None => ServiceAccessStatus::Inconclusive,
        }, if code == Some(0) {
            "MQTT accepted an anonymous connection; it was disconnected without subscribing or publishing"
        } else {
            "MQTT did not confirm anonymous session access"
        }, code.map(|value| vec![format!("MQTT CONNACK code {value}")])
            .unwrap_or_default(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

})

}
}).await,
        ServiceKind::Vnc => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {

    let banner = ({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?;
    if !banner.starts_with(b"RFB ") {
        return Err("VNC version banner was not recognized".to_owned());
    }
    let version = &banner[..banner.len().min(12)];
    stream.write_all(version).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let security = ({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?;
    let none = if version.starts_with(b"RFB 003.003") {
        security.len() >= 4
            && u32::from_be_bytes([security[0], security[1], security[2], security[3]]) == 1
    } else {
        security.first().is_some_and(|count| {
            let count = *count as usize;
            security
                .get(1..=count)
                .is_some_and(|values| values.contains(&1))
        })
    };
    Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, ServiceKind::Vnc, "Advertised security types", if none {
            ServiceAccessStatus::Confirmed
        } else {
            ServiceAccessStatus::Protected
        }, if none {
            "VNC advertised None authentication; no desktop initialization was requested"
        } else {
            "VNC did not advertise None authentication"
        }, Vec::new(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

})

}
}).await,
        ServiceKind::Rdp => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {

    let request = [3, 0, 0, 19, 14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 11, 0, 0, 0];
    stream.write_all(&request).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let response = ({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?;
    let selected = response
        .windows(8)
        .find(|part| part[0] == 2 && part[2] == 8)
        .map(|part| u32::from_le_bytes([part[4], part[5], part[6], part[7]]));
    let nla = selected.is_some_and(|value| value & (2 | 8) != 0);
    Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, ServiceKind::Rdp, "RDP security negotiation", if nla {
            ServiceAccessStatus::Protected
        } else if selected.is_some() {
            ServiceAccessStatus::Offered
        } else {
            ServiceAccessStatus::Inconclusive
        }, if nla {
            "RDP negotiation selected a Network Level Authentication protocol"
        } else if selected.is_some() {
            "RDP negotiation did not require Network Level Authentication"
        } else {
            "RDP security selection was not recognized"
        }, Vec::new(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

})

}
}).await,
        ServiceKind::Smtp => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {
let inlined_result: Result < ServiceAccessResult , String > = {

    let greeting = {
let (value,): (Vec < u8 >,) = (({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?,);
{

    String::from_utf8_lossy(&value).into_owned()

}

};
    stream
        .write_all(b"EHLO scanner.invalid\r\n")
        .await
        .map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let captured_capabilities = {
let (value,): (Vec < u8 >,) = (({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?,);
{

    String::from_utf8_lossy(&value).into_owned()

}

};
    let capabilities = captured_capabilities.to_ascii_uppercase();
    let auth = {
let (capabilities,): (& str,) = (&capabilities,);
let inlined_result: Vec < String > = {

    capabilities
        .lines()
        .filter_map(|line| line.split_once("AUTH").map(|(_, value)| value))
        .flat_map(|value| {
            value
                .trim_start_matches(['=', ' '])
                .split_ascii_whitespace()
        })
        .filter(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .map(str::to_owned)
        .collect()

};
inlined_result
};
    let _ = stream.write_all(b"QUIT\r\n").await;
    let mut observation = {
let (ip, port, service, method, capabilities, auth,): (IpAddr, u16, ServiceKind, & str, & str, Vec < String >,) = (ip, port, ServiceKind::Smtp, "EHLO capabilities", &capabilities, auth,);
let inlined_result: ServiceAccessResult = {

    let upgrade = capabilities.contains("STARTTLS") || capabilities.contains("STLS");
    let cleartext = auth
        .iter()
        .any(|value| matches!(value.as_str(), "PLAIN" | "LOGIN"));
    let mut evidence = Vec::new();
    if !auth.is_empty() {
        evidence.push(format!(
            "Advertised authentication mechanisms: {}",
            auth.join(", ")
        ));
    }
    if upgrade {
        evidence.push("Transport security upgrade advertised".to_owned());
    }
    {
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, service, method, if cleartext {
            ServiceAccessStatus::Offered
        } else {
            ServiceAccessStatus::Protected
        }, if cleartext {
            "Pre-authentication capabilities offer cleartext password mechanisms; no credentials were tested"
        } else {
            "No cleartext password mechanism was identified in the bounded capability response"
        }, evidence,);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

}

};
inlined_result
};
    observation.evidence.push(greeting);
    observation.evidence.push(captured_capabilities);
    Ok(observation)

};
inlined_result
}
}).await,
        ServiceKind::Imap => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {

    let greeting = {
let (value,): (Vec < u8 >,) = (({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?,);
{

    String::from_utf8_lossy(&value).into_owned()

}

};
    stream
        .write_all(b"a001 CAPABILITY\r\n")
        .await
        .map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let captured_capabilities = {
let (value,): (Vec < u8 >,) = (({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?,);
{

    String::from_utf8_lossy(&value).into_owned()

}

};
    let capabilities = captured_capabilities.to_ascii_uppercase();
    let auth = capabilities
        .split_ascii_whitespace()
        .filter_map(|value| value.strip_prefix("AUTH="))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let _ = stream.write_all(b"a002 LOGOUT\r\n").await;
    let mut observation = {
let (ip, port, service, method, capabilities, auth,): (IpAddr, u16, ServiceKind, & str, & str, Vec < String >,) = (ip, port, ServiceKind::Imap, "CAPABILITY", &capabilities, auth,);
let inlined_result: ServiceAccessResult = {

    let upgrade = capabilities.contains("STARTTLS") || capabilities.contains("STLS");
    let cleartext = auth
        .iter()
        .any(|value| matches!(value.as_str(), "PLAIN" | "LOGIN"));
    let mut evidence = Vec::new();
    if !auth.is_empty() {
        evidence.push(format!(
            "Advertised authentication mechanisms: {}",
            auth.join(", ")
        ));
    }
    if upgrade {
        evidence.push("Transport security upgrade advertised".to_owned());
    }
    {
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, service, method, if cleartext {
            ServiceAccessStatus::Offered
        } else {
            ServiceAccessStatus::Protected
        }, if cleartext {
            "Pre-authentication capabilities offer cleartext password mechanisms; no credentials were tested"
        } else {
            "No cleartext password mechanism was identified in the bounded capability response"
        }, evidence,);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

}

};
inlined_result
};
    observation.evidence.push(greeting);
    observation.evidence.push(captured_capabilities);
    Ok(observation)

}
}).await,
        ServiceKind::Pop3 => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {

    let greeting = {
let (value,): (Vec < u8 >,) = (({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?,);
{

    String::from_utf8_lossy(&value).into_owned()

}

};
    stream.write_all(b"CAPA\r\n").await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let captured_capabilities = {
let (value,): (Vec < u8 >,) = (({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?,);
{

    String::from_utf8_lossy(&value).into_owned()

}

};
    let capabilities = captured_capabilities.to_ascii_uppercase();
    let auth = capabilities
        .lines()
        .find_map(|line| line.strip_prefix("SASL "))
        .map(|line| line.split_ascii_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    let _ = stream.write_all(b"QUIT\r\n").await;
    let mut observation =
        {
let (ip, port, service, method, capabilities, auth,): (IpAddr, u16, ServiceKind, & str, & str, Vec < String >,) = (ip, port, ServiceKind::Pop3, "CAPA", &capabilities, auth,);
let inlined_result: ServiceAccessResult = {

    let upgrade = capabilities.contains("STARTTLS") || capabilities.contains("STLS");
    let cleartext = auth
        .iter()
        .any(|value| matches!(value.as_str(), "PLAIN" | "LOGIN"));
    let mut evidence = Vec::new();
    if !auth.is_empty() {
        evidence.push(format!(
            "Advertised authentication mechanisms: {}",
            auth.join(", ")
        ));
    }
    if upgrade {
        evidence.push("Transport security upgrade advertised".to_owned());
    }
    {
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, service, method, if cleartext {
            ServiceAccessStatus::Offered
        } else {
            ServiceAccessStatus::Protected
        }, if cleartext {
            "Pre-authentication capabilities offer cleartext password mechanisms; no credentials were tested"
        } else {
            "No cleartext password mechanism was identified in the bounded capability response"
        }, evidence,);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

}

};
inlined_result
};
    observation.evidence.push(greeting);
    observation.evidence.push(captured_capabilities);
    Ok(observation)

}
}).await,
        ServiceKind::PostgreSql => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {

    stream
        .write_all(&[0, 0, 0, 8, 4, 210, 22, 47])
        .await
        .map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let response = ({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?;
    Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, ServiceKind::PostgreSql, "SSLRequest", if matches!(response.first(), Some(b'S' | b'N')) {
            ServiceAccessStatus::Offered
        } else {
            ServiceAccessStatus::Inconclusive
        }, "PostgreSQL pre-authentication transport method recorded; no startup credentials or query were sent", Vec::new(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

})

}
}).await,
        ServiceKind::Mysql => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {

    let greeting = ({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?;
    if greeting.len() < 5 || greeting[4] != 10 {
        return Err("MySQL handshake was not recognized".to_owned());
    }
    let capabilities = 0x0008_8200u32;
    let mut packet = [0u8; 60];
    packet[..4].copy_from_slice(&[56, 0, 0, 1]);
    packet[4..8].copy_from_slice(&capabilities.to_le_bytes());
    packet[8..12].copy_from_slice(&0x0100_0000u32.to_le_bytes());
    packet[12] = 45;
    packet[38..].copy_from_slice(b"mysql_native_password\0");
    stream.write_all(&packet).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let response = ({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?;
    let marker = response.get(4).copied();
    let accepted = marker == Some(0);
    if accepted {
        let _ = stream.write_all(&[1, 0, 0, 0, 1]).await;
    }
    Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, ServiceKind::Mysql, "Empty anonymous login", if accepted {
            ServiceAccessStatus::Confirmed
        } else if marker == Some(0xff) {
            ServiceAccessStatus::Protected
        } else {
            ServiceAccessStatus::Inconclusive
        }, if accepted {
            "MySQL accepted an empty anonymous login; no data query was issued"
        } else {
            "MySQL did not confirm anonymous access; no credentials were guessed"
        }, exposure_probe::mysql_banner_version(&greeting)
            .map(|identity| vec![format!("Server handshake identity: {identity}")])
            .unwrap_or_default(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

})

}
}).await,
        ServiceKind::MongoDb => Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, service, "Pre-authentication observation", ServiceAccessStatus::Inconclusive, "No MongoDB data or enumeration command was sent", Vec::new(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

}),
        ServiceKind::Rsync => Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, service, "Daemon greeting", ServiceAccessStatus::Offered, "rsync service negotiation was observed without enumerating modules", Vec::new(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

}),
        ServiceKind::Rtsp => ({
let (stream, ip, port, hostname,): (& mut TcpStream, IpAddr, u16, & str,) = (stream, ip, port, hostname,);
async move {
let inlined_result: Result < ServiceAccessResult , String > = {

    let request = format!(
        "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: nancywebdebug\r\nHost: {hostname}\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let response = ({
let (stream,): (& mut TcpStream,) = (stream,);
async move {
let inlined_result: Result < Vec < u8 > , String > = {

    let mut value = vec![0u8; READ_LIMIT];
    let length = stream.read(&mut value).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    value.truncate(length);
    Ok(value)

};
inlined_result
}
}).await?;
    let status = {
let (response,): (& [u8],) = (&response,);
{
'inlined_rtsp_status: {

    let line_end = match response.windows(2).position(|window| window == b"\r\n") { Some(value) => value, None => break 'inlined_rtsp_status None };
    let first_line = match std::str::from_utf8(&response[..line_end]).ok() { Some(value) => value, None => break 'inlined_rtsp_status None };
    let mut fields = first_line.split_ascii_whitespace();
    if !matches!(fields.next(), Some("RTSP/1.0" | "RTSP/2.0")) {
        break 'inlined_rtsp_status None;
    }
    let status = match fields.next() { Some(value) => value, None => break 'inlined_rtsp_status None };
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        break 'inlined_rtsp_status None;
    }
    let status = match status.parse().ok() { Some(value) => value, None => break 'inlined_rtsp_status None };
    (100..=699).contains(&status).then_some(status)

}
}

};
    Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, ServiceKind::Rtsp, "OPTIONS *", match status {
            Some(401 | 403 | 407) => ServiceAccessStatus::Protected,
            Some(_) => ServiceAccessStatus::Offered,
            None => ServiceAccessStatus::Inconclusive,
        }, "RTSP signalling was checked without DESCRIBE, SETUP, PLAY, or media access", status
            .map(|status| vec![format!("RTSP status {status}")])
            .unwrap_or_default(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

})

};
inlined_result
}
}).await,
        ServiceKind::Rtmp => ({
let (stream, ip, port,): (& mut TcpStream, IpAddr, u16,) = (stream, ip, port,);
async move {
let inlined_result: Result < ServiceAccessResult , String > = {

    let mut handshake = [0u8; 1537];
    handshake[0] = 3;
    for (index, byte) in handshake[9..].iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    stream.write_all(&handshake).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let mut response = vec![0u8; 3073];
    stream.read_exact(&mut response).await.map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    let recognized = {
let (response, request,): (& [u8], & [u8],) = (&response, &handshake,);
{

    response.len() == 3073
        && request.len() == 1537
        && response[0] == 3
        && response[1537..1541] == request[1..5]
        && response[1545..3073] == request[9..1537]

}

};
    if recognized {
        stream
            .write_all(&response[1..1537])
            .await
            .map_err(|error: std :: io :: Error| {
    error.to_string()
})?;
    }
    Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, ServiceKind::Rtmp, "RTMP C0/C1 handshake", if recognized {
            ServiceAccessStatus::Offered
        } else {
            ServiceAccessStatus::Inconclusive
        }, "RTMP protocol negotiation was attempted without a stream key or media request", if recognized {
            vec!["RTMP version 3 S0/S1/S2 handshake response".to_owned()]
        } else {
            Vec::new()
        },);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

})

};
inlined_result
}
}).await,
        _ => Ok({
let (ip, port, service, method, status, summary, evidence,): (IpAddr, u16, ServiceKind, & str, ServiceAccessStatus, & str, Vec < String >,) = (ip, port, service, "Pre-authentication observation", ServiceAccessStatus::Inconclusive, "The protocol cannot prove access without enumeration or a data operation", Vec::new(),);
{

    ServiceAccessResult {
        ip,
        port,
        transport: TransportProtocol::Tcp,
        service,
        method: method.to_owned(),
        status,
        summary: summary.to_owned(),
        evidence,
    }

}

}),
    }
}

pub(super) fn access_finding(result: &ServiceAccessResult) -> Option<ExposureFinding> {
    if matches!(
        result.service,
        ServiceKind::WebSocket | ServiceKind::Rtsp | ServiceKind::Rtmp
    ) {
        return (result.status == ServiceAccessStatus::Offered).then(|| {
            public_stream_finding(
                result.ip,
                result.port,
                result.transport,
                &result.service.to_string(),
                &result.method,
                result.evidence.clone(),
            )
        });
    }
    if result.status != ServiceAccessStatus::Confirmed
        || !matches!(
            result.service,
            ServiceKind::Ftp
                | ServiceKind::Ldap
                | ServiceKind::Smb
                | ServiceKind::Redis
                | ServiceKind::Memcached
                | ServiceKind::Mqtt
                | ServiceKind::Vnc
                | ServiceKind::Mysql
        )
    {
        return None;
    }
    Some(ExposureFinding {
        title: format!("Unauthenticated {} access confirmed", result.service),
        description: result.summary.clone(),
        ip: result.ip,
        port: result.port,
        transport: result.transport,
        evidence: result.evidence.clone(),
        component_kind: None,
    })
}
