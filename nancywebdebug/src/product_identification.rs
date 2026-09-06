use super::*;

const IDENTIFICATION_LIMIT: usize = 2;
const MONGO_REQUEST_ID: i32 = 0x4e414e43;

pub(in crate::exposure) fn record_text(endpoint: &mut EndpointScan, text: &str, source: &str) {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(identity) = line
            .strip_prefix("SSH-2.0-")
            .or_else(|| line.strip_prefix("SSH-1.99-"))
        {
            let token = identity.split_whitespace().next().unwrap_or_default();
            for (marker, name) in [("openssh", "OpenSSH"), ("dropbear", "Dropbear")] {
                if token.to_ascii_lowercase() == marker
                    || token
                        .to_ascii_lowercase()
                        .starts_with(&format!("{marker}_"))
                {
                    add_product(
                        endpoint,
                        name,
                        ProductLayer::Protocol,
                        {
                            let (text, marker): (&str, &str) = (token, marker);
                            let inlined_result: Option<String> = {
                                'inlined_version_after: {
                                    let lower = text.to_ascii_lowercase();
                                    let offset = match lower.find(marker) {
                                        Some(value) => value,
                                        None => break 'inlined_version_after None,
                                    } + marker.len();
                                    let tail = text[offset..]
                                        .trim_start_matches([' ', '/', '_', '-', '(', 'v', 'V']);
                                    let version = tail
                                        .chars()
                                        .take_while(|c| {
                                            c.is_ascii_alphanumeric()
                                                || matches!(c, '.' | '-' | '_')
                                        })
                                        .collect::<String>();
                                    version
                                        .starts_with(|c: char| c.is_ascii_digit())
                                        .then_some(version)
                                }
                            };
                            inlined_result
                        },
                        Confidence::High,
                        format!("{source}: {line}"),
                    );
                }
            }
        }
        let greeting = lower.starts_with("220 ")
            || lower.starts_with("220-")
            || lower.starts_with("250 ")
            || lower.starts_with("250-")
            || lower.starts_with("211")
            || lower.starts_with("215")
            || lower.starts_with("* ok")
            || lower.starts_with("* capability")
            || lower.starts_with("+ok");
        if !greeting {
            continue;
        }
        for (marker, name) in [
            ("postfix", "Postfix"),
            ("exim", "Exim"),
            ("dovecot", "Dovecot"),
            ("cyrus imap4", "Cyrus IMAP"),
            ("cyrus imap", "Cyrus IMAP"),
            ("cyrus pop3", "Cyrus IMAP"),
            ("vsftpd", "vsftpd"),
            ("proftpd", "ProFTPD"),
            ("pure-ftpd", "Pure-FTPd"),
            ("filezilla server", "FileZilla Server"),
        ] {
            let explicit = lower.match_indices(marker).any(|(offset, _)| {
                let before = lower[..offset].chars().next_back();
                let after = lower[offset + marker.len()..].chars().next();
                !before.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
                    && !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '.')
            });
            if explicit {
                let version = ({
                    let (text, marker): (&str, &str) = (line, marker);
                    let inlined_result: Option<String> = {
                        'inlined_version_after: {
                            let lower = text.to_ascii_lowercase();
                            let offset = match lower.find(marker) {
                                Some(value) => value,
                                None => break 'inlined_version_after None,
                            } + marker.len();
                            let tail = text[offset..]
                                .trim_start_matches([' ', '/', '_', '-', '(', 'v', 'V']);
                            let version = tail
                                .chars()
                                .take_while(|c| {
                                    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')
                                })
                                .collect::<String>();
                            version
                                .starts_with(|c: char| c.is_ascii_digit())
                                .then_some(version)
                        }
                    };
                    inlined_result
                })
                .or_else(|| {
                    (name == "Cyrus IMAP")
                        .then(|| {
                            let (text, marker): (&str, &str) = (line, "cyrus imap4");
                            let inlined_result: Option<String> = {
                                'inlined_version_after: {
                                    let lower = text.to_ascii_lowercase();
                                    let offset = match lower.find(marker) {
                                        Some(value) => value,
                                        None => break 'inlined_version_after None,
                                    } + marker.len();
                                    let tail = text[offset..]
                                        .trim_start_matches([' ', '/', '_', '-', '(', 'v', 'V']);
                                    let version = tail
                                        .chars()
                                        .take_while(|c| {
                                            c.is_ascii_alphanumeric()
                                                || matches!(c, '.' | '-' | '_')
                                        })
                                        .collect::<String>();
                                    version
                                        .starts_with(|c: char| c.is_ascii_digit())
                                        .then_some(version)
                                }
                            };
                            inlined_result
                        })
                        .flatten()
                });
                add_product(
                    endpoint,
                    name,
                    ProductLayer::Server,
                    version,
                    Confidence::High,
                    format!("{source}: {line}"),
                );
            }
        }
    }
}

pub(super) fn record_mysql(endpoint: &mut EndpointScan, identity: &str) {
    let lower = identity.to_ascii_lowercase();
    let maria = lower.contains("mariadb");
    let name = if maria { "MariaDB" } else { "MySQL" };
    let version = if maria {
        identity
            .strip_prefix("5.5.5-")
            .unwrap_or(identity)
            .split('-')
            .next()
            .map(str::to_owned)
    } else {
        Some(identity.to_owned())
    };
    add_product(
        endpoint,
        name,
        ProductLayer::Protocol,
        version,
        Confidence::High,
        format!("Server handshake identity: {identity}"),
    );
}

fn redis_info(bytes: &[u8]) -> Result<Option<(&'static str, Option<String>)>, String> {
    let body = ({
        let (bytes,): (&[u8],) = (bytes,);
        let inlined_result: Result<&str, String> = {
            'inlined_resp_body: {
                let text = match std::str::from_utf8(bytes).map_err(|_| "Invalid INFO text") {
                    Ok(value) => value,
                    Err(error) => break 'inlined_resp_body Err(::core::convert::From::from(error)),
                };
                if text.starts_with('-') {
                    break 'inlined_resp_body Err(text.trim().to_owned());
                }
                let (header, body) = match text.split_once("\r\n").ok_or("Truncated INFO framing") {
                    Ok(value) => value,
                    Err(error) => break 'inlined_resp_body Err(::core::convert::From::from(error)),
                };
                let length = match header
                    .strip_prefix('$')
                    .and_then(|n| n.parse::<usize>().ok())
                    .ok_or("Invalid INFO bulk-string framing")
                {
                    Ok(value) => value,
                    Err(error) => break 'inlined_resp_body Err(::core::convert::From::from(error)),
                };
                if body.len()
                    != match length.checked_add(2).ok_or("Invalid INFO length") {
                        Ok(value) => value,
                        Err(error) => {
                            break 'inlined_resp_body Err(::core::convert::From::from(error));
                        }
                    }
                    || !body.ends_with("\r\n")
                {
                    break 'inlined_resp_body Err("Truncated or malformed INFO reply".to_owned());
                }
                body.get(..length)
                    .ok_or_else(|| "Invalid INFO encoding".to_owned())
            }
        };
        inlined_result
    })?;
    let fields = body
        .lines()
        .filter_map(|line| line.split_once(':'))
        .collect::<HashMap<_, _>>();
    if !body.lines().any(|line| line == "# Server") {
        return Ok(None);
    }
    let explicit = fields
        .get("server_name")
        .map(|name| name.to_ascii_lowercase());
    let (name, key) = match explicit.as_deref() {
        Some("valkey") => ("Valkey", "valkey_version"),
        Some("redis") => ("Redis", "redis_version"),
        Some(_) => return Ok(None),
        None if fields.contains_key("valkey_version") => ("Valkey", "valkey_version"),
        None if fields.contains_key("redis_version") => ("Redis", "redis_version"),
        _ => return Ok(None),
    };
    let version = fields
        .get(key)
        .or_else(|| explicit.as_ref().and_then(|_| fields.get("server_version")))
        .filter(|value| value.starts_with(|c: char| c.is_ascii_digit()))
        .map(|value| (*value).to_owned());
    Ok(Some((name, version)))
}

pub(in crate::exposure) fn record_service_results(
    endpoint: &mut EndpointScan,
    results: &[ServiceAccessResult],
) {
    let (ip, port, transport) = (endpoint.ip, endpoint.port, endpoint.transport);
    for result in results
        .iter()
        .filter(|r| r.ip == ip && r.port == port && r.transport == transport)
    {
        for evidence in &result.evidence {
            record_text(endpoint, evidence, "Service observation");
            if let Some(identity) = evidence.strip_prefix("Server handshake identity: ") {
                record_mysql(endpoint, identity);
            }
            if let Ok(Some((name, version))) = redis_info(evidence.as_bytes()) {
                add_product(
                    endpoint,
                    name,
                    ProductLayer::Server,
                    version,
                    Confidence::High,
                    "Captured INFO server implementation identity".to_owned(),
                );
            }
        }
    }
}

fn http_identity(response: &HttpObservation, name: &str) -> Option<Option<String>> {
    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    let json = (!response.body_truncated)
        .then(|| serde_json::from_slice::<serde_json::Value>(&response.body).ok())
        .flatten();
    let path = Url::parse(&response.url)
        .ok()
        .map(|url| url.path().to_owned())
        .unwrap_or_default();
    match name {
        "RabbitMQ" => {
            if let Some(json) = &json
                && let Some(version) = json.get("rabbitmq_version").and_then(|v| v.as_str())
            {
                return Some(Some(version.to_owned()));
            }
            (lower.contains("<title>rabbitmq management</title>")
                || ({
                    let (response, name): (&crate::HttpObservation, &str) =
                        (response, "www-authenticate");
                    response
                        .headers
                        .iter()
                        .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.as_str())
                })
                .any(|v| {
                    v.to_ascii_lowercase()
                        .contains("realm=\"rabbitmq management\"")
                }))
            .then_some(None)
        }
        "Prometheus" => {
            if path == "/api/v1/status/buildinfo"
                && (200..300).contains(&response.status)
                && let Some(json) = &json
                && json.get("status").and_then(|v| v.as_str()) == Some("success")
                && let Some(data) = json.get("data")
                && data.get("revision").is_some_and(|v| v.is_string())
                && data.get("goVersion").is_some_and(|v| v.is_string())
                && let Some(version) = data.get("version").and_then(|v| v.as_str())
            {
                return Some(Some(version.to_owned()));
            }
            (lower
                .contains("<title>prometheus time series collection and processing server</title>")
                || lower.contains("<title>prometheus</title>"))
            .then_some(None)
        }
        "OpenSearch" => {
            let json = json?;
            let version = json.get("version")?;
            (version.get("distribution").and_then(|v| v.as_str()) == Some("opensearch")).then(
                || {
                    version
                        .get("number")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                },
            )
        }
        _ => None,
    }
}

pub(in crate::exposure) fn record_captured(endpoint: &mut EndpointScan, cancel: &CancellationToken) {
    if cancel.is_cancelled() {
        return;
    }
    record_text(
        endpoint,
        &String::from_utf8_lossy(&endpoint.banner).into_owned(),
        "Greeting",
    );
    if let Some(identity) = mysql_banner_version(&endpoint.banner) {
        record_mysql(endpoint, &identity);
    } else if endpoint.banner.get(4) == Some(&10) {
        ({
            let (endpoint, name, reason): (&mut EndpointScan, &str, _) = (
                endpoint,
                "MySQL",
                "Malformed or truncated MySQL-compatible greeting; implementation identity unverified",
            );

            add_product(
                endpoint,
                name,
                ProductLayer::Server,
                None,
                Confidence::Low,
                reason.into(),
            );
        });
    }
    if let Ok(Some((name, version))) = redis_info(&endpoint.banner) {
        add_product(
            endpoint,
            name,
            ProductLayer::Server,
            version,
            Confidence::High,
            "Captured INFO server identity".to_owned(),
        );
    }
    for response in endpoint.http.clone() {
        if cancel.is_cancelled() {
            return;
        }
        if Url::parse(&response.url)
            .ok()
            .and_then(|url| url.port_or_known_default())
            != Some(endpoint.port)
        {
            continue;
        }
        for probe in MANAGEMENT_PRODUCT_PROBES {
            if management_fingerprint(probe.kind, &response) {
                add_product(
                    endpoint,
                    probe.product,
                    ProductLayer::Server,
                    management_version(probe.kind, &response),
                    Confidence::High,
                    format!(
                        "{} signature at {} (HTTP {})",
                        probe.product, response.url, response.status
                    ),
                );
            }
        }
        for name in ["RabbitMQ", "Prometheus", "OpenSearch"] {
            if let Some(version) = http_identity(&response, name) {
                add_product(
                    endpoint,
                    name,
                    ProductLayer::Server,
                    version,
                    Confidence::High,
                    format!(
                        "{name} implementation signature at {} (HTTP {})",
                        response.url, response.status
                    ),
                );
            }
        }
    }
}

pub(super) async fn probe(endpoint: &mut EndpointScan, context: ProbeContext<'_>) {
    record_captured_async(endpoint, context.scan.cancel).await;
    let mut remaining = IDENTIFICATION_LIMIT;
    if endpoint.state != PortState::Open || endpoint.transport != TransportProtocol::Tcp {
        return;
    }
    if endpoint.service == ServiceKind::Redis
        && !({
            let (endpoint, names): (&EndpointScan, &[&str]) = (endpoint, &["Redis", "Valkey"]);
            {
                endpoint.products.iter().any(|product| {
                    product.confidence >= Confidence::Medium
                        && names.contains(&product.name.as_str())
                })
            }
        })
    {
        if {
            let (endpoint,): (&EndpointScan,) = (endpoint,);
            {
                endpoint
                    .http
                    .iter()
                    .any(|r| matches!(r.status, 401 | 403 | 407))
                    || endpoint.evidence.iter().any(|e| {
                        let lower = e.to_ascii_lowercase();
                        lower.contains("-noauth")
                            || lower.contains("-noperm")
                            || lower.contains("-wrongpass")
                    })
            }
        } {
            ({
                let (endpoint, name, reason): (&mut EndpointScan, &str, _) = (
                    endpoint,
                    "Redis",
                    "Redis-compatible response rejected authentication; INFO server was not sent; implementation unknown",
                );

                add_product(
                    endpoint,
                    name,
                    ProductLayer::Server,
                    None,
                    Confidence::Low,
                    reason.into(),
                );
            });
        } else {
            remaining -= 1;
            match ({
let (context, payload, mongo,): (ProbeContext < '_ >, & [u8], bool,) = (context, b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n", false,);
async move {

    let mut candidate = limited_connect(context).await;
    let mut stream = candidate.stream.take().ok_or_else(|| {
        candidate
            .attempt
            .error
            .unwrap_or_else(|| "Identification connection failed or cancelled".to_owned())
    })?;
    let operation = async {
        stream.write_all(payload).await.map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        loop {
            if bytes.len() >= MAX_HTTP_BODY_BYTES {
                return Err("Response truncated at identification size limit".to_owned());
            }
            let mut chunk = vec![0; (MAX_HTTP_BODY_BYTES - bytes.len()).min(MAX_BANNER_BYTES)];
            let count = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if count == 0 {
                return Err("Truncated identification reply: connection closed".to_owned());
            }
            bytes.extend_from_slice(&chunk[..count]);
            let expected = if mongo {
                if bytes.len() < 4 {
                    None
                } else {
                    let length = i32::from_le_bytes(bytes[..4].try_into().unwrap());
                    if length < 26 {
                        return Err("Malformed MongoDB frame length".to_owned());
                    }
                    Some(length as usize)
                }
            } else if bytes.starts_with(b"-") {
                if bytes.ends_with(b"\r\n") {
                    return Ok(bytes);
                } else {
                    None
                }
            } else if let Some(end) = bytes.windows(2).position(|w| w == b"\r\n") {
                let length = std::str::from_utf8(&bytes[..end])
                    .ok()
                    .and_then(|s| s.strip_prefix('$'))
                    .and_then(|s| s.parse::<usize>().ok())
                    .ok_or("Malformed INFO framing")?;
                Some(length.checked_add(end + 4).ok_or("Invalid INFO length")?)
            } else {
                None
            };
            if let Some(expected) = expected {
                if expected > MAX_HTTP_BODY_BYTES {
                    return Err(
                        "Response truncated: declared length exceeds identification size limit"
                            .to_owned(),
                    );
                }
                if bytes.len() >= expected {
                    return Ok(bytes);
                }
            }
        }
    };
    tokio::select! {
        _ = context.scan.cancel.cancelled() => Err("Identification cancelled".to_owned()),
        result = tokio::time::timeout(context.scan.request.probe_timeout, operation) => result.map_err(|_| "Identification probe timed out before a complete reply".to_owned())?,
    }

}
})
                .await
                .and_then(|bytes| redis_info(&bytes).map(|identity| (identity, bytes)))
            {
                Ok((Some((name, version)), bytes)) => add_product(
                    endpoint,
                    name,
                    ProductLayer::Server,
                    version,
                    Confidence::High,
                    format!(
                        "INFO server implementation identity: {}",
                        escaped_evidence(&bytes)
                    ),
                ),
                Ok(_) => {
let (endpoint, name, reason,): (& mut EndpointScan, & str, _,) = (endpoint, "Redis", "INFO server did not disclose a recognized implementation identity",);

    add_product(
        endpoint,
        name,
        ProductLayer::Server,
        None,
        Confidence::Low,
        reason.into(),
    );

},
                Err(reason) => {
                    ({
let (endpoint, name, reason,): (& mut EndpointScan, & str, _,) = (endpoint, "Redis", format!("INFO server: {reason}"),);

    add_product(
        endpoint,
        name,
        ProductLayer::Server,
        None,
        Confidence::Low,
        reason.into(),
    );

});
                    return;
                }
            }
        }
    }
    if (crate::product_catalog::associated_port("MongoDB") == Some(endpoint.port)
        || endpoint.service == ServiceKind::MongoDb)
        && !({
            let (endpoint, names): (&EndpointScan, &[&str]) = (endpoint, &["MongoDB"]);
            {
                endpoint.products.iter().any(|product| {
                    product.confidence >= Confidence::Medium
                        && names.contains(&product.name.as_str())
                })
            }
        })
    {
        if remaining == 0 {
            ({
                let (endpoint, name, reason): (&mut EndpointScan, &str, _) = (
                    endpoint,
                    "MongoDB",
                    "Identification request limit (2 per endpoint) reached",
                );

                add_product(
                    endpoint,
                    name,
                    ProductLayer::Server,
                    None,
                    Confidence::Low,
                    reason.into(),
                );
            });
        } else if !({
            let (endpoint,): (&EndpointScan,) = (endpoint,);
            {
                endpoint
                    .http
                    .iter()
                    .any(|r| matches!(r.status, 401 | 403 | 407))
                    || endpoint.evidence.iter().any(|e| {
                        let lower = e.to_ascii_lowercase();
                        lower.contains("-noauth")
                            || lower.contains("-noperm")
                            || lower.contains("-wrongpass")
                    })
            }
        }) {
            remaining -= 1;
            let mongo_payload = {
                let inlined_result: Vec<u8> = {
                    let document = b"\x1f\0\0\0\x10hello\0\x01\0\0\0\x02$db\0\x06\0\0\0admin\0\0";
                    let mut packet = Vec::new();
                    packet.extend_from_slice(&(21i32 + document.len() as i32).to_le_bytes());
                    packet.extend_from_slice(&MONGO_REQUEST_ID.to_le_bytes());
                    packet.extend_from_slice(&0i32.to_le_bytes());
                    packet.extend_from_slice(&2013i32.to_le_bytes());
                    packet.extend_from_slice(&[0; 5]);
                    packet.extend_from_slice(document);
                    packet
                };
                inlined_result
            };
            match ({
let (context, payload, mongo,): (ProbeContext < '_ >, & [u8], bool,) = (context, &mongo_payload, true,);
async move {

    let mut candidate = limited_connect(context).await;
    let mut stream = candidate.stream.take().ok_or_else(|| {
        candidate
            .attempt
            .error
            .unwrap_or_else(|| "Identification connection failed or cancelled".to_owned())
    })?;
    let operation = async {
        stream.write_all(payload).await.map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        loop {
            if bytes.len() >= MAX_HTTP_BODY_BYTES {
                return Err("Response truncated at identification size limit".to_owned());
            }
            let mut chunk = vec![0; (MAX_HTTP_BODY_BYTES - bytes.len()).min(MAX_BANNER_BYTES)];
            let count = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if count == 0 {
                return Err("Truncated identification reply: connection closed".to_owned());
            }
            bytes.extend_from_slice(&chunk[..count]);
            let expected = if mongo {
                if bytes.len() < 4 {
                    None
                } else {
                    let length = i32::from_le_bytes(bytes[..4].try_into().unwrap());
                    if length < 26 {
                        return Err("Malformed MongoDB frame length".to_owned());
                    }
                    Some(length as usize)
                }
            } else if bytes.starts_with(b"-") {
                if bytes.ends_with(b"\r\n") {
                    return Ok(bytes);
                } else {
                    None
                }
            } else if let Some(end) = bytes.windows(2).position(|w| w == b"\r\n") {
                let length = std::str::from_utf8(&bytes[..end])
                    .ok()
                    .and_then(|s| s.strip_prefix('$'))
                    .and_then(|s| s.parse::<usize>().ok())
                    .ok_or("Malformed INFO framing")?;
                Some(length.checked_add(end + 4).ok_or("Invalid INFO length")?)
            } else {
                None
            };
            if let Some(expected) = expected {
                if expected > MAX_HTTP_BODY_BYTES {
                    return Err(
                        "Response truncated: declared length exceeds identification size limit"
                            .to_owned(),
                    );
                }
                if bytes.len() >= expected {
                    return Ok(bytes);
                }
            }
        }
    };
    tokio::select! {
        _ = context.scan.cancel.cancelled() => Err("Identification cancelled".to_owned()),
        result = tokio::time::timeout(context.scan.request.probe_timeout, operation) => result.map_err(|_| "Identification probe timed out before a complete reply".to_owned())?,
    }

}
})
                .await
                .and_then(|bytes| {
let (bytes,): (& [u8],) = (&bytes,);
let inlined_result: Result < serde_json :: Value , String > = {
'inlined_mongo_response: {

    let invalid = || "Malformed or truncated MongoDB hello reply".to_owned();
    if ({
let (bytes, offset,): (& [u8], usize,) = (bytes, 0,);
{
'inlined_read_i32: {

    Some(i32::from_le_bytes(
        match match bytes.get(offset..match offset.checked_add(4) { Some(value) => value, None => break 'inlined_read_i32 None }) { Some(value) => value, None => break 'inlined_read_i32 None }.try_into().ok() { Some(value) => value, None => break 'inlined_read_i32 None },
    ))

}
}

}) != Some(bytes.len() as i32)
        || ({
let (bytes, offset,): (& [u8], usize,) = (bytes, 8,);
{
'inlined_read_i32: {

    Some(i32::from_le_bytes(
        match match bytes.get(offset..match offset.checked_add(4) { Some(value) => value, None => break 'inlined_read_i32 None }) { Some(value) => value, None => break 'inlined_read_i32 None }.try_into().ok() { Some(value) => value, None => break 'inlined_read_i32 None },
    ))

}
}

}) != Some(MONGO_REQUEST_ID)
        || ({
let (bytes, offset,): (& [u8], usize,) = (bytes, 12,);
{
'inlined_read_i32: {

    Some(i32::from_le_bytes(
        match match bytes.get(offset..match offset.checked_add(4) { Some(value) => value, None => break 'inlined_read_i32 None }) { Some(value) => value, None => break 'inlined_read_i32 None }.try_into().ok() { Some(value) => value, None => break 'inlined_read_i32 None },
    ))

}
}

}) != Some(2013)
    {
        break 'inlined_mongo_response Err(invalid());
    }
    let flags = match ({
let (bytes, offset,): (& [u8], usize,) = (bytes, 16,);
{
'inlined_read_i32: {

    Some(i32::from_le_bytes(
        match match bytes.get(offset..match offset.checked_add(4) { Some(value) => value, None => break 'inlined_read_i32 None }) { Some(value) => value, None => break 'inlined_read_i32 None }.try_into().ok() { Some(value) => value, None => break 'inlined_read_i32 None },
    ))

}
}

}).ok_or_else(invalid) { Ok(value) => value, Err(error) => break 'inlined_mongo_response Err(::core::convert::From::from(error)) } as u32;
    if flags & 0xffff & !1 != 0 || bytes.get(20) != Some(&0) {
        break 'inlined_mongo_response Err(invalid());
    }
    let end = match bytes
        .len()
        .checked_sub(if flags & 1 != 0 { 4 } else { 0 })
        .ok_or_else(invalid) { Ok(value) => value, Err(error) => break 'inlined_mongo_response Err(::core::convert::From::from(error)) };
    if flags & 1 != 0 {
        let mut crc = !0u32;
        for byte in &bytes[..end] {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0x82f63b78u32 & 0u32.wrapping_sub(crc & 1));
            }
        }
        if ({
let (bytes, offset,): (& [u8], usize,) = (bytes, end,);
{
'inlined_read_i32: {

    Some(i32::from_le_bytes(
        match match bytes.get(offset..match offset.checked_add(4) { Some(value) => value, None => break 'inlined_read_i32 None }) { Some(value) => value, None => break 'inlined_read_i32 None }.try_into().ok() { Some(value) => value, None => break 'inlined_read_i32 None },
    ))

}
}

}).map(|n| n as u32) != Some(!crc) {
            break 'inlined_mongo_response Err("Invalid MongoDB checksum".to_owned());
        }
    }
    let json = match bson_document(match bytes.get(21..end).ok_or_else(invalid) { Ok(value) => value, Err(error) => break 'inlined_mongo_response Err(::core::convert::From::from(error)) }, 0).ok_or_else(invalid) { Ok(value) => value, Err(error) => break 'inlined_mongo_response Err(::core::convert::From::from(error)) };
    let ok = json.get("ok").and_then(|v| v.as_f64());
    let success = ok == Some(1.0)
        && json
            .get("maxWireVersion")
            .and_then(|v| v.as_i64())
            .is_some_and(|n| n >= 0)
        && json
            .get("minWireVersion")
            .and_then(|v| v.as_i64())
            .is_some_and(|n| n >= 0)
        && (json
            .get("isWritablePrimary")
            .is_some_and(|v| v.is_boolean())
            || json.get("ismaster").is_some_and(|v| v.is_boolean())
            || json.get("msg").and_then(|v| v.as_str()) == Some("isdbgrid"));
    let rejection = ok == Some(0.0)
        && json.get("code").and_then(|v| v.as_i64()).is_some()
        && json.get("errmsg").is_some_and(|v| v.is_string());
    if success || rejection {
        Ok(json)
    } else {
        Err("MongoDB reply lacks a valid hello response structure".to_owned())
    }

}
};
inlined_result
})
            {
                Ok(json) => {
                    if Confidence::High >= endpoint.service_confidence {
                        endpoint.service = ServiceKind::MongoDb;
                        endpoint.service_confidence = Confidence::High;
                    }
                    let evidence = "Validated MongoDB-compatible hello reply";
                    if !endpoint.evidence.iter().any(|item| item == evidence) {
                        endpoint.evidence.push(evidence.to_owned());
                    }
                    let explicit = json
                        .get("server_name")
                        .or_else(|| json.get("product"))
                        .and_then(|v| v.as_str())
                        .is_some_and(|name| name.eq_ignore_ascii_case("mongodb"));
                    add_product(endpoint, "MongoDB", ProductLayer::Server, if explicit { json.get("version").and_then(|v| v.as_str()).map(str::to_owned) } else { None }, if explicit { Confidence::High } else { Confidence::Low }, if explicit { "MongoDB hello explicitly identifies the implementation" } else { "Validated MongoDB-compatible hello; implementation identity undisclosed" }.to_owned());
                    if json.get("ok").and_then(|v| v.as_f64()) == Some(0.0) {
                        ({
let (endpoint, name, reason,): (& mut EndpointScan, & str, _,) = (endpoint, "MongoDB", format!(
                                "hello rejected: {}",
                                json.get("errmsg").unwrap_or(&serde_json::Value::Null)
                            ),);

    add_product(
        endpoint,
        name,
        ProductLayer::Server,
        None,
        Confidence::Low,
        reason.into(),
    );

});
                        return;
                    }
                }
                Err(reason) => {
let (endpoint, name, reason,): (& mut EndpointScan, & str, _,) = (endpoint, "MongoDB", format!("hello identification: {reason}"),);

    add_product(
        endpoint,
        name,
        ProductLayer::Server,
        None,
        Confidence::Low,
        reason.into(),
    );

},
            }
        }
    }
    let scheme = endpoint_scheme(endpoint).or_else(|| {
        (!({
            let (endpoint,): (&EndpointScan,) = (endpoint,);
            let inlined_result: Vec<(&'static str, &'static str)> = {
                [
                    ("RabbitMQ", "/api/overview"),
                    ("Prometheus", "/api/v1/status/buildinfo"),
                ]
                .into_iter()
                .filter(|(name, _)| {
                    crate::product_catalog::associated_port(name) == Some(endpoint.port)
                        || endpoint.products.iter().any(|p| p.name == *name)
                })
                .collect()
            };
            inlined_result
        })
        .is_empty()
            && matches!(endpoint.service, ServiceKind::Unknown | ServiceKind::Tls))
        .then_some(if endpoint.tls.iter().any(|t| t.supported) {
            "https"
        } else {
            "http"
        })
    });
    let Some(scheme) = scheme else {
        return;
    };
    for (name, path) in {
        let (endpoint,): (&EndpointScan,) = (endpoint,);
        let inlined_result: Vec<(&'static str, &'static str)> = {
            [
                ("RabbitMQ", "/api/overview"),
                ("Prometheus", "/api/v1/status/buildinfo"),
            ]
            .into_iter()
            .filter(|(name, _)| {
                crate::product_catalog::associated_port(name) == Some(endpoint.port)
                    || endpoint.products.iter().any(|p| p.name == *name)
            })
            .collect()
        };
        inlined_result
    } {
        if let Some(response) = endpoint.http.iter().find(|r| {
            r.method == "GET"
                && Url::parse(&r.url).ok().is_some_and(|u| {
                    u.path() == path && u.port_or_known_default() == Some(endpoint.port)
                })
        }) {
            let reason = ({
                let (response,): (&HttpObservation,) = (response,);
                {
                    if response.framing.read_timed_out {
                        Some("response read timed out".to_owned())
                    } else if response.body_truncated || response.framing.body_limit_reached {
                        Some("response truncated at configured size limit".to_owned())
                    } else if matches!(response.status, 401 | 403 | 407) {
                        Some("authentication rejected; identification stopped".to_owned())
                    } else if (300..400).contains(&response.status) {
                        Some("redirect not followed for identification".to_owned())
                    } else {
                        None
                    }
                }
            })
            .or_else(|| {
                http_identity(response, name)
                    .is_none()
                    .then(|| format!("HTTP {}; no implementation signature", response.status))
            });
            if let Some(reason) = reason {
                ({
                    let (endpoint, name, reason): (&mut EndpointScan, &str, _) =
                        (endpoint, name, format!("Captured GET {path}: {reason}"));

                    add_product(
                        endpoint,
                        name,
                        ProductLayer::Server,
                        None,
                        Confidence::Low,
                        reason.into(),
                    );
                });
            }
            continue;
        }
        if ({
            let (endpoint, names): (&EndpointScan, &[&str]) = (endpoint, &[name]);
            {
                endpoint.products.iter().any(|product| {
                    product.confidence >= Confidence::Medium
                        && names.contains(&product.name.as_str())
                })
            }
        }) && endpoint
            .products
            .iter()
            .any(|p| p.name == name && p.version.is_some())
        {
            continue;
        }
        if {
            let (endpoint,): (&EndpointScan,) = (endpoint,);
            {
                endpoint
                    .http
                    .iter()
                    .any(|r| matches!(r.status, 401 | 403 | 407))
                    || endpoint.evidence.iter().any(|e| {
                        let lower = e.to_ascii_lowercase();
                        lower.contains("-noauth")
                            || lower.contains("-noperm")
                            || lower.contains("-wrongpass")
                    })
            }
        } {
            ({
                let (endpoint, name, reason): (&mut EndpointScan, &str, _) = (
                    endpoint,
                    name,
                    "Identification stopped after authentication rejection",
                );

                add_product(
                    endpoint,
                    name,
                    ProductLayer::Server,
                    None,
                    Confidence::Low,
                    reason.into(),
                );
            });
            continue;
        }
        if remaining == 0 {
            ({
                let (endpoint, name, reason): (&mut EndpointScan, &str, _) = (
                    endpoint,
                    name,
                    "Identification request limit (2 per endpoint) reached",
                );

                add_product(
                    endpoint,
                    name,
                    ProductLayer::Server,
                    None,
                    Confidence::Low,
                    reason.into(),
                );
            });
            continue;
        }
        remaining -= 1;
        match single_http_request(context, scheme, "GET", path, &[], MAX_HTTP_BODY_BYTES, None)
            .await
        {
            Ok(mut response) => {
                response.url = format!(
                    "{scheme}://{}{path}",
                    host_header(context.scan.hostname, endpoint.port, scheme)
                );
                let reason = {
                    let (response,): (&HttpObservation,) = (&response,);
                    {
                        if response.framing.read_timed_out {
                            Some("response read timed out".to_owned())
                        } else if response.body_truncated || response.framing.body_limit_reached {
                            Some("response truncated at configured size limit".to_owned())
                        } else if matches!(response.status, 401 | 403 | 407) {
                            Some("authentication rejected; identification stopped".to_owned())
                        } else if (300..400).contains(&response.status) {
                            Some("redirect not followed for identification".to_owned())
                        } else {
                            None
                        }
                    }
                };
                let matched = http_identity(&response, name).is_some();
                endpoint.http.push(response);
                record_captured_async(endpoint, context.scan.cancel).await;
                if !matched || reason.is_some() {
                    let reason = reason.unwrap_or_else(|| {
                        format!(
                            "HTTP {}; no implementation signature",
                            endpoint.http.last().unwrap().status
                        )
                    });
                    ({
                        let (endpoint, name, reason): (&mut EndpointScan, &str, _) =
                            (endpoint, name, format!("GET {path}: {reason}"));

                        add_product(
                            endpoint,
                            name,
                            ProductLayer::Server,
                            None,
                            Confidence::Low,
                            reason.into(),
                        );
                    });
                }
            }
            Err(reason) => {
                let (endpoint, name, reason): (&mut EndpointScan, &str, _) =
                    (endpoint, name, format!("GET {path}: {reason}"));

                add_product(
                    endpoint,
                    name,
                    ProductLayer::Server,
                    None,
                    Confidence::Low,
                    reason.into(),
                );
            }
        }
    }
}

fn bson_document(bytes: &[u8], depth: usize) -> Option<serde_json::Value> {
    if depth > 16
        || bytes.len() < 5
        || ({
            let (bytes, offset): (&[u8], usize) = (bytes, 0);
            {
                'inlined_read_i32: {
                    Some(i32::from_le_bytes(
                        match match bytes.get(
                            offset..match offset.checked_add(4) {
                                Some(value) => value,
                                None => break 'inlined_read_i32 None,
                            },
                        ) {
                            Some(value) => value,
                            None => break 'inlined_read_i32 None,
                        }
                        .try_into()
                        .ok()
                        {
                            Some(value) => value,
                            None => break 'inlined_read_i32 None,
                        },
                    ))
                }
            }
        })? != bytes.len() as i32
        || bytes.last() != Some(&0)
    {
        return None;
    }
    let mut offset = 4;
    let mut fields = serde_json::Map::new();
    while offset < bytes.len() - 1 {
        let kind = *bytes.get(offset)?;
        offset += 1;
        let end = offset + bytes.get(offset..)?.iter().position(|b| *b == 0)?;
        let key = std::str::from_utf8(bytes.get(offset..end)?)
            .ok()?
            .to_owned();
        offset = end + 1;
        let mut value = serde_json::Value::Null;
        let length = match kind {
            1 => {
                value = serde_json::json!(f64::from_le_bytes(
                    bytes.get(offset..offset + 8)?.try_into().ok()?
                ));
                8
            }
            2 => {
                let length = usize::try_from(
                    ({
                        let (bytes, offset): (&[u8], usize) = (bytes, offset);
                        {
                            'inlined_read_i32: {
                                Some(i32::from_le_bytes(
                                    match match bytes.get(
                                        offset..match offset.checked_add(4) {
                                            Some(value) => value,
                                            None => break 'inlined_read_i32 None,
                                        },
                                    ) {
                                        Some(value) => value,
                                        None => break 'inlined_read_i32 None,
                                    }
                                    .try_into()
                                    .ok()
                                    {
                                        Some(value) => value,
                                        None => break 'inlined_read_i32 None,
                                    },
                                ))
                            }
                        }
                    })?,
                )
                .ok()?;
                if length == 0 || *bytes.get(offset.checked_add(3 + length)?)? != 0 {
                    return None;
                }
                value = serde_json::Value::String(
                    std::str::from_utf8(bytes.get(offset + 4..offset.checked_add(3 + length)?)?)
                        .ok()?
                        .to_owned(),
                );
                length.checked_add(4)?
            }
            3 | 4 => {
                let length = usize::try_from(
                    ({
                        let (bytes, offset): (&[u8], usize) = (bytes, offset);
                        {
                            'inlined_read_i32: {
                                Some(i32::from_le_bytes(
                                    match match bytes.get(
                                        offset..match offset.checked_add(4) {
                                            Some(value) => value,
                                            None => break 'inlined_read_i32 None,
                                        },
                                    ) {
                                        Some(value) => value,
                                        None => break 'inlined_read_i32 None,
                                    }
                                    .try_into()
                                    .ok()
                                    {
                                        Some(value) => value,
                                        None => break 'inlined_read_i32 None,
                                    },
                                ))
                            }
                        }
                    })?,
                )
                .ok()?;
                value = bson_document(bytes.get(offset..offset.checked_add(length)?)?, depth + 1)?;
                length
            }
            5 => {
                let length = usize::try_from(
                    ({
                        let (bytes, offset): (&[u8], usize) = (bytes, offset);
                        {
                            'inlined_read_i32: {
                                Some(i32::from_le_bytes(
                                    match match bytes.get(
                                        offset..match offset.checked_add(4) {
                                            Some(value) => value,
                                            None => break 'inlined_read_i32 None,
                                        },
                                    ) {
                                        Some(value) => value,
                                        None => break 'inlined_read_i32 None,
                                    }
                                    .try_into()
                                    .ok()
                                    {
                                        Some(value) => value,
                                        None => break 'inlined_read_i32 None,
                                    },
                                ))
                            }
                        }
                    })?,
                )
                .ok()?;
                length.checked_add(5)?
            }
            7 => 12,
            8 => {
                value = match bytes.get(offset)? {
                    0 => serde_json::json!(false),
                    1 => serde_json::json!(true),
                    _ => return None,
                };
                1
            }
            9 | 17 => 8,
            10 | 127 | 255 => 0,
            16 => {
                value = serde_json::json!(
                    ({
                        let (bytes, offset): (&[u8], usize) = (bytes, offset);
                        let inlined_result: Option<i32> = {
                            'inlined_read_i32: {
                                Some(i32::from_le_bytes(
                                    match match bytes.get(
                                        offset..match offset.checked_add(4) {
                                            Some(value) => value,
                                            None => break 'inlined_read_i32 None,
                                        },
                                    ) {
                                        Some(value) => value,
                                        None => break 'inlined_read_i32 None,
                                    }
                                    .try_into()
                                    .ok()
                                    {
                                        Some(value) => value,
                                        None => break 'inlined_read_i32 None,
                                    },
                                ))
                            }
                        };
                        inlined_result
                    })?
                );
                4
            }
            18 => {
                value = serde_json::json!(i64::from_le_bytes(
                    bytes.get(offset..offset + 8)?.try_into().ok()?
                ));
                8
            }
            19 => 16,
            _ => return None,
        };
        offset = offset.checked_add(length)?;
        if offset >= bytes.len() || fields.insert(key, value).is_some() {
            return None;
        }
    }
    (offset == bytes.len() - 1).then_some(serde_json::Value::Object(fields))
}

async fn record_captured_async(endpoint: &mut EndpointScan, cancel: &CancellationToken) {
    if cancel.is_cancelled() {
        return;
    }
    let mut input = endpoint.clone();
    match crate::blocking::run(cancel, move |cancel| {
        record_captured(&mut input, cancel);
        input
    })
    .await
    {
        Ok(processed) => *endpoint = processed,
        Err(crate::blocking::Error::Cancelled) => {}
        Err(error) => endpoint.evidence.push(error.to_string()),
    }
}

