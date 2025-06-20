use reqwest::Client;
use reqwest::Method;
use std::time::Duration;
use std::net::TcpStream;
use std::net::SocketAddr;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use std::thread;

pub async fn send_request(request_type: String, request_url: String, request_headers: String, request_body: String) -> Result<(String, Vec<String>, String), (Box<dyn Error + Send + Sync>, String, Vec<String>, String)> {
    let method = match request_type.as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "PATCH" => Method::PATCH,
        "DELETE" => Method::DELETE,
        _ => return Err(("Invalid request type".into(), String::new(), Vec::new(), String::new())),
    };

    let mut tracebuilder = String::new();

    let new_request_url = request_url.clone();
    if let Ok(url) = thread::spawn(move || reqwest::Url::parse(&new_request_url)).join().unwrap() {
        if let Some(host) = url.host_str() {
            let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
            
            tracebuilder.push_str(&format!("URL Analysis:\n  Host: {}\n  Port: {}\n  Scheme: {}\n\n", host, port, url.scheme()));
            
            // Test basic TCP
            match test_dns(host, port).await {
                Ok(dns) => tracebuilder.push_str(&format!("Resolved DNS to: {}\n", dns.to_string())),
                Err(e) => {
                    tracebuilder.push_str(&format!("{}\n{}", e.0, e.1));
                    return Err((
                        format!("Cannot establish TCP connection to {}:{}", host, port).into(),
                        "DNS Resolution Failed".to_string(),
                        Vec::new(),
                        tracebuilder
                    ));
                }
            }
            
            // Test what the server actually sends
            tracebuilder.push_str("Testing server response...\n");
            let addr = format!("{}:{}", host, port);
            let mut stream = match TokioTcpStream::connect(&addr).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracebuilder.push_str(&format!("Failed to connect to {}: {}\n", addr, e));
                    return Err((format!("Failed to connect to {}: {}", addr, e).into(), "Connection Failed".to_string(), Vec::new(), tracebuilder));
                }
            };
            
            if url.scheme() == "https" {
                let mut buffer = [0; 1024];
                let request = format!("GET / HTTP/1.1\r\nHost: {}\r\n{}\r\n\r\n", host, request_headers);
                match stream.write_all(request.as_bytes()).await {
                    Ok(_) => (),
                    Err(e) => {
                        tracebuilder.push_str(&format!("Failed to write request to {}: {}\n", addr, e));
                        return Err((format!("Failed to write request to {}: {}", addr, e).into(), "Write Failed".to_string(), Vec::new(), tracebuilder));
                    }
                };
        
                match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(1_usize..)) => {
                        if buffer[0] == 0x16 {
                            tracebuilder.push_str("Server responded with TLS handshake\n");
                        } 
                        else if buffer[0..4] == [0x48, 0x54, 0x54, 0x50] { // HTTP
                            let response = String::from_utf8_lossy(&buffer[..100]);
                            tracebuilder.push_str(&format!("Server responded with HTTP: {}\n", &response));
                        } 
                        else {
                            tracebuilder.push_str(&format!("Server responded with unknown data: {:02x?}\n", &buffer[..20]));
                        }
                    },
                    Ok(Ok(0)) => tracebuilder.push_str("Server closed connection immediately\n"),
                    Ok(Err(e)) => tracebuilder.push_str(&format!("Read error: {}\n", e)),
                    Err(_) => tracebuilder.push_str("Server didn't respond within timeout\n"),
                }
            } 
            else {
                let request = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", host);
                match stream.write_all(request.as_bytes()).await {
                    Ok(_) => (),
                    Err(e) => {
                        tracebuilder.push_str(&format!("Failed to write request to {}: {}\n", addr, e));
                        return Err((format!("Failed to write request to {}: {}", addr, e).into(), "Write Failed".to_string(), Vec::new(), tracebuilder));
                    }
                };
                
                let mut buffer = [0; 1024];
                match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(1_usize..)) => {
                        if buffer[0] == 0x16 {
                            tracebuilder.push_str("Server sent TLS handshake on HTTP port\n");
                        } 
                        else if buffer[0..4] == [0x48, 0x54, 0x54, 0x50] {
                            let response = String::from_utf8_lossy(&buffer).to_string();
                            tracebuilder.push_str(&format!("Normal HTTP response: \n\n{}\n", &response));
                        } 
                        else {
                            tracebuilder.push_str(&format!("Unknown response: {:02x?}\n", &buffer[..20]));
                        }
                    },
                    Ok(Ok(0)) => tracebuilder.push_str("Server closed connection\n"),
                    Ok(Err(e)) => tracebuilder.push_str(&format!("Read error: {}\n", e)),
                    Err(_) => tracebuilder.push_str("No response within timeout\n"),
                }
            }
        }
    }

    let clients_to_try = unsafe { vec![
        ("Standard".to_string(), create_standard_client()),
        ("Permissive".to_string(), create_permissive_client()),
        ("Legacy TLS".to_string(), create_legacy_tls_client()),
    ]};
    
    for (name, client_result) in clients_to_try {
        tracebuilder.push_str(&format!("\nTrying {}...\n", name));
        
        let client = match client_result {
            Ok(client) => client,
            Err(e) => {
                tracebuilder.push_str(&format!("Failed to create {}: {}\n", name, e));
                continue;
            }
        };
        
        let req = match client.request(method.clone(), &request_url).build() {
            Ok(req) => req,
            Err(e) => {
                tracebuilder.push_str(&format!("Failed to build request with {}: {}\n", name, e));
                continue;
            }
        };
        tracebuilder.push_str(&format!("Sending {} request to: {} with {}\n", request_type, request_url, name));
        
        match client.execute(req).await {
            Ok(response) => {
                tracebuilder.push_str(&format!("Success with {}!\n", name));
                let status = if response.status().as_u16() == 200 { 
                    format!("{}", response.status().as_u16()) 
                } 
                else { 
                    format!("{} {}", response.status().as_u16(), response.status().canonical_reason().unwrap_or("")) 
                };
                let headers: Vec<String> = response.headers().iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                    .collect();
                let body = match response.text().await {
                    Ok(body) => body,
                    Err(e) => return Err((format!("Unable to read response body: {}", e).into(), format!("{:?}", e.status()), headers, tracebuilder)),
                };
                
                tracebuilder.push_str(&format!("Response received: {}\n", status));
                return Ok((status, headers, body));
            },
            Err(e) => {
                tracebuilder.push_str(&format!("Failed with {}: {}\n", name, e));
                tracebuilder.push_str(&print_error_details(&e));
            }
        }
    }
    
    Err(("All Attempts Failed".into(), "Failed".to_string(), Vec::new(), tracebuilder))
}

fn create_standard_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
}

fn create_permissive_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
}

fn create_legacy_tls_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .min_tls_version(reqwest::tls::Version::TLS_1_0)
        .build()
}

fn print_error_details(e: &reqwest::Error) -> String {
    let mut tracebuilder = String::new();

    tracebuilder.push_str("  Error details:\n");
    tracebuilder.push_str(&format!("    Main error: {}\n", e));
    tracebuilder.push_str(&format!("    Timeout: {}\n", e.is_timeout()));
    tracebuilder.push_str(&format!("    Connection Error: {}\n", e.is_connect()));
    tracebuilder.push_str(&format!("    Request Error: {}\n", e.is_request()));
    if let Some(status) = e.status() {
        tracebuilder.push_str(&format!("    Status: Code {:?}\n", status.as_u16()));
    }
    else {
        tracebuilder.push_str("    Status Code: None\n");
    }
    
    let mut source = e.source();
    let mut level = 0;
    while let Some(err) = source {
        tracebuilder.push_str(&format!("    Level {}: {}\n", level, err));
        source = err.source();
        level += 1;
    }

    tracebuilder
}

async fn test_dns(host: &str, port: u16) -> Result<String, (Box<dyn std::error::Error>, String)> {
    let mut tracebuilder = String::new();
    let addr = format!("{}:{}", host, port);
    
    match addr.parse::<SocketAddr>() {
        Ok(socket_addr) => {
            match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5)) {
                Ok(_stream) => {
                    tracebuilder.push_str("DNS Resolution Successful\n");
                    return Ok(addr)
                },
                Err(e) => {
                    tracebuilder.push_str(&format!("DNS Resolution Failed: {}\n", e));
                    return Err((e.into(), tracebuilder));
                }
            }
        },
        Err(_) => {
            let addr_str = format!("{}:{}", host, port);
            match std::net::ToSocketAddrs::to_socket_addrs(&addr_str) {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        tracebuilder.push_str(&format!("Resolved {} to {}\n", addr_str, addr));
                        match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                            Ok(_stream) => {
                                tracebuilder.push_str("TCP Connection Successful\n");
                                return Ok(addr.to_string());
                            },
                            Err(e) => {
                                tracebuilder.push_str(&format!("TCP Connection Failed: {}\n", e));
                                return Err((e.into(), tracebuilder));
                            }
                        }
                    } 
                    else {
                        tracebuilder.push_str("No addresses resolved\n");
                        return Err((format!("No addresses resolved: {}", addr_str).into(), tracebuilder));
                    }
                },
                Err(e) => {
                    tracebuilder.push_str(&format!("DNS resolution failed: {}\n", e));
                    return Err((e.into(), tracebuilder));
                }
            }
        }
    }
}