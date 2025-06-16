use eframe::egui;
use reqwest::Client;
use reqwest::Method;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::net::TcpStream;
use std::net::SocketAddr;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone)]
struct RequestResult {
    url: String,
    status: String,
    headers: Vec<String>,
    body: String,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct App {
    show_newrequest: bool,
    show_requestdetails: String,

    request_type: String,
    request_url: String,
    request_responses: Arc<Mutex<Vec<RequestResult>>>,
    request_loading: Arc<Mutex<bool>>,

    ui_error: Option<String>,
}

impl App {
    fn new() -> Self {
        App {
            show_newrequest: false,
            show_requestdetails: String::new(),

            request_type: "GET".to_string(),
            request_url: String::new(),
            request_responses: Arc::new(Mutex::new(Vec::new())),
            request_loading: Arc::new(Mutex::new(false)),

            ui_error: None,
        }
    }
    
    fn send_request(&self, request_type: String, mut request_url: String) -> Result<(), Box<dyn std::error::Error>> {
        let responses = Arc::clone(&self.request_responses);
        let is_loading = Arc::clone(&self.request_loading);

        if request_url.is_empty() {
            return Err("URL is empty".into());
        }
        if !request_url.starts_with("http") {
            request_url = format!("http://{}", request_url);
        }

        *is_loading.lock().unwrap() = true;
        
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("Error building tokio runtime: {}", e);
                    return Err(e.into());
                }
            };
            
        thread::spawn(move || {
            let response = match rt.block_on(async { send_request(request_type, request_url.clone()).await }) {
                Ok((status, headers, body)) => RequestResult {
                    url: request_url,
                    status,
                    headers: headers,
                    body,
                    error: None,
                },
                Err((e, status, headers)) => RequestResult {
                    url: request_url,
                    status,
                    headers,
                    body: String::new(),
                    error: Some(e.to_string()),
                },
            };

            responses.lock().unwrap().push(response);
            *is_loading.lock().unwrap() = false;
        });
        
        Ok(())
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let is_loading = *self.request_loading.lock().unwrap();
        let responses = self.request_responses.lock().unwrap().clone();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(20.0);
            ui.columns(2, |columns| {

                /* Headings */
                columns[0].heading("Web Debugger");
                egui::Frame::new().show(&mut columns[1], |ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                        ui.add_space(20.0);
                        if ui.add_sized([120.0, 25.0], egui::Button::new("Create Request")).clicked() {
                            self.show_newrequest = true;
                        }
                    });
                    
                    if is_loading {
                        ui.add_space(10.0);
                        ui.spinner();
                        ui.label("Sending request...");
                    }
                    
                    if let Some(error) = &self.ui_error {
                        ui.add_space(10.0);
                        ui.colored_label(egui::Color32::RED, error);
                        if ui.button("Dismiss").clicked() {
                            self.ui_error = None;
                        }
                    }
                });
                columns[0].add_space(40.0);
                egui::ScrollArea::vertical().id_salt("c1").show(&mut columns[0], |ui| {
                    ui.heading("Request History");
                    ui.add_space(10.0);
                    
                    for response in responses.iter() {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(format!("{}", response.url));
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                                    if let Some(error) = &response.error {
                                        ui.colored_label(egui::Color32::RED, format!("{}", error));
                                    } 
                                    else {
                                        if ui.add_sized([120.0, 20.0], egui::Button::new("View Response")).clicked() {
                                            self.show_requestdetails = response.body.clone();
                                        }
                                    }
                                });
                            });
                            ui.label(format!("Status: {}", response.status));
                        });
                        ui.add_space(10.0);
                    }
                    
                    if responses.is_empty() && !is_loading {
                        ui.label("No requests sent yet.");
                    }
                });

                /* Right Column */
                columns[1].add_space(40.0);
                egui::ScrollArea::vertical().id_salt("c2").show(&mut columns[1], |ui| {
                    ui.heading("Details");
                });

                /* Show Details */
                if !self.show_requestdetails.is_empty() {
                    

                    egui::ScrollArea::vertical()
                    .max_height(350.0)
                    .show(&mut columns[1], |ui| {
                        ui.add(
                        egui::TextEdit::multiline(&mut self.show_requestdetails)
                            .desired_width(f32::INFINITY)
                            .desired_rows(10)
                            .interactive(false)
                    );
                    });
                }
            });

        });

        /* Show New Request */
        if self.show_newrequest {
            egui::Window::new("New Request")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.label("Send HTTP Request");
                        ui.add_space(10.0);

                        ui.horizontal(|ui| {
                            ui.label("Method:");
                            egui::ComboBox::from_id_salt("request_type_combo")
                                .selected_text(&self.request_type)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.request_type, "GET".to_string(), "GET");
                                    ui.selectable_value(&mut self.request_type, "POST".to_string(), "POST");
                                    ui.selectable_value(&mut self.request_type, "PUT".to_string(), "PUT");
                                    ui.selectable_value(&mut self.request_type, "PATCH".to_string(), "PATCH");
                                    ui.selectable_value(&mut self.request_type, "DELETE".to_string(), "DELETE");
                                });
                        });

                        ui.horizontal(|ui| {
                            ui.label("URL:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.request_url)
                                    .desired_width(300.0)
                                    .hint_text("api.example.com/endpoint")
                            );
                        });

                        ui.add_space(20.0);

                        ui.horizontal(|ui| {
                            let send_enabled = !self.request_url.is_empty() && !is_loading;
                            
                            if ui.add_enabled(send_enabled, egui::Button::new("Send")).clicked() {
                                self.show_newrequest = false;    
                                match self.send_request( self.request_type.clone(), self.request_url.clone()) {
                                    Ok(_) => {
                                        self.ui_error = None;
                                    },
                                    Err(e) => {
                                        let error_msg = format!("Error sending request: {}", e);
                                        eprintln!("{}", error_msg);
                                        self.ui_error = Some(error_msg);
                                    }
                                }
                                self.request_url.clear();
                            }

                            if ui.button("Cancel").clicked() {
                                self.show_newrequest = false;
                            }
                        });
                    });
                });
        }

        if is_loading {
            ctx.request_repaint();
        }
    }
}
async fn send_request(request_type: String, request_url: String) -> Result<(String, Vec<String>, String), (Box<dyn Error + Send + Sync>, String, Vec<String>)> {
    let method = match request_type.as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "PATCH" => Method::PATCH,
        "DELETE" => Method::DELETE,
        _ => return Err(("Invalid request type".into(), String::new(), Vec::new())),
    };

    // Parse URL and test different scenarios
    let new_request_url = request_url.clone();
    if let Ok(url) = thread::spawn(move || reqwest::Url::parse(&new_request_url)).join().unwrap() {
        if let Some(host) = url.host_str() {
            let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
            
            println!("URL Analysis:");
            println!("  Host: {}", host);
            println!("  Port: {}", port);
            println!("  Scheme: {}", url.scheme());
            
            // Test basic TCP
            match debug_tcp(host, port).await {
                Ok(_) => println!("TCP connection OK"),
                Err(e) => {
                    println!("✗ TCP connection failed: {}", e);
                    return Err((
                        format!("Cannot establish TCP connection to {}:{}", host, port).into(),
                        "TCP_CONNECTION_FAILED".to_string(),
                        Vec::new()
                    ));
                }
            }
            
            // Test what the server actually sends
            println!("Testing server response...");
            let addr = format!("{}:{}", host, port);
            let mut stream = match TokioTcpStream::connect(&addr).await {
                Ok(stream) => stream,
                Err(e) => {
                    println!("Failed to connect to {}: {}", addr, e);
                    return Err((format!("Failed to connect to {}: {}", addr, e).into(), "CONNECTION_FAILED".to_string(), Vec::new()));
                }
            };
            
            if url.scheme() == "https" {
                let mut buffer = [0; 1024];
                let request = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host);
                match stream.write_all(request.as_bytes()).await {
                    Ok(_) => (),
                    Err(e) => {
                        println!("Failed to write request to {}: {}", addr, e);
                        return Err((format!("Failed to write request to {}: {}", addr, e).into(), "WRITE_FAILED".to_string(), Vec::new()));
                    }
                };
        
                match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(1_usize..)) => {
                        if buffer[0] == 0x16 {
                            println!("Server responded with TLS handshake");
                        } 
                        else if buffer[0..4] == [0x48, 0x54, 0x54, 0x50] { // HTTP
                            let response = String::from_utf8_lossy(&buffer[..100]);
                            println!("Server responded with HTTP: {}", &response)
                        } 
                        else {
                            println!("Server responded with unknown data: {:02x?}", &buffer[..20])
                        }
                    },
                    Ok(Ok(0)) => println!("Server closed connection immediately"),
                    Ok(Err(e)) => println!("Read error: {}", e),
                    Err(_) => println!("Server didn't respond within timeout"),
                }
            } 
            else {
                let request = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", host);
                match stream.write_all(request.as_bytes()).await {
                    Ok(_) => (),
                    Err(e) => {
                        println!("Failed to write request to {}: {}", addr, e);
                        return Err((format!("Failed to write request to {}: {}", addr, e).into(), "WRITE_FAILED".to_string(), Vec::new()));
                    }
                };
                
                let mut buffer = [0; 1024];
                match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(1_usize..)) => {
                        if buffer[0] == 0x16 {
                            println!("Server sent TLS handshake on HTTP port")
                        } 
                        else if buffer[0..4] == [0x48, 0x54, 0x54, 0x50] {
                            let response = String::from_utf8_lossy(&buffer[..100]);
                            println!("Normal HTTP response: {}", &response)
                        } 
                        else {
                            println!("Unknown response: {:02x?}", &buffer[..20])
                        }
                    },
                    Ok(Ok(0)) => println!("Server closed connection"),
                    Ok(Err(e)) => println!("Read error: {}", e),
                    Err(_) => println!("No response within timeout"),
                }
            }
        }
    }

    let clients_to_try = unsafe { vec![
        ("Standard client".to_string(), create_standard_client()),
        ("Permissive client".to_string(), create_permissive_client()),
        ("Legacy TLS client".to_string(), create_legacy_tls_client()),
    ]};
    
    for (name, client_result) in clients_to_try {
        println!("\nTrying {}...", name);
        
        let client = match client_result {
            Ok(client) => client,
            Err(e) => {
                println!("Failed to create {}: {}", name, e);
                continue;
            }
        };
        
        let req = match client.request(method.clone(), &request_url).build() {
            Ok(req) => req,
            Err(e) => {
                println!("Failed to build request with {}: {}", name, e);
                continue;
            }
        };
        println!("Request: {:?}", req);
        
        println!("Sending {} request to: {} with {}", request_type, request_url, name);
        
        match client.execute(req).await {
            Ok(response) => {
                println!("Success with {}!", name);
                let status = if response.status().as_u16() == 200 { 
                    format!("{}", response.status().as_u16()) 
                } else { 
                    format!("{} {}", response.status().as_u16(), response.status().canonical_reason().unwrap_or("")) 
                };
                let headers: Vec<String> = response.headers().iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
                    .collect();
                let body = match response.text().await {
                    Ok(body) => body,
                    Err(e) => return Err((format!("Unable to read response body: {}", e).into(), format!("{:?}", e.status()), headers)),
                };
                
                println!("Response received: {}", status);
                return Ok((status, headers, body));
            },
            Err(e) => {
                println!("Failed with {}: {}", name, e);
                print_error_details(&e);
            }
        }
    }
    
    Err(("All client configurations failed".into(), "ALL_FAILED".to_string(), Vec::new()))
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

fn print_error_details(e: &reqwest::Error) {
    println!("  Error details:");
    println!("    Main error: {}", e);
    println!("    Is timeout: {}", e.is_timeout());
    println!("    Is connect: {}", e.is_connect());
    println!("    Is request: {}", e.is_request());
    println!("    Status: {:?}", e.status());
    
    let mut source = e.source();
    let mut level = 0;
    while let Some(err) = source {
        println!("    Level {}: {}", level, err);
        source = err.source();
        level += 1;
    }
}

async fn test_server_response(host: &str, port: u16, expect_tls: bool) -> Result<String, Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TokioTcpStream::connect(&addr).await?;
    
    if expect_tls {
        let mut buffer = [0; 1024];
        let request = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host);
        stream.write_all(request.as_bytes()).await?;

        match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(1_usize..)) => {
                if buffer[0] == 0x16 {
                    Ok("Server responded with TLS handshake".to_string())
                } 
                else if buffer[0..4] == [0x48, 0x54, 0x54, 0x50] { // HTTP
                    let response = String::from_utf8_lossy(&buffer[..100]);
                    Ok(format!("Server responded with HTTP: {}", &response))
                } 
                else {
                    Ok(format!("Server responded with unknown data: {:02x?}", &buffer[..20]))
                }
            },
            Ok(Ok(0)) => Ok("Server closed connection immediately".to_string()),
            Ok(Err(e)) => Err(format!("Read error: {}", e).into()),
            Err(_) => Ok("Server didn't respond within timeout".to_string()),
        }
    } else {
        let request = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", host);
        stream.write_all(request.as_bytes()).await?;
        
        let mut buffer = [0; 1024];
        match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(1_usize..)) => {
                if buffer[0] == 0x16 {
                    Ok("Server sent TLS handshake on HTTP port".to_string())
                } 
                else if buffer[0..4] == [0x48, 0x54, 0x54, 0x50] {
                    let response = String::from_utf8_lossy(&buffer[..100]);
                    Ok(format!("Normal HTTP response: {}", &response))
                } 
                else {
                    Ok(format!("Unknown response: {:02x?}", &buffer[..20]))
                }
            },
            Ok(Ok(0)) => Ok("Server closed connection".to_string()),
            Ok(Err(e)) => Err(format!("Read error: {}", e).into()),
            Err(_) => Ok("No response within timeout".to_string()),
        }
    }
}

async fn debug_tcp(host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", host, port);
    println!("Testing TCP connection to {}", addr);
    
    match addr.parse::<SocketAddr>() {
        Ok(socket_addr) => {
            match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5)) {
                Ok(_stream) => {
                    println!("TCP Connection Successful");
                    Ok(())
                },
                Err(e) => {
                    println!("TCP Connection Failed: {}", e);
                    Err(e.into())
                }
            }
        },
        Err(_) => {
            let addr_str = format!("{}:{}", host, port);
            match std::net::ToSocketAddrs::to_socket_addrs(&addr_str) {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        println!("Resolved {} to {}", addr_str, addr);
                        match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                            Ok(_stream) => {
                                println!("TCP Connection Successful");
                                Ok(())
                            },
                            Err(e) => {
                                println!("TCP Connection Failed: {}", e);
                                Err(e.into())
                            }
                        }
                    } 
                    else {
                        println!("No addresses resolved");
                        Err("No addresses resolved".into())
                    }
                },
                Err(e) => {
                    println!("DNS resolution failed: {}", e);
                    Err(e.into())
                }
            }
        }
    }
}


fn main() -> Result<(), Box<dyn Error>> {
    println!("Starting Web Debugger application...");
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 700.0]),
        ..Default::default()
    };

    match eframe::run_native(
        "Web Debugger",
        options,
        Box::new(|_cc| {
            println!("Initialising App...");
            Ok(Box::new(App::new()))
        })
    ) {
        Ok(_) => {
            Ok(())
        },
        Err(e) => {
            eprintln!("eframe error: {}", e);
            Err(e.into())
        }
    }
}