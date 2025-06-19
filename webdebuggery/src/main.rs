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
    index: usize,
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
    show_requestheaders: String,
    selected_response_index: Option<usize>,

    request_type: String,
    request_url: String,
    request_responses: Arc<Mutex<Vec<RequestResult>>>,
    request_loading: Arc<Mutex<bool>>,
    next_index: Arc<Mutex<usize>>,

    ui_error: Option<String>,
}

impl App {
    fn new() -> Self {
        App {
            show_newrequest: false,
            show_requestdetails: String::new(),
            show_requestheaders: String::new(),
            selected_response_index: None,

            request_type: "GET".to_string(),
            request_url: String::new(),
            request_responses: Arc::new(Mutex::new(Vec::new())),
            request_loading: Arc::new(Mutex::new(false)),
            next_index: Arc::new(Mutex::new(1)),

            ui_error: None,
        }
    }
    
    fn send_request(&self, request_type: String, mut request_url: String) -> Result<(), Box<dyn std::error::Error>> {
        let responses = Arc::clone(&self.request_responses);
        let is_loading = Arc::clone(&self.request_loading);
        let next_index = Arc::clone(&self.next_index);

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
            let current_index = {
                let mut index = next_index.lock().unwrap();
                let current = *index;
                *index += 1;
                current
            };

            let response = match rt.block_on(async { send_request(request_type, request_url.clone()).await }) {
                Ok((status, headers, body)) => RequestResult {
                    index: current_index,
                    url: request_url,
                    status,
                    headers: headers,
                    body: body,
                    error: None,
                },
                Err((e, status, headers, tracebuilder)) => RequestResult {
                    index: current_index,
                    url: request_url,
                    status,
                    headers,
                    body: tracebuilder,
                    error: Some(e.to_string()),
                },
            };

            responses.lock().unwrap().insert(0, response);
            *is_loading.lock().unwrap() = false;
        });
        
        Ok(())
    }

    fn get_response_by_index(&self, index: usize) -> Option<RequestResult> {
        let responses = self.request_responses.lock().unwrap();
        responses.iter().find(|r| r.index == index).cloned()
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
                                    if ui.add_sized([120.0, 20.0], egui::Button::new("View Response")).clicked() {
                                        self.show_requestdetails = response.body.clone();
                                        self.show_requestheaders = response.headers.join("\n");
                                        self.selected_response_index = Some(response.index);
                                    }
                                });
                            });
                            ui.add_space(10.0);
                            ui.horizontal(|ui| {
                                ui.label(format!("Status: {}", response.status));
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                                    if let Some(error) = &response.error {
                                        ui.colored_label(egui::Color32::RED, format!("{}", error));
                                    }
                                });
                            });
                        });
                        ui.add_space(10.0);
                    }
                    
                    if responses.is_empty() && !is_loading {
                        ui.label("No requests sent yet.");
                    }
                });

                /* Details Block */
                if !self.show_requestdetails.is_empty() && !self.show_requestheaders.is_empty() {
                    columns[1].add_space(40.0);

                    /* Headers */
                    egui::ScrollArea::vertical().id_salt("c2").show(&mut columns[1], |ui| {
                        ui.heading("Details");
                        if let Some(index) = self.selected_response_index {
                            if let Some(response) = self.get_response_by_index(index) {
                                ui.horizontal(|ui| {
                                    ui.label("URL:");
                                    ui.label(&response.url);
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Status:");
                                    ui.label(&response.status);
                                });
                            }
                        }
                    });

                    /* Headers */
                    egui::ScrollArea::vertical()
                    .id_salt("headers")
                    .max_height(150.0)
                    .show(&mut columns[1], |ui| {
                        ui.add(
                        egui::TextEdit::multiline(&mut self.show_requestheaders)
                            .desired_width(f32::INFINITY)
                            .desired_rows(10)
                            .interactive(false)
                        );
                    });

                    columns[1].add_space(10.0);

                    /* Body */
                    egui::ScrollArea::vertical()
                        .id_salt("body")
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
                /* Error Block */
                else if !self.show_requestdetails.is_empty() {
                    columns[1].add_space(40.0);

                    /* Status */
                    egui::ScrollArea::vertical().id_salt("c2").show(&mut columns[1], |ui| {
                        ui.heading("Details");
                        if let Some(index) = self.selected_response_index {
                            if let Some(response) = self.get_response_by_index(index) {
                                ui.horizontal(|ui| {
                                    ui.label("URL:");
                                    ui.label(&response.url);
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Status:");
                                    ui.label(&response.status);
                                });
                            }
                        }
                    });

                    columns[1].add_space(10.0);

                    /* Body */
                    egui::ScrollArea::vertical()
                        .id_salt("body")
                        .max_height(600.0)
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

async fn send_request(request_type: String, request_url: String) -> Result<(String, Vec<String>, String), (Box<dyn Error + Send + Sync>, String, Vec<String>, String)> {
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
                let request = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host);
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
    
    Err(("All client configurations failed".into(), "Failed".to_string(), Vec::new(), tracebuilder))
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


fn main() -> Result<(), Box<dyn Error>> {
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