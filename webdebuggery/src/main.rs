use eframe::egui;
use reqwest::Client;
use reqwest::Method;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone)]
struct RequestResult {
    url: String,
    status: String,
    body: String,
    error: Option<String>,
}

struct App {
    
    // Requests
    show_newrequest: bool,
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
            request_type: "GET".to_string(),
            request_url: String::new(),
            request_responses: Arc::new(Mutex::new(Vec::new())),
            request_loading: Arc::new(Mutex::new(false)),
            ui_error: None,
        }
    }
    
    fn send_request_async(&self, request_type: String, request_url: String) -> Result<(), Box<dyn Error + Send + Sync>> {
        let responses = Arc::clone(&self.request_responses);
        let is_loading = Arc::clone(&self.request_loading);

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
                Ok((status, body)) => RequestResult {
                    url: request_url,
                    status,
                    body,
                    error: None,
                },
                Err(e) => RequestResult {
                    url: request_url,
                    status: "Error".to_string(),
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
                columns[0].add_space(40.0);

                egui::Frame::new().show(&mut columns[1], |ui| {
                    if ui.add_sized([100.0, 20.0], egui::Button::new("Create Request")).clicked() {
                        self.show_newrequest = true;
                    }
                    
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
                columns[1].add_space(40.0);

                /* Left Column */
                egui::ScrollArea::vertical().id_salt("c1").show(&mut columns[0], |ui| {
                    ui.heading("Request History");
                    ui.add_space(10.0);
                    
                    for (i, response) in responses.iter().enumerate() {
                        ui.group(|ui| {
                            ui.label(format!("Request {}: {}", i + 1, response.url));
                            ui.label(format!("Status: {}", response.status));
                            
                            if let Some(error) = &response.error {
                                ui.colored_label(egui::Color32::RED, format!("Error: {}", error));
                            } else {
                                ui.label("Response Body:");
                                ui.add_space(5.0);

                                egui::ScrollArea::vertical()
                                    .max_height(200.0)
                                    .show(ui, |ui| {
                                        ui.add(
                                            egui::TextEdit::multiline(&mut response.body.clone())
                                                .desired_width(f32::INFINITY)
                                                .desired_rows(10)
                                                .interactive(false)
                                        );
                                    });
                            }
                        });
                        ui.add_space(10.0);
                    }
                    
                    if responses.is_empty() && !is_loading {
                        ui.label("No requests sent yet. Click 'Create Request' to get started!");
                    }
                });

                /* Right Column */
                egui::ScrollArea::vertical().id_salt("c2").show(&mut columns[1], |ui| {
                    ui.heading("Request Details");
                    ui.label("Click 'Create Request' to send HTTP requests and see the responses on the left.");
                });
            });
        });

        // Create Request Dialog
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
                                    .hint_text("https://api.example.com/endpoint")
                            );
                        });

                        ui.add_space(20.0);

                        ui.horizontal(|ui| {
                            let send_enabled = !self.request_url.is_empty() && !is_loading;
                            
                            if ui.add_enabled(send_enabled, egui::Button::new("Send")).clicked() {
                                self.show_newrequest = false;    
                                match self.send_request_async( self.request_type.clone(), self.request_url.clone()) {
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

async fn send_request(request_type: String, request_url: String) -> Result<(String, String), Box<dyn Error + Send + Sync>> {
    let method = match request_type.as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "PATCH" => Method::PATCH,
        "DELETE" => Method::DELETE,
        _ => return Err("Invalid request type".into()),
    };
    
    let client = Client::new();
    println!("Sending {} request to: {}", request_type, request_url);
    
    let response = client.request(method, &request_url).send().await?;
    let status = format!("{} {}", response.status().as_u16(), response.status().canonical_reason().unwrap_or(""));
    let body = response.text().await?;
    
    println!("Response received: {}", status);
    Ok((status, body))
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
            println!("Application closed successfully");
            Ok(())
        },
        Err(e) => {
            eprintln!("eframe error: {}", e);
            Err(e.into())
        }
    }
}