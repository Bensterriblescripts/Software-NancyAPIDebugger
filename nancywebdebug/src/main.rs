mod request;

use eframe::egui;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone)]
struct RequestResult {
    index: usize,

    // Request
    req_headers: String,
    req_body: String,

    // Response
    url: String,
    status: String,
    headers: Vec<String>,
    body: String,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct App {
    show_newrequest: bool,
    show_requestdetails: Arc<Mutex<String>>,
    show_requestheaders: Arc<Mutex<String>>,
    show_responsedetails: Arc<Mutex<String>>,
    show_responseheaders: Arc<Mutex<String>>,
    selected_response_index: Option<usize>,
    set_focus: String,

    request_type: Arc<Mutex<String>>,
    request_url: Arc<Mutex<String>>,
    request_headers: Arc<Mutex<String>>,
    request_body: Arc<Mutex<String>>,
    request_responses: Arc<Mutex<Vec<RequestResult>>>,
    request_loading: Arc<Mutex<bool>>,
    next_index: Arc<Mutex<usize>>,

    ui_error: Option<String>,
}

impl App {
    fn new() -> Self {
        App {
            show_newrequest: false,
            show_requestdetails: Arc::new(Mutex::new(String::new())),
            show_requestheaders: Arc::new(Mutex::new(String::new())),
            show_responsedetails: Arc::new(Mutex::new(String::new())),
            show_responseheaders: Arc::new(Mutex::new(String::new())),
            selected_response_index: None,
            set_focus: String::new(),

            request_type: Arc::new(Mutex::new("GET".to_string())),
            request_url: Arc::new(Mutex::new(String::new())),
            request_headers: Arc::new(Mutex::new(String::new())),
            request_body: Arc::new(Mutex::new(String::new())),
            request_responses: Arc::new(Mutex::new(Vec::new())),
            request_loading: Arc::new(Mutex::new(false)),
            next_index: Arc::new(Mutex::new(1)),

            ui_error: None,
        }
    }
    
    fn send_request(&self, request_type: String, mut request_url: String, request_headers: String, request_body: String) -> Result<(), Box<dyn std::error::Error>> {
        let responses = Arc::clone(&self.request_responses);
        let is_loading = Arc::clone(&self.request_loading);
        let next_index = Arc::clone(&self.next_index);
        let details = Arc::clone(&self.show_responsedetails);
        let headers = Arc::clone(&self.show_responseheaders);
        let req_headers = Arc::clone(&self.show_requestheaders);
        let req_body = Arc::clone(&self.show_requestdetails);

        if request_url.is_empty() {
            return Err("URL is empty".into());
        }
        if request_url.contains("localhost") {
            request_url = request_url.replace("localhost", "127.0.0.1");
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

            let response = match rt.block_on(async { request::send_request(request_type.clone(), request_url.clone(), req_headers.lock().unwrap().clone(), req_body.lock().unwrap().clone()).await }) {
                Ok((status, headers, body)) => RequestResult {
                    index: current_index,
                    req_headers: request_headers,
                    req_body: request_body,
                    url: request_url,
                    status,
                    headers: headers.clone(),
                    body: body.clone(),
                    error: None,
                },
                Err((e, status, headers, tracebuilder)) => RequestResult {
                    index: current_index,
                    req_headers: request_headers,
                    req_body: request_body,
                    url: request_url,
                    status,
                    headers: headers.clone(),
                    body: tracebuilder.clone(),
                    error: Some(e.to_string()),
                },
            };

            let response_body = response.body.clone();
            let response_headers = response.headers.join("\n");
            let request_headers = response.req_headers.clone();
            let request_body = response.req_body.clone();

            responses.lock().unwrap().insert(0, response);
            *is_loading.lock().unwrap() = false;
            *details.lock().unwrap() = response_body;
            *headers.lock().unwrap() = response_headers;
            *req_headers.lock().unwrap() = request_headers;
            *req_body.lock().unwrap() = request_body;
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
                columns[0].heading("Nancy API Debugger");
                egui::Frame::new().show(&mut columns[1], |ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                        ui.add_space(20.0);
                        let buttontext = if is_loading { "Sending..." } else { "Create Request" };
                        let button = egui::Button::new(buttontext);
                        if ui.add_sized([120.0, 25.0], button).clicked() {
                            self.show_newrequest = true;
                            self.set_focus = "newrequest".to_string();
                        }
                        if is_loading {
                            ui.add_space(10.0);
                            ui.spinner();
                        }
                    });
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
                                        *self.show_requestheaders.lock().unwrap() = response.req_headers.clone();
                                        *self.show_requestdetails.lock().unwrap() = response.req_body.clone();
                                        *self.show_responsedetails.lock().unwrap() = response.body.clone();
                                        *self.show_responseheaders.lock().unwrap() = response.headers.join("\n");
                                        self.selected_response_index = Some(response.index);
                                    }
                                    if ui.add_sized([80.0, 20.0], egui::Button::new("Resend")).clicked() {
                                        match self.send_request(self.request_type.lock().unwrap().clone(), response.url.clone(), response.req_headers.clone(), response.req_body.clone()) {
                                            Ok(_) => {
                                                self.ui_error = None;
                                                *self.show_requestheaders.lock().unwrap() = String::new();
                                                *self.show_requestdetails.lock().unwrap() = String::new();
                                                *self.show_responsedetails.lock().unwrap() = String::new();
                                                *self.show_responseheaders.lock().unwrap() = String::new();
                                                self.selected_response_index = None;
                                            },
                                            Err(e) => {
                                                let error_msg = format!("Error sending request: {}", e);
                                                eprintln!("{}", error_msg);
                                            }
                                        }
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

                /* Details */
                if !self.show_responsedetails.lock().unwrap().is_empty() {
                    columns[1].add_space(40.0);


                    /* Request */
                    egui::ScrollArea::vertical().id_salt("c2_req").show(&mut columns[1], |ui| {
                        ui.heading("Request");
                        ui.add_space(10.0);
                        if let Some(index) = self.selected_response_index {
                            if let Some(response) = self.get_response_by_index(index) {
                                ui.horizontal(|ui| {
                                    ui.add_space(5.0);
                                    ui.label(&response.req_headers);
                                });
                            }
                        }
                    });
                    columns[1].add_space(10.0);

                    // Headers
                    if !self.show_requestheaders.lock().unwrap().is_empty() {
                        columns[1].add(egui::Label::new("Headers"));
                        egui::ScrollArea::vertical()
                        .id_salt("req_headers")
                        .max_height(150.0)
                        .show(&mut columns[1], |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut *self.show_requestheaders.lock().unwrap())
                                    .id_salt("req_headers_text")
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(10)
                                    .interactive(false)
                            );
                        });
                        columns[1].add_space(10.0);
                    }

                    // Body
                    if !self.show_requestdetails.lock().unwrap().is_empty() {
                        columns[1].add(egui::Label::new("Body"));
                        egui::ScrollArea::vertical()
                            .id_salt("req_body")
                            .max_height(350.0)
                            .show(&mut columns[1], |ui| {
                                ui.add(
                                egui::TextEdit::multiline(&mut *self.show_requestdetails.lock().unwrap())
                                    .id_salt("req_body_text")
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(10)
                                    .interactive(false)
                            );
                        });
                    }

                    /* Response */
                    columns[1].add_space(20.0);
                    columns[1].heading("Response");
                    columns[1].add_space(10.0);

                    // Headers
                    if !self.show_responseheaders.lock().unwrap().is_empty() {
                        columns[1].add(egui::Label::new("Headers"));
                        egui::ScrollArea::vertical()
                            .id_salt("res_headers")
                            .max_height(80.0)
                            .show(&mut columns[1], |ui| {
                                ui.add(
                                egui::TextEdit::multiline(&mut *self.show_responseheaders.lock().unwrap())
                                    .id_salt("res_headers_text")
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(5)
                                    .interactive(false)
                            );
                        });
                        columns[1].add_space(10.0);
                    }

                    // Body
                    columns[1].add(egui::Label::new("Body"));
                    egui::ScrollArea::vertical()
                        .id_salt("res_body")
                        .max_height(350.0)
                        .show(&mut columns[1], |ui| {
                            ui.add(
                            egui::TextEdit::multiline(&mut *self.show_responsedetails.lock().unwrap())
                                .id_salt("res_body_text")
                                .desired_width(f32::INFINITY)
                                .desired_rows(10)
                                .interactive(false)
                        );
                    });
                }
            });

        });

        /* Modal - New Request */
        if self.show_newrequest {
            egui::Window::new("New Request")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.add_space(10.0);

                    ui.vertical_centered(|ui| {

                        /* Method Selector */
                        ui.horizontal(|ui| {
                            ui.label("Method:");
                            egui::ComboBox::from_id_salt("request_type_combo")
                                .selected_text(self.request_type.lock().unwrap().as_str())
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut *self.request_type.lock().unwrap(), "GET".to_string(), "GET");
                                    ui.selectable_value(&mut *self.request_type.lock().unwrap(), "POST".to_string(), "POST");
                                    ui.selectable_value(&mut *self.request_type.lock().unwrap(), "PUT".to_string(), "PUT");
                                    ui.selectable_value(&mut *self.request_type.lock().unwrap(), "PATCH".to_string(), "PATCH");
                                    ui.selectable_value(&mut *self.request_type.lock().unwrap(), "DELETE".to_string(), "DELETE");
                                });
                        });

                        /* URL Input */
                        ui.horizontal(|ui| {
                            ui.label("URL:");
                            let requesturl = ui.add(
                                egui::TextEdit::singleline(&mut *self.request_url.lock().unwrap())
                                    .desired_width(330.0)
                                    .hint_text("api.example.com/endpoint")
                            );
                            if self.show_newrequest && self.set_focus == "newrequest" {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                                if !requesturl.has_focus() {
                                    requesturl.request_focus();
                                }
                            }

                            if requesturl.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                let send_enabled = !self.request_url.lock().unwrap().is_empty() && !is_loading;
                                if send_enabled {
                                    self.show_newrequest = false;    
                                    match self.send_request(self.request_type.lock().unwrap().clone(), self.request_url.lock().unwrap().clone(), self.request_headers.lock().unwrap().clone(), self.request_body.lock().unwrap().clone()) {
                                        Ok(_) => {
                                            self.ui_error = None;
                                            *self.show_requestheaders.lock().unwrap() = String::new();
                                            *self.show_requestdetails.lock().unwrap() = String::new();
                                            *self.show_responsedetails.lock().unwrap() = String::new();
                                            *self.show_responseheaders.lock().unwrap() = String::new();
                                            self.selected_response_index = None;
                                        },
                                        Err(e) => {
                                            let error_msg = format!("Error sending request: {}", e);
                                            eprintln!("{}", error_msg);
                                            self.ui_error = Some(error_msg);
                                        }
                                    }
                                    *self.request_url.lock().unwrap() = String::new();
                                }
                            }
                        });

                        ui.add_space(10.0);

                        /* Custom Headers */
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
                            ui.label("Headers:");
                        });
                        ui.add(
                            egui::TextEdit::multiline(&mut *self.request_headers.lock().unwrap())
                                .desired_width(330.0)
                                .desired_rows(3)
                                .hint_text("Content-Type: application/json")
                        );

                        ui.add_space(10.0);

                        /* Custom Body */
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
                            ui.label("Body:");
                        });
                        ui.add(
                            egui::TextEdit::multiline(&mut *self.request_body.lock().unwrap())
                                .desired_width(330.0)
                                .desired_rows(10)
                                .hint_text("{\"key\": \"value\"}")
                        );

                        ui.add_space(20.0);

                        /* Send/Close Buttons */
                        ui.horizontal(|ui| {
                            let send_enabled = !self.request_url.lock().unwrap().is_empty() && !is_loading;
                            
                            if ui.add_enabled(send_enabled, egui::Button::new("Send")).clicked() {
                                self.show_newrequest = false;    
                                match self.send_request( self.request_type.lock().unwrap().clone(), self.request_url.lock().unwrap().clone(), self.request_headers.lock().unwrap().clone(), self.request_body.lock().unwrap().clone()) {
                                    Ok(_) => {
                                        self.ui_error = None;
                                    },
                                    Err(e) => {
                                        let error_msg = format!("Error sending request: {}", e);
                                        eprintln!("{}", error_msg);
                                        self.ui_error = Some(error_msg);
                                    }
                                }
                                *self.request_url.lock().unwrap() = String::new();
                            }

                            if ui.button("Cancel").clicked() {
                                self.show_newrequest = false;
                            }
                        });
                    });
                });
        }

        if !self.set_focus.is_empty() {
            self.set_focus = String::new();
        }

        if is_loading {
            ctx.request_repaint();
        }
    }
}


fn main() -> Result<(), Box<dyn Error>> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1700.0, 900.0])
            .with_active(true),
        ..Default::default()
    };

    match eframe::run_native(
        "Nancy Web Debugger",
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