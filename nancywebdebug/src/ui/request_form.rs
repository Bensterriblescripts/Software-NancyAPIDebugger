use crate::auth::ProfileSummary;
use crate::diagnostics::{ProtocolPreference, StageTimeouts, UserAgentPreset};
use eframe::egui;
use std::time::Duration;

use super::app::App;

#[derive(Debug, Clone)]
pub(super) struct TimeoutInputs {
    authentication: f64,
    dns: f64,
    transport: f64,
    tls: f64,
    headers: f64,
    first_byte: f64,
    body: f64,
}

impl TimeoutInputs {
    pub(super) fn from_timeouts(timeouts: &StageTimeouts) -> Self {
        Self {
            authentication: timeouts.authentication.as_secs_f64(),
            dns: timeouts.dns.as_secs_f64(),
            transport: timeouts.transport.as_secs_f64(),
            tls: timeouts.tls.as_secs_f64(),
            headers: timeouts.headers.as_secs_f64(),
            first_byte: timeouts.first_byte.as_secs_f64(),
            body: timeouts.body.as_secs_f64(),
        }
    }

    pub(super) fn to_timeouts(&self) -> StageTimeouts {
        StageTimeouts {
            authentication: duration(self.authentication),
            dns: duration(self.dns),
            transport: duration(self.transport),
            tls: duration(self.tls),
            headers: duration(self.headers),
            first_byte: duration(self.first_byte),
            body: duration(self.body),
        }
    }
}

pub(super) fn show(ctx: &egui::Context, app: &mut App) -> bool {
    let mut send_form = false;
    if app.show_new_request {
        egui::Window::new("New Request")
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Method");
                    egui::ComboBox::from_id_salt("method")
                        .selected_text(&app.request_method)
                        .show_ui(ui, |ui| {
                            for method in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] {
                                ui.selectable_value(
                                    &mut app.request_method,
                                    method.to_owned(),
                                    method,
                                );
                            }
                        });
                    ui.label("Protocol");
                    egui::ComboBox::from_id_salt("protocol")
                        .selected_text(app.request_protocol.to_string())
                        .show_ui(ui, |ui| {
                            for protocol in ProtocolPreference::ALL {
                                ui.selectable_value(
                                    &mut app.request_protocol,
                                    protocol,
                                    protocol.to_string(),
                                );
                            }
                        });
                });
                ui.label("URL");
                let url = ui.add(
                    egui::TextEdit::singleline(&mut app.request_url)
                        .desired_width(f32::INFINITY)
                        .hint_text("https://api.example.com/endpoint"),
                );
                if app.set_focus {
                    url.request_focus();
                    app.set_focus = false;
                }
                if url.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                    send_form = true;
                }
                ui.label("Headers");
                ui.add(
                    egui::TextEdit::multiline(&mut app.request_headers)
                        .desired_width(f32::INFINITY)
                        .desired_rows(4)
                        .hint_text("Content-Type: application/json"),
                );
                ui.label("Body");
                ui.add(
                    egui::TextEdit::multiline(&mut app.request_body)
                        .desired_width(f32::INFINITY)
                        .desired_rows(8),
                );
                ui.horizontal_wrapped(|ui| {
                    ui.checkbox(&mut app.request_follow_redirects, "Follow All Redirects");
                    ui.label("User-Agent");
                    egui::ComboBox::from_id_salt("user_agent")
                        .selected_text(app.request_user_agent.label())
                        .show_ui(ui, |ui| {
                            for preset in UserAgentPreset::ALL {
                                ui.selectable_value(
                                    &mut app.request_user_agent,
                                    preset,
                                    preset.label(),
                                );
                            }
                        });
                });
                ui.checkbox(
                    &mut app.request_fingerprint_server,
                    "Run intrusive server fingerprint scan (requires root and Nmap)",
                );
                egui::CollapsingHeader::new("Advanced authentication").show(ui, |ui| {
                    let profiles: Vec<ProfileSummary> = app
                        .auth_store
                        .lock()
                        .map(|store| store.summaries())
                        .unwrap_or_default();
                    let selected_text = app
                        .selected_auth_profile
                        .and_then(|id| profiles.iter().find(|profile| profile.id == id))
                        .map(|profile| profile.name.as_str())
                        .unwrap_or("None");
                    ui.horizontal(|ui| {
                        ui.label("Profile");
                        egui::ComboBox::from_id_salt("auth_profile")
                            .selected_text(selected_text)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut app.selected_auth_profile, None, "None");
                                for profile in &profiles {
                                    ui.selectable_value(
                                        &mut app.selected_auth_profile,
                                        Some(profile.id),
                                        &profile.name,
                                    );
                                }
                            });
                        if ui.button("Manage profiles").clicked() {
                            app.show_auth_profiles = true;
                        }
                    });
                    if let Some(profile) = app
                        .selected_auth_profile
                        .and_then(|id| profiles.iter().find(|profile| profile.id == id))
                    {
                        ui.weak(format!(
                            "{} — {}",
                            profile.profile_type.label(),
                            profile.status
                        ));
                    }
                });
                egui::CollapsingHeader::new("Advanced stage timeouts")
                    .show(ui, |ui| show_timeout_inputs(ui, &mut app.timeout_inputs));
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !app.request_url.trim().is_empty(),
                            egui::Button::new("Send"),
                        )
                        .clicked()
                    {
                        send_form = true;
                    }
                    if ui.button("Close").clicked() {
                        app.show_new_request = false;
                    }
                });
            });
    }
    send_form
}

fn show_timeout_inputs(ui: &mut egui::Ui, values: &mut TimeoutInputs) {
    egui::Grid::new("timeouts").show(ui, |ui| {
        timeout_row(ui, "Authentication", &mut values.authentication);
        timeout_row(ui, "DNS", &mut values.dns);
        timeout_row(ui, "TCP / QUIC", &mut values.transport);
        timeout_row(ui, "TLS", &mut values.tls);
        timeout_row(ui, "HTTP headers", &mut values.headers);
        timeout_row(ui, "First byte", &mut values.first_byte);
        timeout_row(ui, "Body", &mut values.body);
    });
}

fn timeout_row(ui: &mut egui::Ui, label: &str, value: &mut f64) {
    ui.label(label);
    ui.add(
        egui::DragValue::new(value)
            .range(0.1..=3600.0)
            .speed(0.5)
            .suffix(" s"),
    );
    ui.end_row();
}

fn duration(seconds: f64) -> Duration {
    Duration::from_secs_f64(seconds.clamp(0.1, 3600.0))
}
