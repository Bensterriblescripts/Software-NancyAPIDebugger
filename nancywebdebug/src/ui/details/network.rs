use crate::diagnostics::DiagnosticTrace;
use eframe::egui;

pub(in crate::ui) fn show(ui: &mut egui::Ui, trace: &DiagnosticTrace) {
    ({
        eframe::egui::ScrollArea::both()
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.style_mut().wrap_mode = Some(eframe::egui::TextWrapMode::Extend);
                if trace.dns.configured_resolvers.is_empty() {
                    ui.weak("Pending");
                } else {
                    for resolver in &trace.dns.configured_resolvers {
                        ui.monospace(resolver);
                    }
                }
                ui.add_space(8.0);
                if !trace.dns.incomplete_record_types.is_empty() {
                    ui.strong(format!(
                        "DNS record inventory incomplete. Unfinished queries: {}",
                        trace.dns.incomplete_record_types.join(", ")
                    ));
                    ui.add_space(8.0);
                }
                egui::Grid::new("dns_attempts")
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Query");
                        ui.strong("Configured resolver");
                        ui.strong("Actual responder");
                        ui.strong("Transport");
                        ui.strong("Response code");
                        ui.strong("Duration");
                        ui.strong("Error");
                        ui.end_row();
                        for attempt in &trace.dns.attempts {
                            ui.label(&attempt.record_type);
                            ui.monospace(&attempt.configured_resolver);
                            ui.monospace(
                                attempt
                                    .responder
                                    .map(|address| address.to_string())
                                    .unwrap_or_else(|| "—".to_owned()),
                            );
                            ui.label(&attempt.transport);
                            ui.label(attempt.response_code.as_deref().unwrap_or("—"));
                            ui.label(format!("{:.2} ms", attempt.duration_ms));
                            ui.label(attempt.error.as_deref().unwrap_or(""));
                            ui.end_row();
                        }
                    });
                ui.add_space(8.0);
                egui::Grid::new("dns_records").striped(true).show(ui, |ui| {
                    ui.strong("Name");
                    ui.strong("Type");
                    ui.strong("TTL");
                    ui.strong("Value");
                    ui.end_row();
                    for record in &trace.dns.records {
                        ui.label(&record.name);
                        ui.label(&record.record_type);
                        ui.label(format!("{} s", record.ttl));
                        ui.monospace(&record.value);
                        ui.end_row();
                    }
                });

                ui.add_space(18.0);
                ui.heading("Connection Attempts");
                egui::Grid::new("connections").striped(true).show(ui, |ui| {
                    ui.strong("Selected");
                    ui.strong("Family");
                    ui.strong("Remote");
                    ui.strong("Local");
                    ui.strong("Duration");
                    ui.strong("Outcome");
                    ui.strong("Error");
                    ui.end_row();
                    for attempt in &trace.connections {
                        ui.label(if attempt.selected { "✓" } else { "" });
                        ui.label(&attempt.family);
                        ui.monospace(attempt.remote.to_string());
                        ui.monospace(
                            attempt
                                .local
                                .map(|address| address.to_string())
                                .unwrap_or_else(|| "—".to_owned()),
                        );
                        ui.label(format!("{:.2} ms", attempt.duration_ms));
                        ui.label(attempt.outcome.to_string());
                        let mut error = attempt.error.clone().unwrap_or_default();
                        if let Some(code) = attempt.os_error {
                            if !error.is_empty() {
                                error.push_str("; ");
                            }
                            error.push_str(&format!("OS code {code}"));
                        }
                        ui.label(error);
                        ui.end_row();
                    }
                });
            });
    });
}
