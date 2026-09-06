use crate::diagnostics::DiagnosticTrace;
use crate::ui::disclosure::show_with_default_open as disclosure;
use eframe::egui;

pub(in crate::ui) fn show(ui: &mut egui::Ui, trace: &DiagnosticTrace) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
            if trace.dns.configured_resolvers.is_empty() {
                ui.weak("Pending");
            }
            for resolver in &trace.dns.configured_resolvers {
                ui.monospace(resolver);
            }
            ui.add_space(8.0);
            if !trace.dns.incomplete_record_types.is_empty() {
                ui.strong(format!(
                    "DNS record inventory incomplete. Failed or unfinished queries: {}",
                    trace.dns.incomplete_record_types.join(", ")
                ));
            }
            disclosure(
                ui,
                "dns-outcomes",
                "DNS Lookup Coverage",
                true,
                |_| {},
                |ui| {
                    for outcome in &trace.dns.lookup_outcomes {
                        ui.label(format!(
                            "{}: {} - {} -> {}",
                            outcome.record_type,
                            outcome.status,
                            outcome.queried_name,
                            outcome.terminal_name
                        ));
                        for (owner, target) in &outcome.aliases {
                            ui.weak(format!("{owner} -> {target}"));
                        }
                        if let Some(error) = &outcome.failure {
                            ui.label(error);
                        }
                    }
                },
            );
            disclosure(
                ui,
                "dns-queries",
                egui::RichText::new(format!("DNS Queries ({})", trace.dns.attempts.len()))
                    .heading(),
                true,
                |ui| {
                    ui.label(format!(
                        "{:.2} ms total query time; {} errors",
                        trace
                            .dns
                            .attempts
                            .iter()
                            .map(|attempt| attempt.duration_ms)
                            .sum::<f64>(),
                        trace
                            .dns
                            .attempts
                            .iter()
                            .filter(|attempt| attempt.error.is_some())
                            .count()
                    ));
                },
                |ui| {
                    egui::ScrollArea::horizontal()
                        .id_salt("dns_attempts-scroll")
                        .show(ui, |ui| {
                            egui::Grid::new("dns_attempts")
                                .striped(true)
                                .show(ui, |ui| {
                                    for heading in [
                                        "Query",
                                        "Configured resolver",
                                        "Actual responder",
                                        "Transport",
                                        "Response code",
                                        "Duration",
                                        "Error",
                                    ] {
                                        ui.strong(heading);
                                    }
                                    ui.end_row();
                                    for attempt in &trace.dns.attempts {
                                        ui.label(&attempt.record_type);
                                        ui.monospace(&attempt.configured_resolver);
                                        ui.monospace(
                                            attempt
                                                .responder
                                                .map(|address| address.to_string())
                                                .unwrap_or_else(|| "-".to_owned()),
                                        );
                                        ui.label(&attempt.transport);
                                        ui.label(attempt.response_code.as_deref().unwrap_or("-"));
                                        ui.label(format!("{:.2} ms", attempt.duration_ms));
                                        ui.label(attempt.error.as_deref().unwrap_or(""));
                                        ui.end_row();
                                    }
                                });
                        });
                },
            );
            ui.add_space(8.0);
            disclosure(
                ui,
                "dns-records",
                egui::RichText::new(format!("DNS Records ({})", trace.dns.records.len())).heading(),
                true,
                |_| {},
                |ui| {
                    egui::ScrollArea::horizontal()
                        .id_salt("dns_records-scroll")
                        .show(ui, |ui| {
                            egui::Grid::new("dns_records").striped(true).show(ui, |ui| {
                                for heading in ["Name", "Type", "TTL", "Value"] {
                                    ui.strong(heading);
                                }
                                ui.end_row();
                                for record in &trace.dns.records {
                                    ui.label(&record.name);
                                    ui.label(&record.record_type);
                                    ui.label(format!("{} s", record.ttl));
                                    ui.label(&record.value);
                                    ui.end_row();
                                }
                            });
                        });
                },
            );
            ui.add_space(8.0);
            ui.label(&trace.connection_mode);
            disclosure(
                ui,
                "connections",
                egui::RichText::new(format!("Connections ({})", trace.connections.len())).heading(),
                true,
                |_| {},
                |ui| {
                    egui::ScrollArea::horizontal()
                        .id_salt("connections-scroll")
                        .show(ui, |ui| {
                            egui::Grid::new("connections").striped(true).show(ui, |ui| {
                                for heading in [
                                    "Remote", "Local", "Family", "Duration", "Outcome", "Selected",
                                    "OS error", "Error",
                                ] {
                                    ui.strong(heading);
                                }
                                ui.end_row();
                                for attempt in &trace.connections {
                                    ui.monospace(attempt.remote.to_string());
                                    ui.monospace(
                                        attempt
                                            .local
                                            .map(|address| address.to_string())
                                            .unwrap_or_else(|| "-".to_owned()),
                                    );
                                    ui.label(&attempt.family);
                                    ui.label(format!("{:.2} ms", attempt.duration_ms));
                                    ui.label(attempt.outcome.to_string());
                                    ui.label(if attempt.selected { "Yes" } else { "No" });
                                    ui.label(
                                        attempt
                                            .os_error
                                            .map(|code| code.to_string())
                                            .unwrap_or_default(),
                                    );
                                    ui.label(attempt.error.as_deref().unwrap_or(""));
                                    ui.end_row();
                                }
                            });
                        });
                },
            );
        });
}
