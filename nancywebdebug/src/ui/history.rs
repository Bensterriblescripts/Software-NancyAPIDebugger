use crate::diagnostics::{DiagnosticRequest, DiagnosticTrace};
use eframe::egui;

use super::widgets::{display_url, outcome_label};

pub(super) struct HistoryEntry {
    pub(super) request_number: usize,
    pub(super) trace: DiagnosticTrace,
}

pub(super) fn show(
    ctx: &egui::Context,
    history: &[HistoryEntry],
    selected_index: &mut Option<usize>,
    is_active: bool,
) -> Option<DiagnosticRequest> {
    let mut resend = None;
    egui::SidePanel::left("history")
        .resizable(true)
        .default_width(480.0)
        .show(ctx, |ui| {
            ui.heading("Request History");
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for entry in history {
                    let trace = &entry.trace;
                    let selected = *selected_index == Some(trace.index);
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            let label = format!("{} {}", trace.request.method, display_url(trace));
                            if ui.selectable_label(selected, label).clicked() {
                                *selected_index = Some(trace.index);
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .add_enabled(!is_active, egui::Button::new("Resend"))
                                        .clicked()
                                    {
                                        resend = Some(trace.request.clone());
                                    }
                                },
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(entry.request_number.to_string())
                                    .small()
                                    .weak(),
                            );
                            outcome_label(ui, trace.outcome);
                            ui.label(trace.status_text());
                            if let Some(auth) = &trace.request.auth {
                                ui.weak(format!(
                                    "Auth: {} ({})",
                                    auth.profile_name, auth.profile_kind
                                ));
                            }
                            if let Some(stage) = trace.stages.last() {
                                ui.weak(format!("{}: {}", stage.kind, stage.status));
                            }
                        });
                    });
                    ui.add_space(6.0);
                }
                if history.is_empty() {
                    ui.weak("No requests sent yet.");
                }
            });
        });
    resend
}
