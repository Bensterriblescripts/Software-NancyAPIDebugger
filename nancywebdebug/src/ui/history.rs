use crate::{ExposureScanReport, ExposureScanRequest, PortState};
use eframe::egui;

pub(super) struct HistoryEntry {
    pub(super) scan_number: usize,
    pub(super) report: ExposureScanReport,
}

pub(super) fn show(
    ctx: &egui::Context,
    history: &[HistoryEntry],
    selected_scan: &mut Option<usize>,
    is_active: bool,
) -> Option<ExposureScanRequest> {
    let mut rescan = None;
    egui::SidePanel::left("history")
        .resizable(true)
        .default_width(480.0)
        .show(ctx, |ui| {
            ui.heading("Public Exposure Scans");
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for entry in history {
                    let selected = *selected_scan == Some(entry.scan_number);
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            if ui
                                .selectable_label(
                                    selected,
                                    &entry.report.request.diagnostic_request.url,
                                )
                                .clicked()
                            {
                                *selected_scan = Some(entry.scan_number);
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .add_enabled(!is_active, egui::Button::new("Rescan"))
                                        .clicked()
                                    {
                                        rescan = Some(entry.report.request.clone());
                                    }
                                },
                            );
                        });
                        let open = entry
                            .report
                            .endpoints
                            .iter()
                            .filter(|endpoint| endpoint.state == PortState::Open)
                            .count();
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(entry.scan_number.to_string())
                                    .small()
                                    .weak(),
                            );
                            ui.label(entry.report.status.to_string());
                            ui.weak(format!(
                                "{open} open; {} security summary items",
                                entry.report.findings.len()
                            ));
                        });
                    });
                    ui.add_space(6.0);
                }
                if history.is_empty() {
                    ui.weak("No scans yet.");
                }
            });
        });
    rescan
}
