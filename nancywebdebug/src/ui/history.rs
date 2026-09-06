use crate::ExposureScanRequest;
use eframe::egui;

pub(super) struct HistoryEntry {
    pub(super) scan_number: usize,
    pub(super) request: ExposureScanRequest,
    pub(super) error: Option<String>,
    pub(super) warnings: Vec<String>,
}

pub(super) fn show(
    ctx: &egui::Context,
    history: &[HistoryEntry],
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
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(&entry.request.diagnostic_request.url);
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .add_enabled(!is_active, egui::Button::new("Rescan"))
                                        .clicked()
                                    {
                                        rescan = Some(entry.request.clone());
                                    }
                                },
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(entry.scan_number.to_string())
                                    .small()
                                    .weak(),
                            );
                            if entry.error.is_some() {
                                ui.colored_label(egui::Color32::RED, "Failed");
                            } else {
                                ui.colored_label(egui::Color32::GREEN, "Success");
                            }
                        });
                        if let Some(error) = &entry.error {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(error).color(egui::Color32::RED),
                                )
                                .wrap(),
                            );
                        }
                        for warning in &entry.warnings {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(warning).color(egui::Color32::YELLOW),
                                )
                                .wrap(),
                            );
                        }
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
