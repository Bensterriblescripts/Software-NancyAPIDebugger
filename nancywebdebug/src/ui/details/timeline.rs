use crate::diagnostics::DiagnosticTrace;
use eframe::egui;

pub(in crate::ui) fn show(ui: &mut egui::Ui, trace: &DiagnosticTrace) {
    ui.heading("Timeline");
    egui::Grid::new("timeline_grid")
        .striped(true)
        .min_col_width(120.0)
        .show(ui, |ui| {
            ui.strong("Stage");
            ui.strong("Status");
            ui.strong("Duration");
            ui.strong("Detail");
            ui.end_row();
            for stage in &trace.stages {
                ui.label(stage.kind.to_string());
                ui.label(stage.status.to_string());
                ui.label(
                    stage
                        .duration_ms
                        .map(|duration| format!("{duration:.2} ms"))
                        .unwrap_or_else(|| "—".to_owned()),
                );
                ui.label(&stage.detail);
                ui.end_row();
            }
        });
}
