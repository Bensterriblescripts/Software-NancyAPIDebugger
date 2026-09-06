use eframe::egui;
use std::hash::Hash;

pub(super) const SECTION_SPACING: f32 = 12.0;
pub(super) const ITEM_SPACING: f32 = 6.0;

pub(super) fn section_space(ui: &mut egui::Ui) {
    ui.add_space((SECTION_SPACING - ui.spacing().item_spacing.y).max(0.0));
}

pub(super) fn section_separator(ui: &mut egui::Ui) {
    let spacing = (SECTION_SPACING - 2.0 * ui.spacing().item_spacing.y).max(0.0);
    ui.add(egui::Separator::default().spacing(spacing));
}

pub(super) struct LabelValueRows {
    index: usize,
}

impl LabelValueRows {
    pub(super) fn show(
        ui: &mut egui::Ui,
        id_salt: impl Hash,
        content: impl FnOnce(&mut egui::Ui, &mut Self),
    ) {
        ui.push_id(id_salt, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            content(ui, &mut Self { index: 0 });
        });
    }

    pub(super) fn row(
        &mut self,
        ui: &mut egui::Ui,
        label: impl Into<egui::WidgetText>,
        value: impl Into<egui::WidgetText>,
    ) {
        let width = ui.available_width();
        let fill = if self.index % 2 == 0 {
            egui::Color32::TRANSPARENT
        } else {
            ui.visuals().faint_bg_color
        };
        self.index += 1;
        let label = label.into().strong();
        let value = value.into();
        egui::Frame::NONE
            .fill(fill)
            .inner_margin(egui::Margin::symmetric(0, 6))
            .show(ui, |ui| {
                ui.set_width(width);
                ui.spacing_mut().item_spacing = egui::vec2(12.0, ITEM_SPACING);
                if width >= 480.0 {
                    ui.horizontal_top(|ui| {
                        cell(ui, 180.0, label);
                        cell(ui, width - 192.0, value);
                    });
                } else {
                    cell(ui, width, label);
                    cell(ui, width, value);
                }
            });
    }
}

fn cell(ui: &mut egui::Ui, width: f32, text: egui::WidgetText) {
    ui.allocate_ui_with_layout(
        egui::vec2(width, 0.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_width(width);
            ui.add(egui::Label::new(text).wrap());
        },
    );
}

pub(super) fn show_status(
    ui: &mut egui::Ui,
    report: &crate::ExposureScanReport,
    show_status_line: bool,
) {
    if show_status_line {
        ui.add(egui::Label::new(format!("Status: {}", report.status)).wrap());
        section_space(ui);
    }
}
