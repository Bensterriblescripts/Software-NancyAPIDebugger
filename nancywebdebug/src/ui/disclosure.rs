use eframe::egui;
use std::hash::Hash;

pub(super) fn show(
    ui: &mut egui::Ui,
    id_salt: impl Hash,
    title: impl Into<egui::WidgetText>,
    summary: impl FnOnce(&mut egui::Ui),
    body: impl FnOnce(&mut egui::Ui),
) {
    show_with_default_open(ui, id_salt, title, false, summary, body);
}

pub(super) fn show_with_default_open(
    ui: &mut egui::Ui,
    id_salt: impl Hash,
    title: impl Into<egui::WidgetText>,
    default_open: bool,
    summary: impl FnOnce(&mut egui::Ui),
    body: impl FnOnce(&mut egui::Ui),
) {
    ui.push_id(id_salt, |ui| {
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
        let id = ui.make_persistent_id("details");
        let mut state =
            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, default_open);
        let header = ui.horizontal_top(|ui| {
            state.show_toggle_button(ui, egui::collapsing_header::paint_default_icon);
            let response = ui.add(egui::Label::new(title).wrap().sense(egui::Sense::click()));
            if response.clicked() {
                state.toggle(ui);
            }
        });
        ui.indent("summary", summary);
        state.show_body_indented(&header.response, ui, body);
    });
}

pub(super) fn evidence(ui: &mut egui::Ui, items: &[String]) {
    if !items.is_empty() {
        show(
            ui,
            "evidence",
            format!("Evidence ({})", items.len()),
            |_| {},
            |ui| {
                for item in items {
                    ui.weak(item);
                }
            },
        );
    }
}

pub(super) fn evidence_item(
    ui: &mut egui::Ui,
    id_salt: impl Hash,
    title: String,
    summary: impl FnOnce(&mut egui::Ui),
    items: &[String],
) {
    if items.is_empty() {
        ui.strong(title);
        summary(ui);
    } else {
        show(
            ui,
            id_salt,
            egui::RichText::new(format!("{title} — Evidence ({})", items.len())).strong(),
            summary,
            |ui| {
                for item in items {
                    ui.weak(item);
                }
            },
        );
    }
}
