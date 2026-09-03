use crate::diagnostics::{DiagnosticTrace, TraceOutcome};
use eframe::egui;

use super::BodyView;

pub(in crate::ui) fn show(ui: &mut egui::Ui, trace: &DiagnosticTrace, view: &mut BodyView) {
    if !trace.body.decoded_is_text && !trace.body.raw.is_empty() {
        *view = BodyView::Hex;
    }
    ui.horizontal(|ui| {
        ui.heading("Response Body");
        ui.separator();
        ui.add_enabled_ui(
            trace.body.decoded_is_text || trace.body.raw.is_empty(),
            |ui| {
                ui.selectable_value(view, BodyView::Decoded, "Decoded");
            },
        );
        ui.selectable_value(view, BodyView::Hex, "Raw / Hex");
    });
    ui.horizontal_wrapped(|ui| {
        ui.label(format!("Raw: {}", trace.body.raw_capture_status()));
        ui.label(format!("Decoded: {}", trace.body.decoded_capture_status()));
        ui.label(format!(
            "Content-Type: {}",
            trace.body.content_type.as_deref().unwrap_or("Not supplied")
        ));
        ui.label(format!(
            "Content-Encoding: {}",
            trace.body.content_encoding.as_deref().unwrap_or("identity")
        ));
    });
    if let Some(error) = &trace.body.decode_error {
        ui.colored_label(egui::Color32::YELLOW, error);
    }
    ui.separator();
    match view {
        BodyView::Decoded => {
            if trace.body.decoded.is_empty() {
                ui.weak(if trace.outcome == TraceOutcome::Running {
                    "Waiting for body completion..."
                } else {
                    "<empty>"
                });
            } else {
                egui::ScrollArea::both().show(ui, |ui| show_text(ui, trace.body.decoded.as_ref()));
            }
        }
        BodyView::Hex => show_hex(ui, trace.body.raw.as_ref()),
    }
}

pub(super) fn show_text(ui: &mut egui::Ui, text: &str) {
    ui.add(egui::Label::new(egui::RichText::new(text).monospace()).selectable(true));
}

fn show_hex(ui: &mut egui::Ui, bytes: &[u8]) {
    if bytes.is_empty() {
        ui.weak("<empty>");
        return;
    }
    let rows = bytes.len().div_ceil(16);
    egui::ScrollArea::both().show_rows(ui, 18.0, rows, |ui, range| {
        for row in range {
            let offset = row * 16;
            let end = (offset + 16).min(bytes.len());
            let chunk = &bytes[offset..end];
            let hex = chunk
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            let ascii = chunk
                .iter()
                .map(|byte| {
                    if byte.is_ascii_graphic() || *byte == b' ' {
                        char::from(*byte)
                    } else {
                        '.'
                    }
                })
                .collect::<String>();
            ui.monospace(format!("{offset:08X}  {hex:<47}  |{ascii}|"));
        }
    });
}
