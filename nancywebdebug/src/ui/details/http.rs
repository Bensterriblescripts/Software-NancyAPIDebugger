use crate::diagnostics::{DiagnosticTrace, HeaderTrace, escaped_bytes};
use eframe::egui;

use super::body::show_text;
use super::summary::summary_row;

pub(in crate::ui) fn show(ui: &mut egui::Ui, trace: &DiagnosticTrace) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.heading("HTTP Exchange");
        egui::Grid::new("http_summary")
            .striped(true)
            .show(ui, |ui| {
                summary_row(ui, "Requested", &trace.http.requested_protocol);
                summary_row(
                    ui,
                    "Negotiated",
                    trace.http.version.as_deref().unwrap_or("Pending"),
                );
                summary_row(ui, "Status", &trace.status_text());
                summary_row(ui, "Final URL", &trace.http.final_url);
                summary_row(
                    ui,
                    "Request mode",
                    if trace.request.follow_redirects {
                        "Follow redirects (each hop is traced)"
                    } else {
                        "Direct (redirects are not followed)"
                    },
                );
                summary_row(
                    ui,
                    "Redirect target",
                    trace.redirect_target.as_deref().unwrap_or("None"),
                );
                summary_row(
                    ui,
                    "Redirect followed",
                    if trace.redirect_followed { "Yes" } else { "No" },
                );
                summary_row(
                    ui,
                    "Redirect stop reason",
                    trace.redirect_stop_reason.as_deref().unwrap_or("None"),
                );
            });
        if let Some(reason) = &trace.redirect_stop_reason {
            ui.add_space(8.0);
            ui.colored_label(egui::Color32::YELLOW, reason);
        }
        ui.add_space(12.0);
        ui.heading(if trace.http.headers_sent {
            "Request Header Fields"
        } else {
            "Prepared Request Header Fields"
        });
        if !trace.http.request_header_representation.is_empty() {
            ui.weak(&trace.http.request_header_representation);
        }
        show_headers(ui, "sent_headers", &trace.http.request_headers);
        if let Some(serialized) = &trace.http.actual_http1_request_headers {
            egui::CollapsingHeader::new("Actual transmitted HTTP/1.1 header bytes").show(
                ui,
                |ui| {
                    let text = escaped_bytes(serialized);
                    show_text(ui, text.as_ref());
                },
            );
        } else if matches!(trace.http.version.as_deref(), Some("HTTP/2" | "HTTP/3")) {
            ui.weak("Decoded protocol fields are shown; compressed wire bytes are unavailable.");
        }
        ui.add_space(12.0);
        ui.heading("Response Headers");
        show_headers(ui, "response_headers", &trace.http.response_headers);
        if !trace.http.response_trailers.is_empty() {
            ui.add_space(8.0);
            ui.heading("Response Trailers");
            show_headers(ui, "response_trailers", &trace.http.response_trailers);
        }
    });
}

fn show_headers(ui: &mut egui::Ui, id: &str, headers: &[HeaderTrace]) {
    if headers.is_empty() {
        ui.weak("None captured.");
        return;
    }
    egui::Grid::new(id).striped(true).show(ui, |ui| {
        ui.strong("Name");
        ui.strong("Value");
        ui.end_row();
        for header in headers {
            let name = display_header_name(&header.name);
            if header.pseudo {
                ui.monospace(egui::RichText::new(name).color(egui::Color32::LIGHT_BLUE));
            } else {
                ui.monospace(name);
            }
            ui.monospace(header.display_value());
            ui.end_row();
        }
    });
}

fn display_header_name(name: &str) -> &str {
    if name.eq_ignore_ascii_case("content-security-policy-report-only") {
        "CSP-Report-Only"
    } else if name.eq_ignore_ascii_case("content-security-policy") {
        "CSP"
    } else {
        name
    }
}
