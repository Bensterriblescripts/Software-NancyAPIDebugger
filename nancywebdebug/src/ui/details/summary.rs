use crate::diagnostics::DiagnosticTrace;
use eframe::egui;
use std::time::{SystemTime, UNIX_EPOCH};

use super::timeline;
use crate::ui::widgets::display_url;

pub(in crate::ui) fn show(
    ui: &mut egui::Ui,
    trace: &DiagnosticTrace,
    request_chain: &[&DiagnosticTrace],
) {
    let urls = request_chain
        .iter()
        .map(|trace| display_url(trace))
        .collect::<Vec<_>>();
    let start_url = urls.first().copied().unwrap_or_else(|| display_url(trace));
    let final_url = urls.last().copied().unwrap_or_else(|| display_url(trace));
    let additional_redirects = if urls.len() > 2 {
        urls[1..urls.len() - 1].join("\n")
    } else {
        "None".to_owned()
    };
    let redirect_location = trace
        .http
        .response_headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("location"))
        .map(|header| header.display_value().into_owned())
        .unwrap_or_else(|| "None".to_owned());
    let (certificate_expiry, certificate_expiry_color) = certificate_expiry(trace);
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.heading("Diagnostic Summary");
        egui::Grid::new("summary_grid")
            .striped(true)
            .show(ui, |ui| {
                summary_row(ui, "Outcome", &trace.outcome.to_string());
                summary_row(ui, "Method", &trace.request.method);
                summary_row(ui, "Start URL", start_url);
                summary_row(ui, "Additional Redirects", &additional_redirects);
                summary_row(ui, "Final URL", final_url);
                summary_row(
                    ui,
                    "Authentication",
                    &trace
                        .request
                        .auth
                        .as_ref()
                        .map(|auth| format!("{} ({})", auth.profile_name, auth.profile_kind))
                        .unwrap_or_else(|| "None".to_owned()),
                );
                summary_row(
                    ui,
                    "Request mode",
                    if trace.request.follow_redirects {
                        "Follow redirects (each hop is traced)"
                    } else {
                        "Direct (redirects are not followed)"
                    },
                );
                summary_row(ui, "Raw Location", &redirect_location);
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
                summary_row(ui, "Mode", &trace.connection_mode);
                summary_row(ui, "Requested protocol", &trace.http.requested_protocol);
                summary_row(
                    ui,
                    "Negotiated protocol",
                    trace.http.version.as_deref().unwrap_or("Pending"),
                );
                summary_row(ui, "Status", &trace.status_text());
                colored_summary_row(
                    ui,
                    "Certificate expiry",
                    &certificate_expiry,
                    certificate_expiry_color,
                );
                summary_row(ui, "Web server", &trace.fingerprint.web_server);
                summary_row(
                    ui,
                    "Fingerprint status",
                    &trace.fingerprint.status.to_string(),
                );
                summary_row(ui, "Confidence", &trace.fingerprint.confidence);
                summary_row(ui, "Raw body capture", &trace.body.raw_capture_status());
                summary_row(
                    ui,
                    "Decoded body capture",
                    &trace.body.decoded_capture_status(),
                );
            });
        egui::CollapsingHeader::new("Evidence").show(ui, |ui| {
            if trace.fingerprint.evidence.is_empty() {
                ui.weak("None");
            } else {
                for evidence in &trace.fingerprint.evidence {
                    ui.label(evidence);
                }
            }
        });
        if let Some(error) = &trace.error {
            ui.add_space(12.0);
            ui.colored_label(
                egui::Color32::LIGHT_RED,
                format!("{}: {}", error.stage, error.message),
            );
        }
        if let Some(reason) = &trace.redirect_stop_reason {
            ui.add_space(12.0);
            ui.colored_label(egui::Color32::YELLOW, reason);
        }
        if !trace.complete || trace.fingerprint.is_active() {
            ui.add_space(12.0);
            ui.spinner();
        }
        ui.add_space(12.0);
        timeline::show(ui, trace);
    });
}

pub(super) fn summary_row(ui: &mut egui::Ui, label: &str, value: &str) {
    colored_summary_row(ui, label, value, None);
}

fn colored_summary_row(ui: &mut egui::Ui, label: &str, value: &str, color: Option<egui::Color32>) {
    ui.strong(label);
    if let Some(color) = color {
        ui.colored_label(color, value);
    } else {
        ui.label(value);
    }
    ui.end_row();
}

fn certificate_expiry(trace: &DiagnosticTrace) -> (String, Option<egui::Color32>) {
    let days = trace
        .tls
        .as_ref()
        .and_then(|tls| tls.certificates.first())
        .and_then(|certificate| certificate.not_after_unix)
        .and_then(|not_after| {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
            let now = i64::try_from(now.as_secs()).ok()?;
            not_after.checked_sub(now)
        })
        .map(|seconds| seconds.div_euclid(86_400));

    match days {
        Some(days) if days < 7 => (format!("{days} days"), Some(egui::Color32::RED)),
        Some(days) if days <= 30 => (format!("{days} days"), Some(egui::Color32::YELLOW)),
        Some(days) => (format!("{days} days"), None),
        None => ("Unknown".to_owned(), None),
    }
}
