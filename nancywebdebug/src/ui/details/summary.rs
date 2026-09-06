use crate::diagnostics::DiagnosticTrace;
use crate::ui::disclosure::show as disclosure;
use crate::ui::report_layout::{ITEM_SPACING, LabelValueRows, section_space};
use eframe::egui;
use std::time::{SystemTime, UNIX_EPOCH};

pub(in crate::ui) fn show(
    ui: &mut egui::Ui,
    trace: &DiagnosticTrace,
    request_chain: &[&DiagnosticTrace],
) {
    let urls = request_chain
        .iter()
        .map(|trace| {
            let trace: &crate::diagnostics::DiagnosticTrace = trace;
            if trace.url.normalized.is_empty() {
                trace.request.url.as_str()
            } else {
                trace.url.normalized.as_str()
            }
        })
        .collect::<Vec<_>>();
    let start_url = urls.first().copied().unwrap_or_else(|| {
        let trace: &crate::diagnostics::DiagnosticTrace = trace;
        if trace.url.normalized.is_empty() {
            trace.request.url.as_str()
        } else {
            trace.url.normalized.as_str()
        }
    });
    let final_url = urls.last().copied().unwrap_or_else(|| {
        let trace: &crate::diagnostics::DiagnosticTrace = trace;
        if trace.url.normalized.is_empty() {
            trace.request.url.as_str()
        } else {
            trace.url.normalized.as_str()
        }
    });
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
    let (certificate_expiry, certificate_expiry_color) = {
        let (trace,): (&DiagnosticTrace,) = (trace,);
        let inlined_result: (String, Option<egui::Color32>) = {
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
        };
        inlined_result
    };
    ({
        eframe::egui::ScrollArea::vertical().auto_shrink([false, true]).show(ui, |ui| { ui.style_mut().wrap_mode = Some(eframe::egui::TextWrapMode::Wrap);
        ui.spacing_mut().item_spacing.y = ITEM_SPACING;
        ui.heading("Diagnostic Summary");
        LabelValueRows::show(ui, "summary_grid", |ui, rows| {
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Outcome", &trace.outcome.to_string()); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Method", &trace.request.method); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Start URL", start_url); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Additional Redirects", &additional_redirects); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Final URL", final_url); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Authentication", &trace
                        .request
                        .auth
                        .as_ref()
                        .map(|auth| format!("{} ({})", auth.profile_name, auth.profile_kind))
                        .unwrap_or_else(|| "None".to_owned())); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Client certificate", &trace
                        .request
                        .client_certificate
                        .as_ref()
                        .map(|certificate| certificate.profile_name.clone())
                        .unwrap_or_else(|| "None".to_owned())); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Request mode", if trace.request.follow_redirects {
                        "Follow redirects (each hop is traced)"
                    } else {
                        "Direct (redirects are not followed)"
                    }); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Raw Location", &redirect_location); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Redirect target", trace.redirect_target.as_deref().unwrap_or("None")); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Redirect followed", if trace.redirect_followed { "Yes" } else { "No" }); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Redirect stop reason", trace.redirect_stop_reason.as_deref().unwrap_or("None")); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Mode", &trace.connection_mode); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Requested protocol", &trace.http.requested_protocol); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Negotiated protocol", trace.http.version.as_deref().unwrap_or("Pending")); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Status", &trace.status_text()); rows.row(ui, label, value); });
                ({
let (ui, label, value, color,): (& mut egui :: Ui, & str, & str, Option < egui :: Color32 >,) = (ui, "Certificate expiry", &certificate_expiry, certificate_expiry_color,);

    let mut value = egui::RichText::new(value);
    if let Some(color) = color {
        value = value.color(color);
    }
    rows.row(ui, label, value);

});
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Web server", &trace.fingerprint.web_server); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Fingerprint status", &trace.fingerprint.status.to_string()); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Confidence", &trace.fingerprint.confidence); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Raw body capture", &trace.body.raw_capture_status()); rows.row(ui, label, value); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Decoded body capture", &trace.body.decoded_capture_status()); rows.row(ui, label, value); });
            });
        if let Some(certificate) = &trace.request.client_certificate {
            section_space(ui);
            disclosure(ui, "client-certificate", "Client Certificate Details", |_| {}, |ui| {
                ui.label(format!("{} — subject {} — issuer {} — serial {} — valid until {} — SHA-256 {}", certificate.profile_name, certificate.subject, certificate.issuer, certificate.serial, certificate.not_after, certificate.sha256));
            });
        }
        if let Some(error) = &trace.error {
            ui.colored_label(
                egui::Color32::LIGHT_RED,
                format!("{}: {}", error.stage, error.message),
            );
        }
        if let Some(reason) = &trace.redirect_stop_reason {
            ui.colored_label(egui::Color32::YELLOW, reason);
        }
        if !trace.complete {
            ui.spinner();
        }
        section_space(ui);
        ({
            let (ui, trace): (&mut egui::Ui, &DiagnosticTrace) = (ui, trace);

            crate::ui::disclosure::show_with_default_open(ui, "timeline", egui::RichText::new(format!("Timeline ({} stages)", trace.stages.len())).heading(), true,
                |ui| { ui.label(format!("Recorded stage time: {:.2} ms", trace.stages.iter().filter_map(|stage| stage.duration_ms).sum::<f64>())); }, |ui| {
            egui::ScrollArea::horizontal().id_salt("timeline_grid-scroll").auto_shrink([false, true]).show(ui, |ui| {
egui::Grid::new("timeline_grid")
                .num_columns(4)
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
                        ui.label(stage.duration_ms.map_or_else(
                            || "—".to_owned(),
                            |duration| format!("{duration:.2} ms"),
                        ));
                        ui.label(&stage.detail);
                        ui.end_row();
                    }
                });
                });
            });
        });
    });
    });
}
