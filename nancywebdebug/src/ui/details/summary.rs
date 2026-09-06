use crate::diagnostics::DiagnosticTrace;
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
        eframe::egui::ScrollArea::both().auto_shrink([false, true]).show(ui, |ui| { ui.style_mut().wrap_mode = Some(eframe::egui::TextWrapMode::Extend);
        ui.heading("Diagnostic Summary");
        egui::Grid::new("summary_grid")
            .striped(true)
            .show(ui, |ui| {
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Outcome", &trace.outcome.to_string()); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Method", &trace.request.method); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Start URL", start_url); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Additional Redirects", &additional_redirects); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Final URL", final_url); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Authentication", &trace
                        .request
                        .auth
                        .as_ref()
                        .map(|auth| format!("{} ({})", auth.profile_name, auth.profile_kind))
                        .unwrap_or_else(|| "None".to_owned())); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Client certificate", &trace
                        .request
                        .client_certificate
                        .as_ref()
                        .map(|certificate| {
                            format!(
                                "{} — subject {} — issuer {} — serial {} — valid until {} — SHA-256 {}",
                                certificate.profile_name,
                                certificate.subject,
                                certificate.issuer,
                                certificate.serial,
                                certificate.not_after,
                                certificate.sha256
                            )
                        })
                        .unwrap_or_else(|| "None".to_owned())); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Request mode", if trace.request.follow_redirects {
                        "Follow redirects (each hop is traced)"
                    } else {
                        "Direct (redirects are not followed)"
                    }); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Raw Location", &redirect_location); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Redirect target", trace.redirect_target.as_deref().unwrap_or("None")); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Redirect followed", if trace.redirect_followed { "Yes" } else { "No" }); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Redirect stop reason", trace.redirect_stop_reason.as_deref().unwrap_or("None")); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Mode", &trace.connection_mode); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Requested protocol", &trace.http.requested_protocol); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Negotiated protocol", trace.http.version.as_deref().unwrap_or("Pending")); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Status", &trace.status_text()); ui.strong(label); ui.label(value); ui.end_row(); });
                ({
let (ui, label, value, color,): (& mut egui :: Ui, & str, & str, Option < egui :: Color32 >,) = (ui, "Certificate expiry", &certificate_expiry, certificate_expiry_color,);

    ui.strong(label);
    if let Some(color) = color {
        ui.colored_label(color, value);
    } else {
        ui.label(value);
    }
    ui.end_row();

});
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Web server", &trace.fingerprint.web_server); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Fingerprint status", &trace.fingerprint.status.to_string()); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Confidence", &trace.fingerprint.confidence); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Raw body capture", &trace.body.raw_capture_status()); ui.strong(label); ui.label(value); ui.end_row(); });
                ({ let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (ui, "Decoded body capture", &trace.body.decoded_capture_status()); ui.strong(label); ui.label(value); ui.end_row(); });
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
        if !trace.complete {
            ui.add_space(12.0);
            ui.spinner();
        }
        ui.add_space(12.0);
        ({
            let (ui, trace): (&mut egui::Ui, &DiagnosticTrace) = (ui, trace);

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
}
