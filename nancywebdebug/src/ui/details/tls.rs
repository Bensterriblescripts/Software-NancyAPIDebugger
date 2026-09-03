use crate::diagnostics::DiagnosticTrace;
use eframe::egui;

use super::summary::summary_row;

pub(in crate::ui) fn show(ui: &mut egui::Ui, trace: &DiagnosticTrace) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.heading("TLS and Certificates");
        let Some(tls) = &trace.tls else {
            ui.weak(if trace.url.scheme == "http" {
                "Not applicable to plain HTTP."
            } else {
                "No TLS information captured yet."
            });
            return;
        };
        egui::Grid::new("tls_grid").striped(true).show(ui, |ui| {
            summary_row(ui, "SNI", &tls.server_name);
            summary_row(
                ui,
                "TLS version",
                tls.version.as_deref().unwrap_or("Unknown"),
            );
            summary_row(
                ui,
                "Cipher suite",
                tls.cipher_suite.as_deref().unwrap_or("Unknown"),
            );
            summary_row(ui, "ALPN", tls.alpn.as_deref().unwrap_or("None"));
            summary_row(
                ui,
                "Validation",
                tls.validation.as_deref().unwrap_or("Unknown"),
            );
        });
        if let Some(error) = &tls.validation_error {
            ui.colored_label(egui::Color32::LIGHT_RED, error);
        }
        ui.add_space(12.0);
        for (index, certificate) in tls.certificates.iter().enumerate() {
            egui::CollapsingHeader::new(format!(
                "Certificate {}: {}",
                index + 1,
                certificate.subject
            ))
            .default_open(index == 0)
            .show(ui, |ui| {
                egui::Grid::new(format!("certificate_{index}"))
                    .striped(true)
                    .show(ui, |ui| {
                        summary_row(ui, "Subject", &certificate.subject);
                        summary_row(ui, "Issuer", &certificate.issuer);
                        summary_row(ui, "Serial", &certificate.serial);
                        summary_row(ui, "Valid from", &certificate.not_before);
                        summary_row(ui, "Valid until", &certificate.not_after);
                        summary_row(ui, "Public key", &certificate.public_key_algorithm);
                        summary_row(ui, "Signature", &certificate.signature_algorithm);
                        summary_row(ui, "SHA-256", &certificate.sha256);
                    });
                ui.strong("Subject alternative names");
                for name in &certificate.subject_alt_names {
                    ui.monospace(name);
                }
            });
        }
    });
}
