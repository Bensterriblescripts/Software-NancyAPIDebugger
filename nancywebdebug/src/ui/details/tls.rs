use crate::diagnostics::DiagnosticTrace;
use eframe::egui;

pub(in crate::ui) fn show(ui: &mut egui::Ui, trace: &DiagnosticTrace) {
    ({
        eframe::egui::ScrollArea::both()
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.style_mut().wrap_mode = Some(eframe::egui::TextWrapMode::Extend);
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
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                            (ui, "SNI", &tls.server_name);
                        ui.strong(label);
                        ui.label(value);
                        ui.end_row();
                    });
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                            ui,
                            "TLS version",
                            tls.version.as_deref().unwrap_or("Unknown"),
                        );
                        ui.strong(label);
                        ui.label(value);
                        ui.end_row();
                    });
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                            ui,
                            "Cipher suite",
                            tls.cipher_suite.as_deref().unwrap_or("Unknown"),
                        );
                        ui.strong(label);
                        ui.label(value);
                        ui.end_row();
                    });
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                            (ui, "ALPN", tls.alpn.as_deref().unwrap_or("None"));
                        ui.strong(label);
                        ui.label(value);
                        ui.end_row();
                    });
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                            ui,
                            "Validation",
                            tls.validation.as_deref().unwrap_or("Unknown"),
                        );
                        ui.strong(label);
                        ui.label(value);
                        ui.end_row();
                    });
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                            ui,
                            "Client authentication",
                            &tls.client_auth.status.to_string(),
                        );
                        ui.strong(label);
                        ui.label(value);
                        ui.end_row();
                    });
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                            ui,
                            "CertificateRequest",
                            if tls.client_auth.certificate_requested {
                                "Observed"
                            } else {
                                "Not observed"
                            },
                        );
                        ui.strong(label);
                        ui.label(value);
                        ui.end_row();
                    });
                    if let Some(profile) = &tls.client_auth.profile_name {
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                (ui, "Client-certificate profile", profile);
                            ui.strong(label);
                            ui.label(value);
                            ui.end_row();
                        });
                    }
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
                                ({
                                    let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                        (ui, "Subject", &certificate.subject);
                                    ui.strong(label);
                                    ui.label(value);
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                        (ui, "Issuer", &certificate.issuer);
                                    ui.strong(label);
                                    ui.label(value);
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                        (ui, "Serial", &certificate.serial);
                                    ui.strong(label);
                                    ui.label(value);
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                        (ui, "Valid from", &certificate.not_before);
                                    ui.strong(label);
                                    ui.label(value);
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                        (ui, "Valid until", &certificate.not_after);
                                    ui.strong(label);
                                    ui.label(value);
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                        (ui, "Public key", &certificate.public_key_algorithm);
                                    ui.strong(label);
                                    ui.label(value);
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                        (ui, "Signature", &certificate.signature_algorithm);
                                    ui.strong(label);
                                    ui.label(value);
                                    ui.end_row();
                                });
                                ({
                                    let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                        (ui, "SHA-256", &certificate.sha256);
                                    ui.strong(label);
                                    ui.label(value);
                                    ui.end_row();
                                });
                            });
                        ui.strong("Subject alternative names");
                        for name in &certificate.subject_alt_names {
                            ui.monospace(name);
                        }
                    });
                }
            });
    });
}
