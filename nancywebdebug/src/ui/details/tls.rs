use crate::diagnostics::DiagnosticTrace;
use crate::ui::disclosure::show as disclosure;
use crate::ui::report_layout::{ITEM_SPACING, LabelValueRows, section_space};
use eframe::egui;

pub(in crate::ui) fn show(ui: &mut egui::Ui, trace: &DiagnosticTrace) {
    ({
        eframe::egui::ScrollArea::vertical()
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.style_mut().wrap_mode = Some(eframe::egui::TextWrapMode::Wrap);
                ui.spacing_mut().item_spacing.y = ITEM_SPACING;
                ui.heading("TLS and Certificates");
                let Some(tls) = &trace.tls else {
                    ui.weak(if trace.url.scheme == "http" {
                        "Not applicable to plain HTTP."
                    } else {
                        "No TLS information captured yet."
                    });
                    return;
                };
                LabelValueRows::show(ui, "tls_grid", |ui, rows| {
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                            (ui, "SNI", &tls.server_name);
                        rows.row(ui, label, value);
                    });
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                            ui,
                            "TLS version",
                            tls.version.as_deref().unwrap_or("Unknown"),
                        );
                        rows.row(ui, label, value);
                    });
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                            ui,
                            "Cipher suite",
                            tls.cipher_suite.as_deref().unwrap_or("Unknown"),
                        );
                        rows.row(ui, label, value);
                    });
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                            (ui, "ALPN", tls.alpn.as_deref().unwrap_or("None"));
                        rows.row(ui, label, value);
                    });
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                            ui,
                            "Validation",
                            tls.validation.as_deref().unwrap_or("Unknown"),
                        );
                        rows.row(ui, label, value);
                    });
                    ({
                        let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                            ui,
                            "Client authentication",
                            &tls.client_auth.status.to_string(),
                        );
                        rows.row(ui, label, value);
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
                        rows.row(ui, label, value);
                    });
                    if let Some(profile) = &tls.client_auth.profile_name {
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                (ui, "Client-certificate profile", profile);
                            rows.row(ui, label, value);
                        });
                    }
                });
                if let Some(error) = &tls.validation_error {
                    ui.colored_label(egui::Color32::LIGHT_RED, error);
                }
                section_space(ui);
                for (index, certificate) in tls.certificates.iter().enumerate() {
                    disclosure(
                        ui,
                        ("certificate", index),
                        egui::RichText::new(format!(
                            "Certificate {}: {}",
                            index + 1,
                            certificate.subject
                        ))
                        .strong(),
                        |ui| {
                            ui.label(format!("Valid until {}", certificate.not_after));
                        },
                        |ui| {
                            LabelValueRows::show(ui, format!("certificate_{index}"), |ui, rows| {
                                    ({
                                        let (ui, label, value): (
                                            &mut eframe::egui::Ui,
                                            &str,
                                            &str,
                                        ) = (ui, "Subject", &certificate.subject);
                                        rows.row(ui, label, value);
                                    });
                                    ({
                                        let (ui, label, value): (
                                            &mut eframe::egui::Ui,
                                            &str,
                                            &str,
                                        ) = (ui, "Issuer", &certificate.issuer);
                                        rows.row(ui, label, value);
                                    });
                                    ({
                                        let (ui, label, value): (
                                            &mut eframe::egui::Ui,
                                            &str,
                                            &str,
                                        ) = (ui, "Serial", &certificate.serial);
                                        rows.row(ui, label, value);
                                    });
                                    ({
                                        let (ui, label, value): (
                                            &mut eframe::egui::Ui,
                                            &str,
                                            &str,
                                        ) = (ui, "Valid from", &certificate.not_before);
                                        rows.row(ui, label, value);
                                    });
                                    ({
                                        let (ui, label, value): (
                                            &mut eframe::egui::Ui,
                                            &str,
                                            &str,
                                        ) = (ui, "Valid until", &certificate.not_after);
                                        rows.row(ui, label, value);
                                    });
                                    ({
                                        let (ui, label, value): (
                                            &mut eframe::egui::Ui,
                                            &str,
                                            &str,
                                        ) = (ui, "Public key", &certificate.public_key_algorithm);
                                        rows.row(ui, label, value);
                                    });
                                    ({
                                        let (ui, label, value): (
                                            &mut eframe::egui::Ui,
                                            &str,
                                            &str,
                                        ) = (ui, "Signature", &certificate.signature_algorithm);
                                        rows.row(ui, label, value);
                                    });
                                    ({
                                        let (ui, label, value): (
                                            &mut eframe::egui::Ui,
                                            &str,
                                            &str,
                                        ) = (ui, "SHA-256", &certificate.sha256);
                                        rows.row(ui, label, value);
                                    });
                                });
                            ui.strong("Subject alternative names");
                            for name in &certificate.subject_alt_names {
                                ui.monospace(name);
                            }
                        },
                    );
                }
            });
    });
}
