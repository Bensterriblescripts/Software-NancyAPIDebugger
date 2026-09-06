use crate::diagnostics::{DiagnosticTrace, HeaderTrace, escaped_bytes};
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
                ui.heading("HTTP Exchange");
                LabelValueRows::show(ui, "http_summary", |ui, rows| {
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                (ui, "Requested", &trace.http.requested_protocol);
                            rows.row(ui, label, value);
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                                ui,
                                "Negotiated",
                                trace.http.version.as_deref().unwrap_or("Pending"),
                            );
                            rows.row(ui, label, value);
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                (ui, "Status", &trace.status_text());
                            rows.row(ui, label, value);
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                (ui, "Final URL", &trace.http.final_url);
                            rows.row(ui, label, value);
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                                ui,
                                "Request mode",
                                if trace.request.follow_redirects {
                                    "Follow redirects (each hop is traced)"
                                } else {
                                    "Direct (redirects are not followed)"
                                },
                            );
                            rows.row(ui, label, value);
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                                ui,
                                "Redirect target",
                                trace.redirect_target.as_deref().unwrap_or("None"),
                            );
                            rows.row(ui, label, value);
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                                ui,
                                "Redirect followed",
                                if trace.redirect_followed { "Yes" } else { "No" },
                            );
                            rows.row(ui, label, value);
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                                ui,
                                "Redirect stop reason",
                                trace.redirect_stop_reason.as_deref().unwrap_or("None"),
                            );
                            rows.row(ui, label, value);
                        });
                    });
                if let Some(reason) = &trace.redirect_stop_reason {
                    ui.colored_label(egui::Color32::YELLOW, reason);
                }
                section_space(ui);
                disclosure(
                    ui,
                    "request-headers",
                    egui::RichText::new(format!(
                        "{} ({})",
                        if trace.http.headers_sent {
                            "Request Header Fields"
                        } else {
                            "Prepared Request Header Fields"
                        },
                        trace.http.request_headers.len()
                    ))
                    .heading(),
                    |_| {},
                    |ui| {
                        ({
                            let (ui, id, headers): (&mut egui::Ui, &str, &[HeaderTrace]) =
                                (ui, "sent_headers", &trace.http.request_headers);
                            'inlined_show_headers: {
                                if headers.is_empty() {
                                    ui.weak("None captured.");
                                    break 'inlined_show_headers;
                                }
                                LabelValueRows::show(ui, id, |ui, rows| {
                                    for header in headers {
                                        let name = {
                                            let (name,): (&str,) = (&header.name,);
                                            let inlined_result: &str = {
                                                if name.eq_ignore_ascii_case(
                                                    "content-security-policy-report-only",
                                                ) {
                                                    "CSP-Report-Only"
                                                } else if name
                                                    .eq_ignore_ascii_case("content-security-policy")
                                                {
                                                    "CSP"
                                                } else {
                                                    name
                                                }
                                            };
                                            inlined_result
                                        };
                                        let mut name = egui::RichText::new(name).monospace();
                                        if header.pseudo {
                                            name = name.color(egui::Color32::LIGHT_BLUE);
                                        }
                                        rows.row(ui, name, header.display_value());
                                    }
                                });
                            }
                        });
                        if let Some(serialized) = &trace.http.actual_http1_request_headers {
                            egui::CollapsingHeader::new("Actual transmitted HTTP/1.1 header bytes")
                                .show(ui, |ui| {
                                    let text = escaped_bytes(serialized);
                                    ({
                                        let (ui, text): (&mut eframe::egui::Ui, &str) =
                                            (ui, text.as_ref());
                                        ui.add(
                                            eframe::egui::Label::new(
                                                eframe::egui::RichText::new(text).monospace(),
                                            )
                                            .selectable(true),
                                        );
                                    });
                                });
                        }
                    },
                );
                section_space(ui);
                disclosure(
                    ui,
                    "response-headers",
                    egui::RichText::new(format!(
                        "Response Headers ({})",
                        trace.http.response_headers.len()
                    ))
                    .heading(),
                    |_| {},
                    |ui| {
                        ({
                            let (ui, id, headers): (&mut egui::Ui, &str, &[HeaderTrace]) =
                                (ui, "response_headers", &trace.http.response_headers);
                            'inlined_show_headers: {
                                if headers.is_empty() {
                                    ui.weak("None captured.");
                                    break 'inlined_show_headers;
                                }
                                LabelValueRows::show(ui, id, |ui, rows| {
                                    for header in headers {
                                        let name = {
                                            let (name,): (&str,) = (&header.name,);
                                            let inlined_result: &str = {
                                                if name.eq_ignore_ascii_case(
                                                    "content-security-policy-report-only",
                                                ) {
                                                    "CSP-Report-Only"
                                                } else if name
                                                    .eq_ignore_ascii_case("content-security-policy")
                                                {
                                                    "CSP"
                                                } else {
                                                    name
                                                }
                                            };
                                            inlined_result
                                        };
                                        let mut name = egui::RichText::new(name).monospace();
                                        if header.pseudo {
                                            name = name.color(egui::Color32::LIGHT_BLUE);
                                        }
                                        rows.row(ui, name, header.display_value());
                                    }
                                });
                            }
                        });
                    },
                );
                if !trace.http.response_trailers.is_empty() {
                    section_space(ui);
                    disclosure(
                        ui,
                        "response-trailers",
                        egui::RichText::new(format!(
                            "Response Trailers ({})",
                            trace.http.response_trailers.len()
                        ))
                        .heading(),
                        |_| {},
                        |ui| {
                            ({
                                let (ui, id, headers): (&mut egui::Ui, &str, &[HeaderTrace]) =
                                    (ui, "response_trailers", &trace.http.response_trailers);
                                'inlined_show_headers: {
                                    if headers.is_empty() {
                                        ui.weak("None captured.");
                                        break 'inlined_show_headers;
                                    }
                                    LabelValueRows::show(ui, id, |ui, rows| {
                                        for header in headers {
                                            let name = {
                                                let (name,): (&str,) = (&header.name,);
                                                let inlined_result: &str = {
                                                    if name.eq_ignore_ascii_case(
                                                        "content-security-policy-report-only",
                                                    ) {
                                                        "CSP-Report-Only"
                                                    } else if name.eq_ignore_ascii_case(
                                                        "content-security-policy",
                                                    ) {
                                                        "CSP"
                                                    } else {
                                                        name
                                                    }
                                                };
                                                inlined_result
                                            };
                                            let mut name = egui::RichText::new(name).monospace();
                                            if header.pseudo {
                                                name = name.color(egui::Color32::LIGHT_BLUE);
                                            }
                                            rows.row(ui, name, header.display_value());
                                        }
                                    });
                                }
                            });
                        },
                    );
                }
            });
    });
}
