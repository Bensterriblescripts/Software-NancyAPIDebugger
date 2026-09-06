use crate::diagnostics::{DiagnosticTrace, HeaderTrace, escaped_bytes};
use eframe::egui;

pub(in crate::ui) fn show(ui: &mut egui::Ui, trace: &DiagnosticTrace) {
    ({
        eframe::egui::ScrollArea::both()
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.style_mut().wrap_mode = Some(eframe::egui::TextWrapMode::Extend);
                ui.heading("HTTP Exchange");
                egui::Grid::new("http_summary")
                    .striped(true)
                    .show(ui, |ui| {
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                (ui, "Requested", &trace.http.requested_protocol);
                            ui.strong(label);
                            ui.label(value);
                            ui.end_row();
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                                ui,
                                "Negotiated",
                                trace.http.version.as_deref().unwrap_or("Pending"),
                            );
                            ui.strong(label);
                            ui.label(value);
                            ui.end_row();
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                (ui, "Status", &trace.status_text());
                            ui.strong(label);
                            ui.label(value);
                            ui.end_row();
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) =
                                (ui, "Final URL", &trace.http.final_url);
                            ui.strong(label);
                            ui.label(value);
                            ui.end_row();
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
                            ui.strong(label);
                            ui.label(value);
                            ui.end_row();
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                                ui,
                                "Redirect target",
                                trace.redirect_target.as_deref().unwrap_or("None"),
                            );
                            ui.strong(label);
                            ui.label(value);
                            ui.end_row();
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                                ui,
                                "Redirect followed",
                                if trace.redirect_followed { "Yes" } else { "No" },
                            );
                            ui.strong(label);
                            ui.label(value);
                            ui.end_row();
                        });
                        ({
                            let (ui, label, value): (&mut eframe::egui::Ui, &str, &str) = (
                                ui,
                                "Redirect stop reason",
                                trace.redirect_stop_reason.as_deref().unwrap_or("None"),
                            );
                            ui.strong(label);
                            ui.label(value);
                            ui.end_row();
                        });
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
                ({
                    let (ui, id, headers): (&mut egui::Ui, &str, &[HeaderTrace]) =
                        (ui, "sent_headers", &trace.http.request_headers);
                    'inlined_show_headers: {
                        if headers.is_empty() {
                            ui.weak("None captured.");
                            break 'inlined_show_headers;
                        }
                        egui::Grid::new(id).striped(true).show(ui, |ui| {
                            ui.strong("Name");
                            ui.strong("Value");
                            ui.end_row();
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
                                if header.pseudo {
                                    ui.monospace(
                                        egui::RichText::new(name).color(egui::Color32::LIGHT_BLUE),
                                    );
                                } else {
                                    ui.monospace(name);
                                }
                                ui.monospace(header.display_value());
                                ui.end_row();
                            }
                        });
                    }
                });
                if let Some(serialized) = &trace.http.actual_http1_request_headers {
                    egui::CollapsingHeader::new("Actual transmitted HTTP/1.1 header bytes").show(
                        ui,
                        |ui| {
                            let text = escaped_bytes(serialized);
                            ({
                                let (ui, text): (&mut eframe::egui::Ui, &str) = (ui, text.as_ref());
                                ui.add(
                                    eframe::egui::Label::new(
                                        eframe::egui::RichText::new(text).monospace(),
                                    )
                                    .selectable(true),
                                );
                            });
                        },
                    );
                }
                ui.add_space(12.0);
                ui.heading("Response Headers");
                ({
                    let (ui, id, headers): (&mut egui::Ui, &str, &[HeaderTrace]) =
                        (ui, "response_headers", &trace.http.response_headers);
                    'inlined_show_headers: {
                        if headers.is_empty() {
                            ui.weak("None captured.");
                            break 'inlined_show_headers;
                        }
                        egui::Grid::new(id).striped(true).show(ui, |ui| {
                            ui.strong("Name");
                            ui.strong("Value");
                            ui.end_row();
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
                                if header.pseudo {
                                    ui.monospace(
                                        egui::RichText::new(name).color(egui::Color32::LIGHT_BLUE),
                                    );
                                } else {
                                    ui.monospace(name);
                                }
                                ui.monospace(header.display_value());
                                ui.end_row();
                            }
                        });
                    }
                });
                if !trace.http.response_trailers.is_empty() {
                    ui.add_space(8.0);
                    ui.heading("Response Trailers");
                    ({
                        let (ui, id, headers): (&mut egui::Ui, &str, &[HeaderTrace]) =
                            (ui, "response_trailers", &trace.http.response_trailers);
                        'inlined_show_headers: {
                            if headers.is_empty() {
                                ui.weak("None captured.");
                                break 'inlined_show_headers;
                            }
                            egui::Grid::new(id).striped(true).show(ui, |ui| {
                                ui.strong("Name");
                                ui.strong("Value");
                                ui.end_row();
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
                                    if header.pseudo {
                                        ui.monospace(
                                            egui::RichText::new(name)
                                                .color(egui::Color32::LIGHT_BLUE),
                                        );
                                    } else {
                                        ui.monospace(name);
                                    }
                                    ui.monospace(header.display_value());
                                    ui.end_row();
                                }
                            });
                        }
                    });
                }
            });
    });
}
