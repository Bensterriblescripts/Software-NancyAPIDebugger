use crate::auth::{ProfileSummary, SharedAuthStore};
use crate::diagnostics::{DiagnosticRequest, ProtocolPreference, StageTimeouts, UserAgentPreset};
use crate::exposure::fingerprints::{self, InitializationStatus};
use crate::scan_limits as limits;
use crate::{
    Confidence, CrawlContactType, EndpointScan, ExposureScanPhaseState, ExposureScanReport,
    ExposureScanRequest, PortSelection, PortState, ServiceKind, TransportProtocol, WebProbeLevel,
    curated_tcp_port_metadata,
};
use eframe::egui;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::app::{App, ExposureLiveState};
use super::details::{
    BodyView, DetailTab, show_body, show_http, show_network,
    show_summary as show_diagnostic_summary, show_tls,
};

labeled_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum PortChoice[3] {
        Curated => "Curated",
        Custom => "Custom",
        All => "All TCP ports",
    }
}

impl PortChoice {
    fn show(&mut self, ui: &mut egui::Ui, transport: TransportProtocol) {
        egui::ComboBox::from_id_salt(("exposure_ports", transport))
            .selected_text({
                let (inlined_self, transport): (PortChoice, TransportProtocol) = (*self, transport);
                let inlined_result: &'static str = {
                    match (inlined_self, transport) {
                        (PortChoice::Curated, TransportProtocol::Udp) => "Curated UDP ports",
                        (PortChoice::Custom, TransportProtocol::Udp) => "Custom UDP ports",
                        _ => inlined_self.label(),
                    }
                };
                inlined_result
            })
            .show_ui(ui, |ui| {
                for choice in Self::ALL {
                    if transport == TransportProtocol::Tcp || choice != Self::All {
                        ui.selectable_value(self, choice, {
                            let (inlined_self, transport): (PortChoice, TransportProtocol) =
                                (choice, transport);
                            let inlined_result: &'static str = {
                                match (inlined_self, transport) {
                                    (PortChoice::Curated, TransportProtocol::Udp) => {
                                        "Curated UDP ports"
                                    }
                                    (PortChoice::Custom, TransportProtocol::Udp) => {
                                        "Custom UDP ports"
                                    }
                                    _ => inlined_self.label(),
                                }
                            };
                            inlined_result
                        });
                    }
                }
            });
    }
}

#[derive(Debug, Clone)]
pub(super) struct TimeoutInputs {
    authentication: f64,
    dns: f64,
    transport: f64,
    tls: f64,
    headers: f64,
    first_byte: f64,
    body: f64,
}

#[derive(Debug, Clone)]
pub(super) struct DiagnosticForm {
    pub(super) method: String,
    pub(super) url: String,
    pub(super) headers: String,
    pub(super) body: String,
    pub(super) protocol: ProtocolPreference,
    pub(super) follow_redirects: bool,
    pub(super) user_agent: UserAgentPreset,
    pub(super) selected_auth_profile: Option<u64>,
    pub(super) selected_client_certificate_profile: Option<u64>,
    timeouts: TimeoutInputs,
}

#[derive(Debug, Clone)]
pub(super) struct ScanForm {
    pub(super) diagnostic: DiagnosticForm,
    port_choice: PortChoice,
    custom_ports: String,
    udp_port_choice: PortChoice,
    custom_udp_ports: String,
    concurrency: usize,
    rate: u32,
    connection_timeout: f64,
    probe_timeout: f64,
    security_operations: bool,
    web_probe_level: WebProbeLevel,
    active_requests_per_origin: usize,
    active_requests_total: usize,
    service_access_checks: bool,
    udp_scanning: bool,
    dns_and_discovery: bool,
    ct_hostname_limit: usize,
    dkim_selectors: String,
    crawl_max_urls: usize,
    crawl_concurrency: usize,
    crawl_rate: u32,
}

impl Default for ScanForm {
    fn default() -> Self {
        let scan = ExposureScanRequest::default();
        let diagnostic = scan.diagnostic_request;
        Self {
            diagnostic: DiagnosticForm {
                method: diagnostic.method,
                url: diagnostic.url,
                headers: diagnostic.headers,
                body: String::from_utf8_lossy(&diagnostic.body).into_owned(),
                protocol: diagnostic.protocol,
                follow_redirects: diagnostic.follow_redirects,
                user_agent: diagnostic.user_agent,
                selected_auth_profile: None,
                selected_client_certificate_profile: None,
                timeouts: ({
                    let (timeouts,): (&StageTimeouts,) = (&diagnostic.timeouts,);
                    {
                        TimeoutInputs {
                            authentication: timeouts.authentication.as_secs_f64(),
                            dns: timeouts.dns.as_secs_f64(),
                            transport: timeouts.transport.as_secs_f64(),
                            tls: timeouts.tls.as_secs_f64(),
                            headers: timeouts.headers.as_secs_f64(),
                            first_byte: timeouts.first_byte.as_secs_f64(),
                            body: timeouts.body.as_secs_f64(),
                        }
                    }
                }),
            },
            port_choice: PortChoice::Curated,
            custom_ports: "80,443".to_owned(),
            udp_port_choice: PortChoice::Curated,
            custom_udp_ports: "53,123,443,500,1884,1900,3478,3702,4500,5060,5353,5683,9000"
                .to_owned(),
            concurrency: scan.concurrency,
            rate: scan.connection_starts_per_second,
            connection_timeout: scan.connection_timeout.as_secs_f64(),
            probe_timeout: scan.probe_timeout.as_secs_f64(),
            security_operations: scan.security_operations,
            web_probe_level: WebProbeLevel::Passive,
            active_requests_per_origin: scan.active_requests_per_origin,
            active_requests_total: scan.active_requests_total,
            service_access_checks: true,
            udp_scanning: true,
            dns_and_discovery: true,
            ct_hostname_limit: scan.ct_hostname_limit,
            dkim_selectors: String::new(),
            crawl_max_urls: scan.crawl_max_urls,
            crawl_concurrency: scan.crawl_concurrency,
            crawl_rate: scan.crawl_requests_per_second,
        }
    }
}

impl ScanForm {
    pub(super) fn to_request(
        &self,
        auth_store: &SharedAuthStore,
    ) -> Result<ExposureScanRequest, String> {
        let auth = match self.diagnostic.selected_auth_profile {
            Some(id) => Some(
                auth_store
                    .lock()
                    .map_err(|_| "Authentication profile store is unavailable".to_owned())?
                    .metadata(id)
                    .ok_or_else(|| "Selected authentication profile no longer exists".to_owned())?,
            ),
            None => None,
        };
        let client_certificate = match self.diagnostic.selected_client_certificate_profile {
            Some(id) => Some(
                auth_store
                    .lock()
                    .map_err(|_| "Authentication profile store is unavailable".to_owned())?
                    .client_certificate_metadata(id)
                    .ok_or_else(|| {
                        "Selected client-certificate profile no longer exists".to_owned()
                    })?,
            ),
            None => None,
        };
        let defaults = ExposureScanRequest::default();
        let mut request = ExposureScanRequest {
            diagnostic_request: DiagnosticRequest {
                method: self.diagnostic.method.clone(),
                url: self.diagnostic.url.trim().to_owned(),
                headers: self.diagnostic.headers.clone(),
                body: Arc::from(self.diagnostic.body.as_bytes()),
                protocol: self.diagnostic.protocol,
                timeouts: StageTimeouts {
                    authentication: limits::timeout(
                        self.diagnostic.timeouts.authentication,
                        limits::STAGE_TIMEOUT,
                        "Authentication stage timeout (seconds)",
                    )?,
                    dns: limits::timeout(
                        self.diagnostic.timeouts.dns,
                        limits::STAGE_TIMEOUT,
                        "DNS stage timeout (seconds)",
                    )?,
                    transport: limits::timeout(
                        self.diagnostic.timeouts.transport,
                        limits::STAGE_TIMEOUT,
                        "TCP / QUIC stage timeout (seconds)",
                    )?,
                    tls: limits::timeout(
                        self.diagnostic.timeouts.tls,
                        limits::STAGE_TIMEOUT,
                        "TLS stage timeout (seconds)",
                    )?,
                    headers: limits::timeout(
                        self.diagnostic.timeouts.headers,
                        limits::STAGE_TIMEOUT,
                        "HTTP headers stage timeout (seconds)",
                    )?,
                    first_byte: limits::timeout(
                        self.diagnostic.timeouts.first_byte,
                        limits::STAGE_TIMEOUT,
                        "First byte stage timeout (seconds)",
                    )?,
                    body: limits::timeout(
                        self.diagnostic.timeouts.body,
                        limits::STAGE_TIMEOUT,
                        "Body stage timeout (seconds)",
                    )?,
                },
                auth,
                client_certificate,
                follow_redirects: self.diagnostic.follow_redirects,
                user_agent: self.diagnostic.user_agent,
            },
            ports: match self.port_choice {
                PortChoice::Curated => PortSelection::Curated,
                PortChoice::All => PortSelection::All,
                PortChoice::Custom => PortSelection::parse(&self.custom_ports)
                    .map_err(|error| format!("TCP ports: {error}"))?,
            },
            connection_timeout: limits::timeout(
                self.connection_timeout,
                limits::CONNECTION_TIMEOUT,
                "Connection timeout (seconds)",
            )?,
            probe_timeout: limits::timeout(
                self.probe_timeout,
                limits::PROBE_TIMEOUT,
                "Probe timeout (seconds)",
            )?,
            concurrency: self.concurrency,
            connection_starts_per_second: self.rate,
            security_operations: self.security_operations,
            web_probe_level: self.web_probe_level,
            service_access_checks: self.service_access_checks,
            udp_scanning: self.udp_scanning,
            asset_discovery: self.dns_and_discovery,
            dns_assessment: self.dns_and_discovery,
            ..defaults
        };
        if self.udp_scanning {
            request.udp_ports = match self.udp_port_choice {
                PortChoice::Curated => PortSelection::Curated,
                PortChoice::All => PortSelection::All,
                PortChoice::Custom => PortSelection::parse(&self.custom_udp_ports)
                    .map_err(|error| format!("UDP ports: {error}"))?,
            };
        }
        if self.web_probe_level != WebProbeLevel::Passive {
            request.active_requests_per_origin = self.active_requests_per_origin;
            request.active_requests_total = self.active_requests_total;
        }
        if self.dns_and_discovery {
            request.ct_hostname_limit = self.ct_hostname_limit;
            for selector in self
                .dkim_selectors
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                let selector = selector.to_ascii_lowercase();
                if !request.dkim_selectors.contains(&selector) {
                    request.dkim_selectors.push(selector);
                }
            }
        }
        if self.security_operations {
            request.crawl_max_urls = self.crawl_max_urls;
            request.crawl_concurrency = self.crawl_concurrency;
            request.crawl_requests_per_second = self.crawl_rate;
        }
        request.validate()?;
        Ok(request)
    }
}

pub(super) struct DiagnosticViewState {
    pub(super) endpoint_index: Option<usize>,
    pub(super) hop_index: usize,
    pub(super) tab: DetailTab,
    pub(super) body_view: BodyView,
}

impl Default for DiagnosticViewState {
    fn default() -> Self {
        Self {
            endpoint_index: None,
            hop_index: 0,
            tab: DetailTab::Summary,
            body_view: BodyView::Decoded,
        }
    }
}

labeled_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum ExposureDetailTab[10] {
        Summary => "Summary",
        Diagnostics => "Diagnostics",
        Tcp => "TCP",
        Udp => "UDP",
        Services => "Services",
        DnsAndDiscovery => "DNS",
        Crawl => "Details",
        ExternalSources => "External Sources",
        JavaScript => "Technology Versions",
        SecuritySummary => "Security Summary",
    }
}

pub(super) fn show_dialog(ctx: &egui::Context, app: &mut App) -> bool {
    let mut start = false;
    if app.show_exposure_scan {
        egui::Window::new("Public Exposure Scan")
            .collapsible(false)
            .resizable(true)
            .default_width(560.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Target URL");
                let target = ui.add(
                    egui::TextEdit::singleline(&mut app.scan_form.diagnostic.url)
                        .desired_width(f32::INFINITY)
                        .hint_text("https://api.example.com/path?query=value"),
                );
                if app.scan_set_focus {
                    target.request_focus();
                    app.scan_set_focus = false;
                }
                ui.horizontal(|ui| {
                    ui.label("Ports");
                    app.scan_form.port_choice.show(ui, TransportProtocol::Tcp);
                });
                if app.scan_form.port_choice == PortChoice::Custom {
                    ui.add(
                        egui::TextEdit::singleline(&mut app.scan_form.custom_ports)
                            .desired_width(f32::INFINITY)
                            .hint_text("80,443,8000-8100"),
                    );
                }
                ui.horizontal(|ui| {
                    ui.checkbox(&mut app.scan_form.udp_scanning, "UDP scanning");
                    if app.scan_form.udp_scanning {
                        app.scan_form.udp_port_choice.show(ui, TransportProtocol::Udp);
                    }
                });
                if app.scan_form.udp_scanning
                    && app.scan_form.udp_port_choice == PortChoice::Custom
                {
                    ui.add(
                        egui::TextEdit::singleline(&mut app.scan_form.custom_udp_ports)
                            .desired_width(f32::INFINITY)
                            .hint_text("53,123,443,3478,5060"),
                    );
                }
                egui::CollapsingHeader::new("Advanced settings")
                    .default_open(true)
                    .show(ui, |ui| {
                        ({
let (ui, app,): (& mut egui :: Ui, & mut App,) = (ui, app,);

    ui.horizontal_wrapped(|ui| {
        ui.label("Method");
        egui::ComboBox::from_id_salt("scan_method")
            .selected_text(&app.scan_form.diagnostic.method)
            .show_ui(ui, |ui| {
                for method in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] {
                    ui.selectable_value(
                        &mut app.scan_form.diagnostic.method,
                        method.to_owned(),
                        method,
                    );
                }
            });
        ui.label("Protocol");
        egui::ComboBox::from_id_salt("scan_protocol")
            .selected_text(app.scan_form.diagnostic.protocol.to_string())
            .show_ui(ui, |ui| {
                for protocol in ProtocolPreference::ALL {
                    ui.selectable_value(
                        &mut app.scan_form.diagnostic.protocol,
                        protocol,
                        protocol.to_string(),
                    );
                }
            });
    });
    ui.label("Headers");
    ui.add(
        egui::TextEdit::multiline(&mut app.scan_form.diagnostic.headers)
            .desired_width(f32::INFINITY)
            .desired_rows(4)
            .hint_text("Content-Type: application/json"),
    );
    ui.label("Body");
    ui.add(
        egui::TextEdit::multiline(&mut app.scan_form.diagnostic.body)
            .desired_width(f32::INFINITY)
            .desired_rows(6),
    );
    ui.horizontal_wrapped(|ui| {
        ui.checkbox(
            &mut app.scan_form.diagnostic.follow_redirects,
            "Follow public redirects",
        );
        ui.label("User-Agent");
        egui::ComboBox::from_id_salt("scan_user_agent")
            .selected_text(app.scan_form.diagnostic.user_agent.label())
            .show_ui(ui, |ui| {
                for preset in UserAgentPreset::ALL {
                    ui.selectable_value(
                        &mut app.scan_form.diagnostic.user_agent,
                        preset,
                        preset.label(),
                    );
                }
            });
    });
    let profiles: Vec<ProfileSummary> = app
        .auth_store
        .lock()
        .map(|store| store.summaries())
        .unwrap_or_default();
    let selected_text = app
        .scan_form
        .diagnostic
        .selected_auth_profile
        .and_then(|id| profiles.iter().find(|profile| profile.id == id))
        .map(|profile| profile.name.as_str())
        .unwrap_or("None");
    ui.horizontal(|ui| {
        ui.label("Authentication profile");
        egui::ComboBox::from_id_salt("scan_auth_profile")
            .selected_text(selected_text)
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut app.scan_form.diagnostic.selected_auth_profile,
                    None,
                    "None",
                );
                for profile in profiles.iter().filter(|profile| {
                    profile.profile_type != crate::auth::ProfileType::ClientCertificate
                }) {
                    ui.selectable_value(
                        &mut app.scan_form.diagnostic.selected_auth_profile,
                        Some(profile.id),
                        &profile.name,
                    );
                }
            });
        if ui.button("Manage profiles").clicked() {
            app.show_auth_profiles = true;
        }
    });
    if let Some(profile) = app
        .scan_form
        .diagnostic
        .selected_auth_profile
        .and_then(|id| profiles.iter().find(|profile| profile.id == id))
    {
        ui.weak(format!(
            "{} — {}",
            profile.profile_type.label(),
            profile.status
        ));
    }
    let selected_certificate_text = app
        .scan_form
        .diagnostic
        .selected_client_certificate_profile
        .and_then(|id| profiles.iter().find(|profile| profile.id == id))
        .map(|profile| profile.name.as_str())
        .unwrap_or("None");
    ui.horizontal(|ui| {
        ui.label("Client certificate");
        egui::ComboBox::from_id_salt("scan_client_certificate_profile")
            .selected_text(selected_certificate_text)
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut app.scan_form.diagnostic.selected_client_certificate_profile,
                    None,
                    "None",
                );
                for profile in profiles.iter().filter(|profile| {
                    profile.profile_type == crate::auth::ProfileType::ClientCertificate
                }) {
                    ui.selectable_value(
                        &mut app.scan_form.diagnostic.selected_client_certificate_profile,
                        Some(profile.id),
                        &profile.name,
                    );
                }
            });
    });
    egui::CollapsingHeader::new("Stage timeouts")
        .default_open(true)
        .show(ui, |ui| {
            {
let (ui, values,): (& mut egui :: Ui, & mut TimeoutInputs,) = (ui, &mut app.scan_form.diagnostic.timeouts,);

    egui::Grid::new("scan_timeouts").show(ui, |ui| {
        ({
let (ui, label, value,): (& mut egui :: Ui, & str, & mut f64,) = (ui, "Authentication", &mut values.authentication,);

    ui.label(label);
    ui.add(
        egui::DragValue::new(value)
            .range(limits::STAGE_TIMEOUT)
            .clamp_existing_to_range(false)
            .speed(0.5)
            .suffix(" s"),
    );
    ui.end_row();

});
        ({
let (ui, label, value,): (& mut egui :: Ui, & str, & mut f64,) = (ui, "DNS", &mut values.dns,);

    ui.label(label);
    ui.add(
        egui::DragValue::new(value)
            .range(limits::STAGE_TIMEOUT)
            .clamp_existing_to_range(false)
            .speed(0.5)
            .suffix(" s"),
    );
    ui.end_row();

});
        ({
let (ui, label, value,): (& mut egui :: Ui, & str, & mut f64,) = (ui, "TCP / QUIC", &mut values.transport,);

    ui.label(label);
    ui.add(
        egui::DragValue::new(value)
            .range(limits::STAGE_TIMEOUT)
            .clamp_existing_to_range(false)
            .speed(0.5)
            .suffix(" s"),
    );
    ui.end_row();

});
        ({
let (ui, label, value,): (& mut egui :: Ui, & str, & mut f64,) = (ui, "TLS", &mut values.tls,);

    ui.label(label);
    ui.add(
        egui::DragValue::new(value)
            .range(limits::STAGE_TIMEOUT)
            .clamp_existing_to_range(false)
            .speed(0.5)
            .suffix(" s"),
    );
    ui.end_row();

});
        ({
let (ui, label, value,): (& mut egui :: Ui, & str, & mut f64,) = (ui, "HTTP headers", &mut values.headers,);

    ui.label(label);
    ui.add(
        egui::DragValue::new(value)
            .range(limits::STAGE_TIMEOUT)
            .clamp_existing_to_range(false)
            .speed(0.5)
            .suffix(" s"),
    );
    ui.end_row();

});
        ({
let (ui, label, value,): (& mut egui :: Ui, & str, & mut f64,) = (ui, "First byte", &mut values.first_byte,);

    ui.label(label);
    ui.add(
        egui::DragValue::new(value)
            .range(limits::STAGE_TIMEOUT)
            .clamp_existing_to_range(false)
            .speed(0.5)
            .suffix(" s"),
    );
    ui.end_row();

});
        ({
let (ui, label, value,): (& mut egui :: Ui, & str, & mut f64,) = (ui, "Body", &mut values.body,);

    ui.label(label);
    ui.add(
        egui::DragValue::new(value)
            .range(limits::STAGE_TIMEOUT)
            .clamp_existing_to_range(false)
            .speed(0.5)
            .suffix(" s"),
    );
    ui.end_row();

});
    });

}
        });

});
                        ui.separator();
                        egui::Grid::new("exposure_advanced").show(ui, |ui| {
                            ui.label("Concurrent endpoints");
                            ui.add(
                                egui::DragValue::new(&mut app.scan_form.concurrency)
                                    .range(limits::CONCURRENCY)
                                    .clamp_existing_to_range(false),
                            );
                            ui.end_row();
                            ui.label("Connection starts / second");
                            ui.add(
                                egui::DragValue::new(&mut app.scan_form.rate)
                                    .range(limits::CONNECTION_RATE)
                                    .clamp_existing_to_range(false),
                            );
                            ui.end_row();
                            ui.label("Connection timeout");
                            ui.add(
                                egui::DragValue::new(&mut app.scan_form.connection_timeout)
                                    .range(limits::CONNECTION_TIMEOUT)
                                    .clamp_existing_to_range(false)
                                    .suffix(" s"),
                            );
                            ui.end_row();
                            ui.label("Probe timeout");
                            ui.add(
                                egui::DragValue::new(&mut app.scan_form.probe_timeout)
                                    .range(limits::PROBE_TIMEOUT)
                                    .clamp_existing_to_range(false)
                                    .suffix(" s"),
                            );
                            ui.end_row();
                            ui.label("Web probe level");
                            egui::ComboBox::from_id_salt("web_probe_level")
                                .selected_text(app.scan_form.web_probe_level.to_string())
                                .show_ui(ui, |ui| {
                                    for level in WebProbeLevel::ALL {
                                        ui.selectable_value(
                                            &mut app.scan_form.web_probe_level,
                                            level,
                                            level.to_string(),
                                        );
                                    }
                                });
                            ui.end_row();
                            ui.label("Security operations");
                            ui.checkbox(
                                &mut app.scan_form.security_operations,
                                "Broad exposure, source-map secret, advanced browser-policy, CORS consistency, DNS takeover, crawl, and technology checks",
                            );
                            ui.end_row();
                            if app.scan_form.web_probe_level != WebProbeLevel::Passive {
                                ui.label("Active requests / origin");
                                ui.add(
                                    egui::DragValue::new(
                                        &mut app.scan_form.active_requests_per_origin,
                                    )
                                    .range(limits::ACTIVE_PER_ORIGIN)
                                    .clamp_existing_to_range(false),
                                );
                                ui.end_row();
                                ui.label("Total active requests");
                                ui.add(
                                    egui::DragValue::new(&mut app.scan_form.active_requests_total)
                                        .range(limits::ACTIVE_TOTAL)
                                        .clamp_existing_to_range(false),
                                );
                                ui.end_row();
                            }
                            ui.label("Service access checks");
                            ui.checkbox(
                                &mut app.scan_form.service_access_checks,
                                "Handshake-only anonymous access checks",
                            );
                            ui.end_row();
                            ui.label("DNS & Discovery");
                            ui.checkbox(
                                &mut app.scan_form.dns_and_discovery,
                                "Assess DNS/email security; query crt.sh for inventory only",
                            );
                            ui.end_row();
                            if app.scan_form.dns_and_discovery {
                                ui.label("CT hostname limit");
                                ui.add(
                                    egui::DragValue::new(&mut app.scan_form.ct_hostname_limit)
                                        .range(limits::CT_HOSTNAMES)
                                        .clamp_existing_to_range(false),
                                );
                                ui.end_row();
                                ui.label("DKIM selectors");
                                ui.add(
                                    egui::TextEdit::singleline(&mut app.scan_form.dkim_selectors)
                                        .hint_text("selector1,selector2"),
                                );
                                ui.end_row();
                            }
                            if app.scan_form.security_operations {
                                ui.label("Crawl URLs / domain");
                                ui.add(
                                    egui::DragValue::new(&mut app.scan_form.crawl_max_urls)
                                        .range(limits::CRAWL_URLS)
                                        .clamp_existing_to_range(false),
                                );
                                ui.end_row();
                                ui.label("Concurrent crawl requests");
                                ui.add(
                                    egui::DragValue::new(&mut app.scan_form.crawl_concurrency)
                                        .range(limits::CRAWL_CONCURRENCY)
                                        .clamp_existing_to_range(false),
                                );
                                ui.end_row();
                                ui.label("Crawl requests / second");
                                ui.add(
                                    egui::DragValue::new(&mut app.scan_form.crawl_rate)
                                        .range(limits::CRAWL_RATE)
                                        .clamp_existing_to_range(false),
                                );
                                ui.end_row();
                            }
                        });
                    });
                if matches!( app.scan_form.web_probe_level, crate::WebProbeLevel::StateChanging) {
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        "State-changing probes may create application data. Cleanup is best-effort.",
                    );
                }
                if let Some(error) = &app.ui_error {
                    ui.colored_label(egui::Color32::RED, error);
                }
                ui.horizontal(|ui| {
                    let fingerprints_ready = matches!(
                        fingerprints::initialization_status(),
                        InitializationStatus::Ready { .. }
                    );
                    if ui
                        .add_enabled(
                            fingerprints_ready
                                && !app.scan_form.diagnostic.url.trim().is_empty(),
                            egui::Button::new("Start Scan"),
                        )
                        .clicked()
                    {
                        start = true;
                    }
                    if !fingerprints_ready {
                        ui.spinner();
                        ui.weak("Initializing fingerprint catalog");
                    }
                    if ui.button("Close").clicked() {
                        app.show_exposure_scan = false;
                    }
                });
            });
    }
    start
}

pub(super) fn show_live(ui: &mut egui::Ui, live: &ExposureLiveState) {
    ui.heading("Public Exposure Scan");
    ui.horizontal(|ui| {
        if live.resolving {
            ui.spinner();
        }
        ui.label(&live.message);
    });
    let complete = live
        .phases
        .iter()
        .filter(|phase| phase.state == ExposureScanPhaseState::Complete)
        .count();
    let remaining = live
        .phases
        .iter()
        .filter(|phase| {
            matches!(
                phase.state,
                ExposureScanPhaseState::Pending | ExposureScanPhaseState::Running
            )
        })
        .count();
    let skipped = live
        .phases
        .iter()
        .filter(|phase| phase.state == ExposureScanPhaseState::Skipped)
        .count();
    ui.strong(format!(
        "{complete} phases complete • {remaining} remaining • {skipped} skipped"
    ));
    ui.add_space(4.0);
    for phase in &live.phases {
        let (fraction, animate, fill, status) = match phase.state {
            ExposureScanPhaseState::Pending => (
                0.0,
                false,
                Some(egui::Color32::TRANSPARENT),
                "Pending".to_owned(),
            ),
            ExposureScanPhaseState::Running => (phase.fraction, true, None, phase.text.clone()),
            ExposureScanPhaseState::Complete => (1.0, false, None, "Complete".to_owned()),
            ExposureScanPhaseState::Skipped => {
                (1.0, false, Some(egui::Color32::GRAY), "Skipped".to_owned())
            }
        };
        let mut bar = egui::ProgressBar::new(fraction)
            .animate(animate)
            .text(format!("{} — {status}", phase.phase.label()));
        if let Some(fill) = fill {
            bar = bar.fill(fill);
        }
        ui.add(bar);
    }
    ui.add_space(4.0);
    ui.label(format!(
        "Open endpoints found: {}",
        live.open_endpoints.len()
    ));
    if let Some(endpoint) = &live.last_endpoint {
        ui.weak(format!(
            "Latest: {}:{} — {}",
            endpoint.ip, endpoint.port, endpoint.state
        ));
    }
}

#[path = "exposure_report.rs"]
mod report;
pub(super) use report::show_report;
