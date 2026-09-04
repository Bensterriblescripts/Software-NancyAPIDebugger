use crate::auth::{ProfileSummary, SharedAuthStore};
use crate::diagnostics::{
    DiagnosticRequest, ProtocolPreference, StageTimeouts, TraceOutcome, UserAgentPreset,
};
use crate::exposure::fingerprints::{self, InitializationStatus};
use crate::{
    Confidence, EndpointScan, ExposureScanReport, ExposureScanRequest, PortSelection, PortState,
    ServiceKind, curated_tcp_port_metadata,
};
use eframe::egui;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use super::app::{App, ExposureLiveState};
use super::details::{
    BodyView, DetailTab, show_body, show_http, show_network,
    show_summary as show_diagnostic_summary, show_tls,
};
use super::widgets::display_url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExposurePortChoice {
    Curated,
    Custom,
    All,
}

impl ExposurePortChoice {
    const ALL: [Self; 3] = [Self::Curated, Self::Custom, Self::All];

    fn label(self) -> &'static str {
        match self {
            Self::Curated => "Curated",
            Self::Custom => "Custom",
            Self::All => "All TCP ports",
        }
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

impl TimeoutInputs {
    fn from_timeouts(timeouts: &StageTimeouts) -> Self {
        Self {
            authentication: timeouts.authentication.as_secs_f64(),
            dns: timeouts.dns.as_secs_f64(),
            transport: timeouts.transport.as_secs_f64(),
            tls: timeouts.tls.as_secs_f64(),
            headers: timeouts.headers.as_secs_f64(),
            first_byte: timeouts.first_byte.as_secs_f64(),
            body: timeouts.body.as_secs_f64(),
        }
    }

    fn to_timeouts(&self) -> StageTimeouts {
        StageTimeouts {
            authentication: duration(self.authentication),
            dns: duration(self.dns),
            transport: duration(self.transport),
            tls: duration(self.tls),
            headers: duration(self.headers),
            first_byte: duration(self.first_byte),
            body: duration(self.body),
        }
    }
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
    pub(super) fingerprint_server: bool,
    pub(super) selected_auth_profile: Option<u64>,
    timeouts: TimeoutInputs,
}

#[derive(Debug, Clone)]
pub(super) struct ScanForm {
    pub(super) diagnostic: DiagnosticForm,
    port_choice: ExposurePortChoice,
    custom_ports: String,
    concurrency: usize,
    rate: u32,
    connection_timeout: f64,
    probe_timeout: f64,
    security_operations: bool,
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
                fingerprint_server: diagnostic.fingerprint_server,
                selected_auth_profile: None,
                timeouts: TimeoutInputs::from_timeouts(&diagnostic.timeouts),
            },
            port_choice: ExposurePortChoice::Curated,
            custom_ports: "80,443".to_owned(),
            concurrency: scan.concurrency,
            rate: scan.connection_starts_per_second,
            connection_timeout: scan.connection_timeout.as_secs_f64(),
            probe_timeout: scan.probe_timeout.as_secs_f64(),
            security_operations: true,
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
        if !self.connection_timeout.is_finite()
            || self.connection_timeout <= 0.0
            || !self.probe_timeout.is_finite()
            || self.probe_timeout <= 0.0
        {
            return Err("Exposure scan timeouts must be positive numbers".to_owned());
        }
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
        Ok(ExposureScanRequest {
            diagnostic_request: DiagnosticRequest {
                method: self.diagnostic.method.clone(),
                url: self.diagnostic.url.trim().to_owned(),
                headers: self.diagnostic.headers.clone(),
                body: Arc::from(self.diagnostic.body.as_bytes()),
                protocol: self.diagnostic.protocol,
                timeouts: self.diagnostic.timeouts.to_timeouts(),
                auth,
                follow_redirects: self.diagnostic.follow_redirects,
                user_agent: self.diagnostic.user_agent,
                fingerprint_server: self.diagnostic.fingerprint_server,
            },
            ports: selection(self)?,
            connection_timeout: Duration::from_secs_f64(self.connection_timeout),
            probe_timeout: Duration::from_secs_f64(self.probe_timeout),
            concurrency: self.concurrency,
            connection_starts_per_second: self.rate,
            security_operations: self.security_operations,
            crawl_max_urls: self.crawl_max_urls,
            crawl_concurrency: self.crawl_concurrency,
            crawl_requests_per_second: self.crawl_rate,
        })
    }
}

pub(super) struct DiagnosticViewState {
    pub(super) endpoint_index: usize,
    pub(super) hop_index: usize,
    pub(super) tab: DetailTab,
    pub(super) body_view: BodyView,
    initialized: bool,
}

impl Default for DiagnosticViewState {
    fn default() -> Self {
        Self {
            endpoint_index: 0,
            hop_index: 0,
            tab: DetailTab::Summary,
            body_view: BodyView::Decoded,
            initialized: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExposureDetailTab {
    Diagnostics,
    Ports,
    HttpTls,
    Evidence,
    Crawl,
    JavaScript,
    SecuritySummary,
}

impl ExposureDetailTab {
    pub(super) const ALL: [Self; 7] = [
        Self::Diagnostics,
        Self::Ports,
        Self::HttpTls,
        Self::Evidence,
        Self::Crawl,
        Self::JavaScript,
        Self::SecuritySummary,
    ];

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Diagnostics => "Diagnostics",
            Self::Ports => "Ports",
            Self::HttpTls => "HTTP / TLS",
            Self::Evidence => "Evidence",
            Self::Crawl => "Crawl",
            Self::JavaScript => "Technology Versions",
            Self::SecuritySummary => "Security Summary",
        }
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
                ui.label("Scan only a public target you are authorized to assess.");
                ui.separator();
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
                    egui::ComboBox::from_id_salt("exposure_ports")
                        .selected_text(app.scan_form.port_choice.label())
                        .show_ui(ui, |ui| {
                            for choice in ExposurePortChoice::ALL {
                                ui.selectable_value(
                                    &mut app.scan_form.port_choice,
                                    choice,
                                    choice.label(),
                                );
                            }
                        });
                });
                if app.scan_form.port_choice == ExposurePortChoice::Custom {
                    ui.add(
                        egui::TextEdit::singleline(&mut app.scan_form.custom_ports)
                            .desired_width(f32::INFINITY)
                            .hint_text("80,443,8000-8100"),
                    );
                }
                egui::CollapsingHeader::new("Advanced settings")
                    .default_open(true)
                    .show(ui, |ui| {
                        show_diagnostic_inputs(ui, app);
                        ui.separator();
                        egui::Grid::new("exposure_advanced").show(ui, |ui| {
                            ui.label("Concurrent endpoints");
                            ui.add(
                                egui::DragValue::new(&mut app.scan_form.concurrency)
                                    .range(1..=4096),
                            );
                            ui.end_row();
                            ui.label("Connection starts / second");
                            ui.add(egui::DragValue::new(&mut app.scan_form.rate).range(1..=10_000));
                            ui.end_row();
                            ui.label("Connection timeout");
                            ui.add(
                                egui::DragValue::new(&mut app.scan_form.connection_timeout)
                                    .range(0.1..=120.0)
                                    .suffix(" s"),
                            );
                            ui.end_row();
                            ui.label("Probe timeout");
                            ui.add(
                                egui::DragValue::new(&mut app.scan_form.probe_timeout)
                                    .range(0.1..=300.0)
                                    .suffix(" s"),
                            );
                            ui.end_row();
                            ui.label("Security Operations");
                            ui.checkbox(
                            &mut app.scan_form.security_operations,
                            "Crawl, technology versions, cookie/session, URL-token, and CSP checks",
                        );
                            ui.end_row();
                            ui.add_enabled_ui(app.scan_form.security_operations, |ui| {
                                ui.label("Crawl URLs / domain");
                            });
                            ui.add_enabled(
                                app.scan_form.security_operations,
                                egui::DragValue::new(&mut app.scan_form.crawl_max_urls)
                                    .range(1..=100_000),
                            );
                            ui.end_row();
                            ui.label("Concurrent crawl requests");
                            ui.add_enabled(
                                app.scan_form.security_operations,
                                egui::DragValue::new(&mut app.scan_form.crawl_concurrency)
                                    .range(1..=1024),
                            );
                            ui.end_row();
                            ui.label("Crawl requests / second");
                            ui.add_enabled(
                                app.scan_form.security_operations,
                                egui::DragValue::new(&mut app.scan_form.crawl_rate)
                                    .range(1..=10_000),
                            );
                            ui.end_row();
                        });
                    });
                ui.horizontal(|ui| {
                    let fingerprints_ready = matches!(
                        fingerprints::initialization_status(),
                        InitializationStatus::Ready { .. }
                    );
                    if ui
                        .add_enabled(
                            fingerprints_ready && !app.scan_form.diagnostic.url.trim().is_empty(),
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

pub(super) fn selection(form: &ScanForm) -> Result<PortSelection, String> {
    match form.port_choice {
        ExposurePortChoice::Curated => Ok(PortSelection::Curated),
        ExposurePortChoice::All => Ok(PortSelection::All),
        ExposurePortChoice::Custom => PortSelection::parse(&form.custom_ports),
    }
}

fn show_diagnostic_inputs(ui: &mut egui::Ui, app: &mut App) {
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
    ui.checkbox(
        &mut app.scan_form.diagnostic.fingerprint_server,
        "Analyze server identity from the diagnostic response",
    );
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
                for profile in &profiles {
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
    egui::CollapsingHeader::new("Stage timeouts")
        .default_open(true)
        .show(ui, |ui| {
            show_timeout_inputs(ui, &mut app.scan_form.diagnostic.timeouts)
        });
}

fn show_timeout_inputs(ui: &mut egui::Ui, values: &mut TimeoutInputs) {
    egui::Grid::new("scan_timeouts").show(ui, |ui| {
        timeout_row(ui, "Authentication", &mut values.authentication);
        timeout_row(ui, "DNS", &mut values.dns);
        timeout_row(ui, "TCP / QUIC", &mut values.transport);
        timeout_row(ui, "TLS", &mut values.tls);
        timeout_row(ui, "HTTP headers", &mut values.headers);
        timeout_row(ui, "First byte", &mut values.first_byte);
        timeout_row(ui, "Body", &mut values.body);
    });
}

fn timeout_row(ui: &mut egui::Ui, label: &str, value: &mut f64) {
    ui.label(label);
    ui.add(
        egui::DragValue::new(value)
            .range(0.1..=3600.0)
            .speed(0.5)
            .suffix(" s"),
    );
    ui.end_row();
}

fn duration(seconds: f64) -> Duration {
    Duration::from_secs_f64(seconds.clamp(0.1, 3600.0))
}

pub(super) fn show_live(ui: &mut egui::Ui, live: &ExposureLiveState) {
    ui.heading("Public Exposure Scan");
    ui.label(&live.message);
    if live.total > 0 {
        ui.add(
            egui::ProgressBar::new(live.completed as f32 / live.total as f32)
                .text(format!("{} / {} endpoints", live.completed, live.total)),
        );
    } else {
        ui.spinner();
    }
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

pub(super) fn show_report(
    ui: &mut egui::Ui,
    report: &ExposureScanReport,
    tab: ExposureDetailTab,
    diagnostic_view: &mut DiagnosticViewState,
) {
    egui::ScrollArea::vertical().show(ui, |ui| match tab {
        ExposureDetailTab::Diagnostics => {
            show_summary(ui, report);
            ui.separator();
            show_diagnostics(ui, report, diagnostic_view);
        }
        ExposureDetailTab::Ports => show_ports(ui, report),
        ExposureDetailTab::HttpTls => show_http_tls(ui, report),
        ExposureDetailTab::Evidence => show_evidence(ui, report),
        ExposureDetailTab::Crawl => show_crawl(ui, report),
        ExposureDetailTab::JavaScript => show_technology(ui, report),
        ExposureDetailTab::SecuritySummary => show_security_summary(ui, report),
    });
}

fn show_diagnostics(
    ui: &mut egui::Ui,
    report: &ExposureScanReport,
    view: &mut DiagnosticViewState,
) {
    let endpoint_indices = report
        .endpoints
        .iter()
        .enumerate()
        .filter_map(|(index, endpoint)| (!endpoint.diagnostics.is_empty()).then_some(index))
        .collect::<Vec<_>>();
    let Some(&first_endpoint) = endpoint_indices.first() else {
        ui.heading("Endpoint Diagnostics");
        ui.weak("No HTTP or HTTPS endpoints were discovered.");
        return;
    };
    if !view.initialized {
        let preferred = endpoint_indices.iter().find_map(|&endpoint_index| {
            report.endpoints[endpoint_index]
                .diagnostics
                .iter()
                .position(|trace| {
                    trace.outcome == TraceOutcome::Success
                        && trace
                            .http
                            .status
                            .is_some_and(|status| (200..=299).contains(&status))
                })
                .map(|hop_index| (endpoint_index, hop_index))
        });
        (view.endpoint_index, view.hop_index) = preferred.unwrap_or((first_endpoint, 0));
        view.initialized = true;
    } else if !endpoint_indices.contains(&view.endpoint_index) {
        view.endpoint_index = first_endpoint;
        view.hop_index = 0;
    }
    ui.horizontal_wrapped(|ui| {
        ui.label("Endpoint");
        let selected = &report.endpoints[view.endpoint_index];
        egui::ComboBox::from_id_salt("diagnostic_endpoint")
            .selected_text(format!("{}:{}", selected.ip, selected.port))
            .show_ui(ui, |ui| {
                for &index in &endpoint_indices {
                    let endpoint = &report.endpoints[index];
                    if ui
                        .selectable_value(
                            &mut view.endpoint_index,
                            index,
                            format!("{}:{} — {}", endpoint.ip, endpoint.port, endpoint.service),
                        )
                        .clicked()
                    {
                        view.hop_index = 0;
                    }
                }
            });
    });
    let endpoint = &report.endpoints[view.endpoint_index];
    view.hop_index = view.hop_index.min(endpoint.diagnostics.len() - 1);
    ui.horizontal_wrapped(|ui| {
        ui.label("Hop");
        egui::ComboBox::from_id_salt("diagnostic_hop")
            .selected_text(format!(
                "{} — {}",
                view.hop_index + 1,
                display_url(&endpoint.diagnostics[view.hop_index])
            ))
            .show_ui(ui, |ui| {
                for (index, trace) in endpoint.diagnostics.iter().enumerate() {
                    ui.selectable_value(
                        &mut view.hop_index,
                        index,
                        format!("{} — {}", index + 1, display_url(trace)),
                    );
                }
            });
    });
    ui.horizontal_wrapped(|ui| {
        for tab in DetailTab::ALL {
            ui.selectable_value(&mut view.tab, tab, tab.label());
        }
    });
    ui.separator();
    let trace = &endpoint.diagnostics[view.hop_index];
    let chain = endpoint.diagnostics.iter().collect::<Vec<_>>();
    match view.tab {
        DetailTab::Summary => show_diagnostic_summary(ui, trace, &chain),
        DetailTab::Network => show_network(ui, trace),
        DetailTab::Tls => show_tls(ui, trace),
        DetailTab::Http => show_http(ui, trace),
        DetailTab::Body => show_body(ui, trace, &mut view.body_view),
    }
}

fn show_summary(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("Public Exposure Summary");
    egui::Grid::new("exposure_summary")
        .striped(true)
        .show(ui, |ui| {
            row(ui, "Target", &report.request.diagnostic_request.url);
            row(ui, "Hostname / SNI", &report.hostname);
            row(ui, "Status", &report.status.to_string());
            row(
                ui,
                "Public IPv4 addresses",
                &report
                    .resolved_addresses
                    .iter()
                    .filter(|address| address.is_ipv4())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            row(
                ui,
                "Public IPv6 addresses",
                &report
                    .resolved_addresses
                    .iter()
                    .filter(|address| address.is_ipv6())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            row(
                ui,
                "Open endpoints",
                &state_count(report, PortState::Open).to_string(),
            );
            row(ui, "Security Summary", &report.findings.len().to_string());
            row(
                ui,
                "Total time",
                &format!("{:.2} s", report.timings.total_ms / 1_000.0),
            );
        });
    if let Some(error) = &report.error {
        ui.colored_label(egui::Color32::RED, error);
    }
    for warning in &report.warnings {
        ui.colored_label(egui::Color32::YELLOW, warning);
    }
    let technologies = open_endpoints(report)
        .flat_map(|endpoint| {
            endpoint
                .products
                .iter()
                .filter(|product| {
                    matches!(
                        product.layer,
                        crate::ProductLayer::Cms | crate::ProductLayer::Ecommerce
                    )
                })
                .map(move |product| (endpoint, product))
        })
        .collect::<Vec<_>>();
    if !technologies.is_empty() {
        ui.separator();
        ui.heading("CMS and E-commerce Visibility");
        for (endpoint, product) in &technologies {
            ui.label(format!(
                "{} [{}]{} — {} confidence — {}:{}",
                product.name,
                product.layer,
                product
                    .version
                    .as_ref()
                    .map(|version| format!(" {version}"))
                    .unwrap_or_default(),
                product.confidence,
                endpoint.ip,
                endpoint.port
            ));
        }
        let generic = technologies
            .iter()
            .any(|(_, product)| product.name == "Generic commerce");
        ui.weak(format!(
            "Generic commerce detected: {}",
            if generic { "Yes" } else { "No" }
        ));
    }
}

fn show_ports(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("TCP Ports");
    ui.horizontal_wrapped(|ui| {
        ui.label(format!("Open: {}", state_count(report, PortState::Open)));
        ui.weak(format!(
            "Closed: {}",
            state_count(report, PortState::Closed)
        ));
        ui.weak(format!(
            "Filtered/no response: {}",
            state_count(report, PortState::FilteredOrNoResponse)
        ));
        ui.weak(format!("Errors: {}", state_count(report, PortState::Error)));
        ui.weak(format!(
            "Cancelled: {}",
            state_count(report, PortState::Cancelled)
        ));
    });
    for endpoint in open_endpoints(report) {
        ui.separator();
        egui::CollapsingHeader::new(format!("{}:{}", endpoint.ip, endpoint.port))
            .default_open(false)
            .show(ui, |ui| {
                ui.label(format!(
                    "{} ({}) — {:.2} ms",
                    endpoint.service, endpoint.service_confidence, endpoint.connect_duration_ms
                ));
                if endpoint.products.is_empty() {
                    ui.weak("Product undisclosed");
                } else {
                    for product in &endpoint.products {
                        ui.label(format!(
                            "{} [{}]{} — {} confidence",
                            product.name,
                            product.layer,
                            product
                                .version
                                .as_ref()
                                .map(|version| format!(" {version}"))
                                .unwrap_or_default(),
                            product.confidence
                        ));
                    }
                }
            });
    }
}

fn show_http_tls(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("HTTP / TLS Observations");
    for endpoint in open_endpoints(report) {
        if endpoint.tls.is_empty() && endpoint.http.is_empty() {
            continue;
        }
        ui.separator();
        egui::CollapsingHeader::new(
            egui::RichText::new(format!("{}:{}", endpoint.ip, endpoint.port)).strong(),
        )
        .default_open(false)
        .show(ui, |ui| {
            for tls in &endpoint.tls {
                if tls.supported {
                    ui.label(format!(
                        "{}: {}; {}; ALPN {}; cipher {}",
                        tls.requested_version,
                        tls.negotiated_version.as_deref().unwrap_or("negotiated"),
                        if tls.verified { "valid" } else { "UNVERIFIED" },
                        tls.alpn.as_deref().unwrap_or("none"),
                        tls.cipher.as_deref().unwrap_or("undisclosed")
                    ));
                    if let Some(error) = &tls.validation_error {
                        ui.colored_label(egui::Color32::YELLOW, error);
                    }
                    for certificate in &tls.certificates {
                        ui.weak(format!(
                            "Certificate: {}; issuer: {}; valid {} to {}",
                            certificate.subject,
                            certificate.issuer,
                            certificate.not_before,
                            certificate.not_after
                        ));
                    }
                }
            }
            for http in &endpoint.http {
                ui.label(format!(
                    "{} {} → {} {}{}",
                    http.method,
                    http.url,
                    http.status,
                    http.reason,
                    if http.tls_unverified {
                        " [UNVERIFIED TLS]"
                    } else {
                        ""
                    }
                ));
                for (name, value) in &http.headers {
                    ui.weak(format!("{name}: {value}"));
                }
            }
        });
    }
}

fn show_evidence(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("Service and Product Evidence");
    for endpoint in open_endpoints(report) {
        ui.separator();
        ui.strong(format!(
            "{}:{} — {}",
            endpoint.ip, endpoint.port, endpoint.service
        ));
        for evidence in &endpoint.evidence {
            ui.label(evidence);
        }
        for product in &endpoint.products {
            ui.label(format!(
                "{} — {} confidence",
                product.name, product.confidence
            ));
            for evidence in product
                .evidence
                .iter()
                .filter(|evidence| !is_noisy_header_evidence(evidence))
            {
                ui.weak(evidence);
            }
        }
    }
}

fn is_noisy_header_evidence(evidence: &str) -> bool {
    evidence.starts_with("header cf-ray at ") || evidence.starts_with("header server at ")
}

fn show_crawl(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("Crawl Inventory");
    if !report.request.security_operations {
        ui.weak("Security Operations crawling was disabled.");
        return;
    }
    ui.label(format!(
        "{} origins; {} reported URLs; {} forms; {} skipped URLs; {} external indicators",
        report.crawl_origins.len(),
        report.crawled_resources.len(),
        report.crawl_forms.len(),
        report.crawl_skipped_urls.len(),
        report.crawl_external_indicators.len()
    ));
    for origin in &report.crawl_origins {
        ui.separator();
        ui.strong(format!(
            "{}://{}:{} ({}) — {}/{} completed",
            origin.scheme, origin.hostname, origin.port, origin.ip, origin.completed, origin.queued
        ));
        ui.weak(format!("Seed: {}", origin.seed_url));
        for exclusion in &origin.robots_exclusions {
            ui.weak(format!("robots.txt exclusion (informational): {exclusion}"));
        }
        for sitemap in &origin.sitemap_urls {
            ui.weak(format!("Sitemap: {sitemap}"));
        }
    }
    let mut visible_resources = report.crawled_resources.iter().peekable();
    if visible_resources.peek().is_some() {
        ui.separator();
        ui.heading("Discovered URLs");
        for resource in visible_resources {
            let result = resource
                .status
                .map(|status| format!("HTTP {status}"))
                .or_else(|| resource.error.clone())
                .unwrap_or_else(|| "No result".to_owned());
            ui.label(format!(
                "Depth {} — {} — {} — {} bytes{}",
                resource.depth,
                resource.url,
                result,
                resource.bytes_inspected,
                if resource.body_truncated {
                    " (truncated)"
                } else {
                    ""
                }
            ));
            if !resource.detected_file_types.is_empty() {
                ui.weak(format!(
                    "Detected: {}",
                    resource
                        .detected_file_types
                        .iter()
                        .map(|detected| format!(
                            "{} ({} confidence)",
                            detected.file_type, detected.confidence
                        ))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }
    if !report.crawl_forms.is_empty() {
        ui.separator();
        ui.heading("Forms");
        for form in &report.crawl_forms {
            ui.label(format!(
                "{} {} — source {}{}{}",
                form.method,
                form.action_url,
                form.source_url,
                if form.has_password {
                    " — password field"
                } else {
                    ""
                },
                if form.enqueued { " — GET queued" } else { "" }
            ));
        }
    }
    if !report.crawl_skipped_urls.is_empty() {
        ui.separator();
        ui.heading("Skipped URLs");
        for skipped in &report.crawl_skipped_urls {
            ui.weak(format!("{} — {}", skipped.url, skipped.reason));
        }
    }
    if !report.crawl_external_indicators.is_empty() {
        ui.separator();
        ui.heading("External Indicators");
        ui.weak("Report-only; these indicators were never contacted.");
        for indicator in &report.crawl_external_indicators {
            ui.label(format!(
                "{}: {} — {} — source {}",
                indicator.kind, indicator.value, indicator.evidence, indicator.source_url
            ));
        }
    }
}

fn show_evidence_disclosure(
    ui: &mut egui::Ui,
    id_salt: impl std::hash::Hash,
    evidence_urls: &[String],
    evidence: &[String],
) {
    let count = evidence_urls.len() + evidence.len();
    if count == 0 {
        return;
    }

    egui::CollapsingHeader::new(format!("Evidence ({count})"))
        .id_salt(id_salt)
        .default_open(false)
        .show(ui, |ui| {
            for url in evidence_urls {
                ui.weak(format!("Evidence URL: {url}"));
            }
            for item in evidence {
                ui.weak(format!("Evidence: {item}"));
            }
        });
}

fn show_technology(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("Technology Versions");
    show_technology_inventory(ui, report);
    ui.separator();
    ui.heading("Evidence and Details");
    ui.heading("Detected Web Technologies");
    let mut technologies =
        BTreeMap::<String, Vec<(&EndpointScan, &crate::WebTechnologyDetection)>>::new();
    for endpoint in open_endpoints(report) {
        for technology in &endpoint.web_technologies {
            technologies
                .entry(technology.name.to_ascii_lowercase())
                .or_default()
                .push((endpoint, technology));
        }
    }
    if technologies.is_empty() {
        ui.weak("No passive web technology signatures matched.");
    } else {
        for matches in technologies.into_values() {
            let name = &matches[0].1.name;
            ui.separator();
            ui.strong(name);
            for (endpoint, technology) in matches {
                ui.label(format!(
                    "{} — {} confidence — {}:{}",
                    technology
                        .version
                        .as_deref()
                        .unwrap_or("version not observed"),
                    technology.confidence,
                    endpoint.ip,
                    endpoint.port
                ));
                ui.weak(format!(
                    "Categories: {}",
                    if technology.category_names.is_empty() {
                        "Uncategorized".to_owned()
                    } else {
                        technology.category_names.join(", ")
                    }
                ));
                show_evidence_disclosure(
                    ui,
                    (
                        "web-technology-evidence",
                        endpoint.ip,
                        endpoint.port,
                        &technology.name,
                        &technology.version,
                    ),
                    &technology.evidence_urls,
                    &technology.evidence,
                );
            }
        }
    }
    ui.separator();
    if !report.request.security_operations {
        ui.weak("Crawling and technology version analysis were disabled with Security Operations; passive web fingerprinting still ran.");
        return;
    }
    ui.heading("Detected Languages / File Types");
    let mut detected = BTreeMap::<String, Vec<String>>::new();
    for resource in &report.crawled_resources {
        for item in &resource.detected_file_types {
            if item.file_type.language() == "JavaScript" {
                continue;
            }
            detected
                .entry(item.file_type.language().to_owned())
                .or_default()
                .push(format!(
                    "{} — {} confidence",
                    item.file_type, item.confidence
                ));
        }
    }
    if detected.is_empty() {
        ui.weak("No supported remotely observable file types were detected.");
    } else {
        for (language, mut file_types) in detected {
            file_types.sort();
            file_types.dedup();
            ui.label(format!("{language}: {}", file_types.join(", ")));
        }
    }
    ui.separator();
    ui.heading("Servers, Frameworks, Plugins, Runtimes, and Packages");
    let mut components_found = false;
    for endpoint in open_endpoints(report) {
        for component in &endpoint.technology_components {
            components_found = true;
            ui.label(format!(
                "{}: {} {} — {} — latest stable {}",
                component.kind,
                component.name,
                component
                    .installed_version
                    .as_deref()
                    .unwrap_or("(version not observed)"),
                component.status,
                component.latest_version.as_deref().unwrap_or("not checked")
            ));
            ui.weak(format!(
                "{}; {} confidence{}{}",
                component.ecosystem,
                component.confidence,
                component
                    .package_identifier
                    .as_deref()
                    .map(|package| format!("; registry identifier: {package}"))
                    .unwrap_or_default(),
                if component.support_status == crate::TechnologySupportStatus::NotApplicable {
                    String::new()
                } else {
                    format!("; lifecycle: {}", component.support_status)
                }
            ));
            if let Some(source) = &component.release_source_url {
                ui.hyperlink_to("Upstream release/lifecycle source", source);
            }
            show_evidence_disclosure(
                ui,
                (
                    "technology-component-evidence",
                    endpoint.ip,
                    endpoint.port,
                    component.ecosystem,
                    component.kind,
                    &component.name,
                    &component.package_identifier,
                    &component.installed_version,
                ),
                &component.evidence_urls,
                &component.evidence,
            );
            if let Some(error) = &component.check_error {
                ui.weak(format!("Version check: {error}"));
            }
        }
    }
    if !components_found {
        ui.weak("No servers, frameworks, plugins, runtimes, or packages were identified.");
    }
    ui.separator();
    ui.heading("JavaScript Sources");
    let mut found = false;
    for endpoint in open_endpoints(report) {
        for source in &endpoint.javascript_sources {
            found = true;
            ui.separator();
            egui::CollapsingHeader::new(egui::RichText::new(&source.source_url).strong())
                .id_salt((endpoint.ip, endpoint.port, &source.source_url))
                .default_open(false)
                .show(ui, |ui| {
                    ui.weak(format!("Endpoint: {}:{}", endpoint.ip, endpoint.port));
                    if let Some(final_url) = source
                        .final_url
                        .as_deref()
                        .filter(|final_url| *final_url != source.source_url)
                    {
                        ui.label(format!("Final URL: {final_url}"));
                    }
                    if let Some(status) = source.http_status {
                        ui.label(format!(
                            "HTTP {} {} — {} bytes{}",
                            status,
                            source.http_reason.as_deref().unwrap_or_default(),
                            source.captured_size,
                            if source.truncated { " (truncated)" } else { "" }
                        ));
                    }
                    if let Some(hash) = &source.sha256 {
                        ui.weak(format!("SHA-256: {hash}"));
                    }
                    if let Some(error) = &source.retrieval_error {
                        ui.colored_label(egui::Color32::YELLOW, format!("Retrieval: {error}"));
                    }
                    if let Some(error) = &source.analysis_error {
                        ui.colored_label(egui::Color32::YELLOW, format!("Analysis: {error}"));
                    }
                    if source.libraries.is_empty() && source.retrieval_error.is_none() {
                        ui.weak("No JavaScript library or version signature matched this source");
                    }
                    for library in &source.libraries {
                        ui.label(format!(
                            "{} {} — {} — npm newest stable {}",
                            library.name,
                            library
                                .installed_version
                                .as_deref()
                                .unwrap_or("version unknown"),
                            library.status,
                            library.latest_version.as_deref().unwrap_or("not checked")
                        ));
                        if let Some(package) = &library.npm_package {
                            ui.weak(format!("npm package: {package}"));
                        }
                        show_evidence_disclosure(
                            ui,
                            (
                                "javascript-library-evidence",
                                endpoint.ip,
                                endpoint.port,
                                &source.source_url,
                                &library.name,
                                &library.npm_package,
                                &library.installed_version,
                            ),
                            &[],
                            &library.evidence,
                        );
                        if let Some(error) = &library.check_error {
                            ui.weak(format!("Version check: {error}"));
                        }
                    }
                });
        }
    }
    if !found {
        ui.weak("No HTTP(S) script sources were discovered on root pages or during crawling.");
    }
}

fn show_technology_inventory(ui: &mut egui::Ui, report: &ExposureScanReport) {
    let mut web_technologies = BTreeSet::new();
    let mut file_types = BTreeSet::new();
    let mut components = BTreeSet::new();
    let mut libraries = BTreeSet::new();

    for endpoint in open_endpoints(report) {
        for technology in &endpoint.web_technologies {
            web_technologies.insert(format!(
                "{} {} — {} confidence",
                technology.name,
                technology
                    .version
                    .as_deref()
                    .unwrap_or("(version not observed)"),
                technology.confidence
            ));
        }
        for component in &endpoint.technology_components {
            components.insert(format!(
                "{}: {} {} — {}",
                component.kind,
                component.name,
                component
                    .installed_version
                    .as_deref()
                    .unwrap_or("(version not observed)"),
                component.status
            ));
        }
        for source in &endpoint.javascript_sources {
            for library in &source.libraries {
                libraries.insert(format!(
                    "{} {} — {}",
                    library.name,
                    library
                        .installed_version
                        .as_deref()
                        .unwrap_or("(version not observed)"),
                    library.status
                ));
            }
        }
    }

    for resource in &report.crawled_resources {
        for item in &resource.detected_file_types {
            file_types.insert(format!(
                "{}: {} — {} confidence",
                item.file_type.language(),
                item.file_type,
                item.confidence
            ));
        }
    }

    ui.heading("Concise Inventory");
    if web_technologies.is_empty()
        && file_types.is_empty()
        && components.is_empty()
        && libraries.is_empty()
    {
        ui.weak("No technologies, file types, components, or JavaScript libraries were detected.");
        return;
    }

    for (heading, entries) in [
        ("Web Technologies", &web_technologies),
        ("Languages / File Types", &file_types),
        ("Components", &components),
        ("JavaScript Libraries", &libraries),
    ] {
        if entries.is_empty() {
            continue;
        }
        ui.strong(heading);
        for entry in entries {
            ui.label(format!("• {entry}"));
        }
    }
}

fn show_security_summary(ui: &mut egui::Ui, report: &ExposureScanReport) {
    ui.heading("Security Summary");
    if !report.request.security_operations {
        ui.weak("Security Operations crawling, technology versions, cookie/session, web-storage, URL-token, and CSP checks were disabled; standard confirmed-risk checks still ran.");
    }
    ui.separator();
    ui.heading(format!("Confirmed Findings ({})", report.findings.len()));
    if report.findings.is_empty() {
        ui.weak("No confirmed security findings were observed by the bounded checks.");
    } else {
        let mut missing_browser_headers_shown = false;
        for finding in &report.findings {
            if finding.title == "Browser security headers are missing" {
                if missing_browser_headers_shown {
                    continue;
                }
                missing_browser_headers_shown = true;
                ui.separator();
                ui.strong(&finding.title);
                ui.label(&finding.description);
                for grouped in report
                    .findings
                    .iter()
                    .filter(|grouped| grouped.title == finding.title)
                {
                    ui.label(format!("Endpoint: {}:{}", grouped.ip, grouped.port));
                    show_missing_browser_header_evidence(ui, &grouped.evidence);
                }
                continue;
            }
            if finding.title.starts_with("Outdated component: ") {
                ui.separator();
                ui.strong(&finding.title);
                let affected_resource = finding
                    .evidence
                    .iter()
                    .find_map(|item| item.strip_prefix("Affected resource: "));
                if let Some(url) = affected_resource {
                    ui.label(format!("Endpoint: {}:{} | {url}", finding.ip, finding.port));
                } else {
                    ui.label(format!("Endpoint: {}:{}", finding.ip, finding.port));
                }
                continue;
            }
            ui.separator();
            ui.strong(&finding.title);
            ui.label(&finding.description);
            ui.label(format!("Endpoint: {}:{}", finding.ip, finding.port));
            for evidence in &finding.evidence {
                ui.weak(format!("Evidence: {evidence}"));
            }
        }
    }

    let mut exposed_services = open_endpoints(report)
        .filter(|endpoint| !matches!(endpoint.service, ServiceKind::Http | ServiceKind::Https))
        .collect::<Vec<_>>();
    exposed_services.sort_by(|left, right| left.ip.cmp(&right.ip).then(left.port.cmp(&right.port)));
    if !exposed_services.is_empty() {
        ui.separator();
        ui.heading(format!(
            "Publicly Exposed Services ({})",
            exposed_services.len()
        ));
        for endpoint in exposed_services {
            ui.label(format!(
                "{}:{} — {}",
                endpoint.ip,
                endpoint.port,
                exposed_service_label(endpoint)
            ));
        }
    }

    let technologies = open_endpoints(report)
        .flat_map(|endpoint| {
            endpoint
                .products
                .iter()
                .filter(|product| {
                    matches!(
                        product.layer,
                        crate::ProductLayer::Cms | crate::ProductLayer::Ecommerce
                    )
                })
                .map(move |product| (endpoint, product))
        })
        .collect::<Vec<_>>();
    if !technologies.is_empty() {
        ui.separator();
        ui.heading("Technology Visibility");
        ui.weak("Platform presence, exposed pages, and version disclosure are visibility information, not vulnerabilities by themselves.");
        for (endpoint, product) in technologies {
            ui.strong(format!(
                "{} [{}]{} — {} confidence — {}:{}",
                product.name,
                product.layer,
                product
                    .version
                    .as_ref()
                    .map(|version| format!(" {version}"))
                    .unwrap_or_default(),
                product.confidence,
                endpoint.ip,
                endpoint.port
            ));
            for evidence in &product.evidence {
                ui.weak(format!("Evidence: {evidence}"));
            }
        }
    }

    let mut surfaces = open_endpoints(report)
        .flat_map(|endpoint| {
            endpoint
                .observed_web_surfaces
                .iter()
                .map(move |surface| (endpoint, surface))
        })
        .collect::<Vec<_>>();
    surfaces.sort_by(|(left_endpoint, left), (right_endpoint, right)| {
        left_endpoint
            .ip
            .cmp(&right_endpoint.ip)
            .then(left_endpoint.port.cmp(&right_endpoint.port))
            .then(left.url.cmp(&right.url))
            .then(left.surface_type.cmp(&right.surface_type))
    });
    if !surfaces.is_empty() || !report.crawl_observed_web_surfaces.is_empty() {
        ui.separator();
        ui.heading(format!(
            "Observed Web Surfaces ({})",
            surfaces.len() + report.crawl_observed_web_surfaces.len()
        ));
        ui.weak("These are informational observations, not confirmed vulnerabilities or evidence of an authorization bypass.");
        for (endpoint, surface) in surfaces {
            ui.strong(format!(
                "{} {} — {} — HTTP {} — {} confidence",
                surface.technology,
                surface.surface_type,
                surface.url,
                surface.status,
                surface.confidence
            ));
            ui.weak(format!(
                "Scanned endpoint: {}:{}",
                endpoint.ip, endpoint.port
            ));
            for evidence in &surface.evidence {
                ui.weak(format!("Evidence: {evidence}"));
            }
        }
        for surface in &report.crawl_observed_web_surfaces {
            ui.strong(format!(
                "{} — {} — HTTP {} — {} confidence",
                surface.surface_type, surface.url, surface.status, surface.confidence
            ));
            ui.weak(format!(
                "Scanned endpoint: {}:{} — anonymous crawl observation",
                surface.ip, surface.port
            ));
            for evidence in &surface.evidence {
                ui.weak(format!("Evidence: {evidence}"));
            }
        }
    }
}

fn show_missing_browser_header_evidence(ui: &mut egui::Ui, evidence: &[String]) {
    let mut groups = BTreeMap::<Vec<String>, (Option<&str>, Option<&str>, usize)>::new();
    let mut ungrouped = Vec::new();
    for value in evidence {
        let Some((headers, page)) = missing_browser_header_set(value) else {
            ungrouped.push(value.as_str());
            continue;
        };
        let group = groups.entry(headers).or_default();
        if page {
            group.0.get_or_insert(value);
            group.2 += 1;
        } else {
            group.1.get_or_insert(value);
        }
    }
    for (_, (page_evidence, generic_evidence, page_count)) in groups {
        if let Some(value) = page_evidence {
            let page_label = if page_count == 1 { "page" } else { "pages" };
            ui.weak(format!(
                "Evidence: {value} ({page_count} {page_label} with this header set)"
            ));
        } else if let Some(value) = generic_evidence {
            ui.weak(format!("Evidence: {value}"));
        }
    }
    for value in ungrouped {
        ui.weak(format!("Evidence: {value}"));
    }
}

fn missing_browser_header_set(evidence: &str) -> Option<(Vec<String>, bool)> {
    let (headers, page) = if let Some(headers) = evidence.strip_prefix("Missing: ") {
        (headers, false)
    } else {
        let (_, headers) = evidence.rsplit_once(" missing ")?;
        (headers, true)
    };
    let mut headers = headers
        .split(',')
        .map(str::trim)
        .filter(|header| !header.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if headers.is_empty() {
        return None;
    }
    headers.sort();
    headers.dedup();
    Some((headers, page))
}

fn exposed_service_label(endpoint: &EndpointScan) -> String {
    if endpoint.service != ServiceKind::Unknown {
        return endpoint.service.to_string();
    }
    if endpoint.service_confidence == Confidence::Low
        && let Some(metadata) = curated_tcp_port_metadata(endpoint.port)
    {
        return format!("{} (unconfirmed)", metadata.service_name);
    }
    "Unknown service".to_owned()
}

fn state_count(report: &ExposureScanReport, state: PortState) -> usize {
    report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.state == state)
        .count()
}

fn open_endpoints(report: &ExposureScanReport) -> impl Iterator<Item = &EndpointScan> {
    report
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.state == PortState::Open)
}

fn row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.strong(label);
    ui.label(if value.is_empty() { "None" } else { value });
    ui.end_row();
}
