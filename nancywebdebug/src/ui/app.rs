use crate::auth::{self, ProfileInput, SharedAuthStore};
use crate::exposure::fingerprints::{self, InitializationStatus};
use crate::{
    EndpointScan, ExposureScanPhase, ExposureScanPhaseState, ExposureScanProgress,
    ExposureScanReport, ExposureScanRequest, ExposureScanStatus, ExposureScanTimings, PortState,
    run_exposure_scan_with_auth_store,
};
use eframe::egui;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use super::exposure_view::{self, DiagnosticViewState, ExposureDetailTab, ScanForm};

use super::{auth_profiles, history};

struct ActiveScan {
    scan_number: usize,
    cancel: CancellationToken,
}

pub(super) struct ExposureLiveState {
    pub(super) message: String,
    pub(super) resolving: bool,
    pub(super) completed: usize,
    pub(super) total: usize,
    pub(super) open_endpoints: Vec<EndpointScan>,
    pub(super) last_endpoint: Option<EndpointScan>,
    pub(super) phases: [ExposureLivePhase; ExposureScanPhase::ALL.len()],
}

pub(super) struct ExposureLivePhase {
    pub(super) phase: ExposureScanPhase,
    pub(super) state: ExposureScanPhaseState,
    pub(super) fraction: f32,
    pub(super) text: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkerKind {
    Scan,
    SignIn,
    CookieCapture,
    Fingerprints,
}

struct WorkerError {
    kind: WorkerKind,
    message: String,
}

enum WorkerEvent {
    ScanCompleted {
        scan_number: usize,
        report: Box<ExposureScanReport>,
    },
    AuthCompleted {
        kind: WorkerKind,
        profile_id: u64,
        result: Result<String, String>,
    },
    FingerprintsCompleted(Result<(), String>),
}

pub(super) struct App {
    pub(super) scan_form: ScanForm,
    pub(super) auth_store: SharedAuthStore,
    pub(super) show_auth_profiles: bool,
    pub(super) profile_editor_open: bool,
    pub(super) editing_auth_profile: Option<u64>,
    pub(super) profile_draft: ProfileInput,
    pub(super) auth_busy: Option<u64>,
    pub(super) auth_cancel: Option<CancellationToken>,
    pub(super) auth_notice: Option<String>,
    worker_event_tx: Sender<WorkerEvent>,
    worker_event_rx: Receiver<WorkerEvent>,
    worker_errors: Vec<WorkerError>,
    ctx: egui::Context,
    history: Vec<history::HistoryEntry>,
    latest_report: Option<ExposureScanReport>,
    active: Option<ActiveScan>,
    next_scan_number: usize,
    progress_rx: Receiver<ExposureScanProgress>,
    exposure_live: Option<ExposureLiveState>,
    exposure_detail_tab: ExposureDetailTab,
    diagnostic_view: DiagnosticViewState,
    pub(super) show_exposure_scan: bool,
    pub(super) scan_set_focus: bool,
    pub(super) ui_error: Option<String>,
}

impl App {
    fn start_scan(&mut self, request: ExposureScanRequest) -> Result<(), String> {
        if !matches!(
            fingerprints::initialization_status(),
            InitializationStatus::Ready { .. }
        ) {
            return Err("Web technology fingerprints are still initializing".to_owned());
        }
        if self.active.is_some() {
            return Err("Another scan is already running".to_owned());
        }
        request.validate()?;
        self.clear_worker_error(WorkerKind::Scan);
        self.latest_report = None;
        let scan_number = self.next_scan_number;
        self.next_scan_number += 1;
        let cancel = CancellationToken::new();
        self.active = Some(ActiveScan {
            scan_number,
            cancel: cancel.clone(),
        });
        self.exposure_detail_tab = ExposureDetailTab::Summary;
        self.diagnostic_view = DiagnosticViewState::default();
        self.exposure_live = Some(ExposureLiveState {
            message: "Starting public exposure scan...".to_owned(),
            resolving: true,
            completed: 0,
            total: 0,
            open_endpoints: Vec::new(),
            last_endpoint: None,
            phases: ExposureScanPhase::ALL.map(|phase| {
                let skipped = !matches!(
                    request.web_probe_level,
                    crate::WebProbeLevel::Active | crate::WebProbeLevel::StateChanging
                ) && phase == ExposureScanPhase::ActiveWebAssessment;
                let skipped = skipped
                    || (!request.security_operations
                        && matches!(
                            phase,
                            ExposureScanPhase::Crawl
                                | ExposureScanPhase::JavaScriptAnalysis
                                | ExposureScanPhase::TechnologyAnalysis
                        ))
                    || (phase == ExposureScanPhase::UdpScanning && !request.udp_scanning)
                    || (phase == ExposureScanPhase::ServiceAccess
                        && !request.service_access_checks)
                    || (phase == ExposureScanPhase::AssetDiscovery && !request.asset_discovery)
                    || (phase == ExposureScanPhase::DnsAssessment && !request.dns_assessment);
                ExposureLivePhase {
                    phase,
                    state: if skipped {
                        ExposureScanPhaseState::Skipped
                    } else {
                        ExposureScanPhaseState::Pending
                    },
                    fraction: if skipped { 1.0 } else { 0.0 },
                    text: if skipped { "Skipped" } else { "Pending" }.to_owned(),
                }
            }),
        });
        let (progress, progress_rx) = mpsc::channel();
        self.progress_rx = progress_rx;
        let auth_store = self.auth_store.clone();
        let failed_request = request.clone();
        let events = self.worker_event_tx.clone();
        let ctx = self.ctx.clone();
        crate::worker::spawn(
            "Exposure scan",
            move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| format!("Unable to create async runtime: {error}"))?;
                Ok(runtime.block_on(run_exposure_scan_with_auth_store(
                    request,
                    auth_store,
                    cancel,
                    Some(progress),
                )))
            },
            move |result| {
                let report = result
                    .unwrap_or_else(|error| failed_scan_report(failed_request.clone(), error));
                let _ = events.send(WorkerEvent::ScanCompleted {
                    scan_number,
                    report: Box::new(report),
                });
                ctx.request_repaint();
            },
        );
        self.show_exposure_scan = false;
        Ok(())
    }

    fn receive_worker_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.worker_event_rx.try_recv() {
            match event {
                WorkerEvent::ScanCompleted {
                    scan_number,
                    report,
                } => {
                    if self.active.as_ref().map(|scan| scan.scan_number) != Some(scan_number) {
                        continue;
                    }
                    if report.status == ExposureScanStatus::Failed {
                        if let Some(error) = &report.error {
                            self.set_worker_error(
                                WorkerKind::Scan,
                                format!("Scan {scan_number}: {error}"),
                            );
                        }
                    }
                    self.history.insert(
                        0,
                        history::HistoryEntry {
                            scan_number,
                            request: report.request.clone(),
                            error: report.error.clone(),
                        },
                    );
                    self.latest_report = Some(*report);
                    self.diagnostic_view = DiagnosticViewState::default();
                    self.active = None;
                    self.exposure_live = None;
                    self.spawn_fingerprint_initialization(true, ctx);
                }
                WorkerEvent::AuthCompleted {
                    kind,
                    profile_id,
                    result,
                } => {
                    if self.auth_busy != Some(profile_id) {
                        continue;
                    }
                    self.auth_busy = None;
                    self.auth_cancel = None;
                    self.auth_notice = None;
                    match result {
                        Ok(message) => self.auth_notice = Some(message),
                        Err(error) => self.set_worker_error(kind, error),
                    }
                }
                WorkerEvent::FingerprintsCompleted(result) => {
                    if let Err(error) = result {
                        self.set_worker_error(WorkerKind::Fingerprints, error);
                    }
                }
            }
        }
    }

    fn spawn_fingerprint_initialization(&self, force: bool, ctx: &egui::Context) {
        let ctx = ctx.clone();
        let events = self.worker_event_tx.clone();
        fingerprints::spawn_initialization(force, move |result| {
            let _ = events.send(WorkerEvent::FingerprintsCompleted(result));
            ctx.request_repaint();
        });
    }

    fn clear_worker_error(&mut self, kind: WorkerKind) {
        self.worker_errors.retain(|error| error.kind != kind);
    }

    fn set_worker_error(&mut self, kind: WorkerKind, message: String) {
        self.clear_worker_error(kind);
        self.worker_errors.push(WorkerError { kind, message });
    }

    fn spawn_auth_worker(
        &mut self,
        kind: WorkerKind,
        name: &'static str,
        profile_id: u64,
        work: impl FnOnce() -> Result<String, String> + Send + 'static,
    ) {
        self.clear_worker_error(kind);
        let events = self.worker_event_tx.clone();
        let ctx = self.ctx.clone();
        crate::worker::spawn(name, work, move |result| {
            let _ = events.send(WorkerEvent::AuthCompleted {
                kind,
                profile_id,
                result,
            });
            ctx.request_repaint();
        });
    }

    pub(super) fn start_interactive_sign_in(&mut self, profile_id: u64) {
        if self.auth_busy.is_some() {
            return;
        }
        self.auth_busy = Some(profile_id);
        let cancel = CancellationToken::new();
        self.auth_cancel = Some(cancel.clone());
        self.auth_notice = Some("Waiting for Azure sign-in in the system browser...".to_owned());
        let store = self.auth_store.clone();
        self.spawn_auth_worker(
            WorkerKind::SignIn,
            "Interactive sign-in",
            profile_id,
            move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| format!("Unable to create authentication runtime: {error}"))?;
                runtime.block_on(auth::sign_in_interactive(store, profile_id, cancel))
            },
        );
    }

    pub(super) fn start_browser_cookie_capture(&mut self, profile_id: u64) {
        if self.auth_busy.is_some() {
            return;
        }
        let target = self.scan_form.diagnostic.url.trim().to_owned();
        if target.is_empty() {
            self.ui_error = Some("Enter the target URL before capturing cookies".to_owned());
            return;
        }
        self.auth_busy = Some(profile_id);
        let cancel = CancellationToken::new();
        self.auth_cancel = Some(cancel.clone());
        self.auth_notice = Some(
            "Sign in through WebView2, then close the browser window to capture cookies".to_owned(),
        );
        let store = self.auth_store.clone();
        self.spawn_auth_worker(
            WorkerKind::CookieCapture,
            "Cookie capture",
            profile_id,
            move || auth::capture_browser_cookies(store, profile_id, &target, cancel),
        );
    }

    pub(super) fn new_profile_draft(&self) -> ProfileInput {
        let mut draft = ProfileInput::default();
        if let Ok(url) = url::Url::parse(&crate::diagnostics::normalize_url_input(
            &self.scan_form.diagnostic.url,
        )) {
            draft.login_url = url.origin().ascii_serialization();
            draft.host_scope = url.host_str().unwrap_or_default().to_owned();
        }
        draft
    }
}

impl Drop for App {
    fn drop(&mut self) {
        if let Some(active) = &self.active {
            active.cancel.cancel();
        }
        if let Some(cancel) = &self.auth_cancel {
            cancel.cancel();
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ({
            let (inlined_self,): (&mut App,) = (&mut *self,);

            while let Ok(update) = inlined_self.progress_rx.try_recv() {
                match update {
                    ExposureScanProgress::Resolving { target } => {
                        if let Some(live) = &mut inlined_self.exposure_live {
                            live.message = format!("Resolving {target}...");
                        }
                    }
                    ExposureScanProgress::Resolved {
                        public_addresses,
                        total_endpoints,
                    } => {
                        if let Some(live) = &mut inlined_self.exposure_live {
                            live.resolving = false;
                            live.total = total_endpoints;
                            live.message = format!(
                                "Scanning {} public address{}...",
                                public_addresses.len(),
                                if public_addresses.len() == 1 {
                                    ""
                                } else {
                                    "es"
                                }
                            );
                        }
                    }
                    ExposureScanProgress::EndpointCompleted {
                        completed,
                        total,
                        endpoint,
                    } => {
                        if let Some(live) = &mut inlined_self.exposure_live {
                            live.completed = completed;
                            live.total = total;
                            live.last_endpoint = Some(endpoint.clone());
                            if endpoint.state == PortState::Open {
                                live.open_endpoints.push(endpoint);
                            }
                            if completed == total {
                                live.message = "Running endpoint diagnostics...".to_owned();
                            }
                        }
                    }
                    ExposureScanProgress::UdpEndpointCompleted {
                        completed,
                        total,
                        endpoint,
                    } => {
                        if let Some(live) = &mut inlined_self.exposure_live {
                            live.message = format!(
                                "UDP {completed}/{total}: {}:{} — {}",
                                endpoint.ip, endpoint.port, endpoint.state
                            );
                        }
                    }
                    ExposureScanProgress::ServiceAccessCompleted {
                        completed,
                        total,
                        result,
                    } => {
                        if let Some(live) = &mut inlined_self.exposure_live {
                            live.message = format!(
                                "Service check {completed}/{total}: {}:{} — {}",
                                result.ip, result.port, result.status
                            );
                        }
                    }
                    ExposureScanProgress::AssetDiscovered {
                        completed,
                        total,
                        asset,
                    } => {
                        if let Some(live) = &mut inlined_self.exposure_live {
                            live.message = format!(
                                "CT asset {completed}/{total}: {} — {}",
                                asset.hostname, asset.state
                            );
                        }
                    }
                    ExposureScanProgress::DnsObservationCompleted {
                        completed,
                        total,
                        observation,
                    } => {
                        if let Some(live) = &mut inlined_self.exposure_live {
                            live.message = format!(
                                "DNS observation {completed}/{total}: {} — {}",
                                observation.check, observation.status
                            );
                        }
                    }
                    ExposureScanProgress::CrawlProgress {
                        origin,
                        queued,
                        completed,
                        current_url,
                    } => {
                        if let Some(live) = &mut inlined_self.exposure_live {
                            live.message =
                                format!("Crawling {origin}: {completed}/{queued} — {current_url}");
                        }
                    }
                    ExposureScanProgress::PhaseProgress {
                        phase,
                        state,
                        fraction,
                        text,
                    } => {
                        if let Some(live) = &mut inlined_self.exposure_live {
                            if state == ExposureScanPhaseState::Running {
                                live.message = text.clone();
                            }
                            if phase == ExposureScanPhase::PortScanning {
                                live.resolving = false;
                            }
                            if let Some(live_phase) = live
                                .phases
                                .iter_mut()
                                .find(|live_phase| live_phase.phase == phase)
                            {
                                live_phase.state = state;
                                live_phase.fraction = match state {
                                    ExposureScanPhaseState::Pending => 0.0,
                                    ExposureScanPhaseState::Running => fraction.clamp(0.0, 1.0),
                                    ExposureScanPhaseState::Complete
                                    | ExposureScanPhaseState::Skipped => 1.0,
                                };
                                live_phase.text = text;
                            }
                        }
                    }
                    ExposureScanProgress::Completed(_) => {}
                }
            }
        });
        self.receive_worker_events(ctx);
        let fingerprint_status = fingerprints::initialization_status();
        let fingerprints_ready = matches!(fingerprint_status, InitializationStatus::Ready { .. });
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(active) = &self.active {
                        if ui.button("Cancel Scan").clicked() {
                            active.cancel.cancel();
                        }
                        ui.spinner();
                    } else if ui.button("New Scan").clicked() {
                        self.show_exposure_scan = true;
                        self.scan_set_focus = true;
                    }
                });
            });
            if let Some(error) = &self.ui_error {
                ui.colored_label(egui::Color32::RED, error);
            }
            self.worker_errors.retain(|error| {
                let mut dismissed = false;
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(egui::Color32::RED, &error.message);
                    dismissed = ui.small_button("Dismiss").clicked();
                });
                !dismissed
            });
            if let Some(notice) = &self.auth_notice {
                ui.weak(notice);
            }
            match &fingerprint_status {
                InitializationStatus::NotStarted | InitializationStatus::Pending => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Loading web technology fingerprints...");
                    });
                }
                InitializationStatus::Ready {
                    warning: Some(warning),
                    using_curated_fallback,
                } => {
                    ui.colored_label(egui::Color32::YELLOW, warning);
                    let retry_label = if *using_curated_fallback {
                        "Retry fingerprint catalog"
                    } else {
                        "Retry fingerprint refresh"
                    };
                    if ui.button(retry_label).clicked() {
                        self.clear_worker_error(WorkerKind::Fingerprints);
                        self.spawn_fingerprint_initialization(true, ctx);
                    }
                }
                InitializationStatus::Ready { warning: None, .. } => {}
            }
        });

        let rescan = history::show(
            ctx,
            &self.history,
            self.active.is_some() || !fingerprints_ready,
        );

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(live) = &self.exposure_live {
                exposure_view::show_live(ui, live);
            } else if let Some(report) = &self.latest_report {
                ui.horizontal_wrapped(|ui| {
                    for tab in ExposureDetailTab::ALL {
                        ui.selectable_value(&mut self.exposure_detail_tab, tab, tab.label());
                    }
                });
                ui.separator();
                exposure_view::show_report(
                    ui,
                    report,
                    self.exposure_detail_tab,
                    &mut self.diagnostic_view,
                );
            } else {
                ui.centered_and_justified(|ui| {
                    ui.weak("Configure an advanced public exposure scan to begin.");
                });
            }
        });

        let start = exposure_view::show_dialog(ctx, self);
        if self.show_auth_profiles {
            auth_profiles::show(ctx, self);
        }
        if start && self.active.is_none() {
            let result = self
                .scan_form
                .to_request(&self.auth_store)
                .and_then(|request| self.start_scan(request));
            self.ui_error = result.err();
        }
        if let Some(request) = rescan {
            self.ui_error = self.start_scan(request).err();
        }
        if self.active.is_some() || self.auth_busy.is_some() || !fingerprints_ready {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }
}

fn failed_scan_report(request: ExposureScanRequest, error: String) -> ExposureScanReport {
    ExposureScanReport {
        request,
        hostname: String::new(),
        supplied_port: None,
        resolved_addresses: Vec::new(),
        ignored_addresses: Vec::new(),
        warnings: Vec::new(),
        endpoint_health: Vec::new(),
        endpoints: Vec::new(),
        udp_endpoints: Vec::new(),
        service_access: Vec::new(),
        discovered_assets: Vec::new(),
        dns_observations: Vec::new(),
        stream_observations: Vec::new(),
        findings: Vec::new(),
        security_checks: Vec::new(),
        crawl_observed_web_surfaces: Vec::new(),
        crawl_origins: Vec::new(),
        crawled_resources: Vec::new(),
        crawl_forms: Vec::new(),
        crawl_contacts: Vec::new(),
        crawl_external_indicators: Vec::new(),
        crawl_skipped_urls: Vec::new(),
        timings: ExposureScanTimings::default(),
        status: ExposureScanStatus::Failed,
        error: Some(error),
    }
}

pub fn run() -> Result<(), eframe::Error> {
    let mut arguments = std::env::args().skip(1);
    if arguments.next().as_deref() == Some("--cookie-browser") {
        let login_url = arguments.next();
        let target_url = arguments.next();
        let result = match (login_url, target_url, arguments.next()) {
            (Some(login_url), Some(target_url), None) => {
                auth::run_cookie_browser(login_url, target_url)
            }
            _ => Err("Usage: --cookie-browser <login-url> <target-url>".to_owned()),
        };
        let write_succeeded = auth::write_protocol_result(&result).is_ok();
        let success = result.is_ok() && write_succeeded;
        drop(result);
        if success {
            return Ok(());
        }
        std::process::exit(1);
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_maximized(true)
            .with_active(true),
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        "Nancy Web Debugger",
        options,
        Box::new(|_cc| {
            Ok(Box::new({
                let inlined_result: App = {
                    let (_, progress_rx) = mpsc::channel();
                    let (worker_event_tx, worker_event_rx) = mpsc::channel();
                    let app = App {
                        scan_form: ScanForm::default(),
                        auth_store: auth::AuthStore::shared(),
                        show_auth_profiles: false,
                        profile_editor_open: false,
                        editing_auth_profile: None,
                        profile_draft: ProfileInput::default(),
                        auth_busy: None,
                        auth_cancel: None,
                        auth_notice: None,
                        worker_event_tx,
                        worker_event_rx,
                        worker_errors: Vec::new(),
                        ctx: _cc.egui_ctx.clone(),
                        history: Vec::new(),
                        latest_report: None,
                        active: None,
                        next_scan_number: 1,
                        progress_rx,
                        exposure_live: None,
                        exposure_detail_tab: ExposureDetailTab::Summary,
                        diagnostic_view: DiagnosticViewState::default(),
                        show_exposure_scan: true,
                        scan_set_focus: true,
                        ui_error: None,
                    };
                    app.spawn_fingerprint_initialization(false, &_cc.egui_ctx);
                    app
                };
                inlined_result
            }))
        }),
    )
}
