use crate::auth::{self, ProfileInput, SharedAuthStore};
use crate::exposure::fingerprints::{self, InitializationStatus};
use crate::{
    EndpointScan, ExposureScanProgress, ExposureScanReport, ExposureScanRequest,
    ExposureScanStatus, ExposureScanTimings, PortState, run_exposure_scan_with_auth_store,
};
use eframe::egui;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use super::exposure_view::{self, DiagnosticViewState, ExposureDetailTab, ScanForm};
use super::widgets::normalized_url;
use super::{auth_profiles, history};

struct ActiveScan {
    scan_number: usize,
    cancel: CancellationToken,
}

pub(super) struct ExposureLiveState {
    pub(super) message: String,
    pub(super) completed: usize,
    pub(super) total: usize,
    pub(super) open_endpoints: Vec<EndpointScan>,
    pub(super) last_endpoint: Option<EndpointScan>,
}

struct AuthEvent {
    profile_id: u64,
    result: Result<String, String>,
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
    auth_event_tx: Sender<AuthEvent>,
    auth_event_rx: Receiver<AuthEvent>,
    history: Vec<history::HistoryEntry>,
    selected_scan: Option<usize>,
    active: Option<ActiveScan>,
    next_scan_number: usize,
    progress_tx: Sender<ExposureScanProgress>,
    progress_rx: Receiver<ExposureScanProgress>,
    exposure_live: Option<ExposureLiveState>,
    exposure_detail_tab: ExposureDetailTab,
    diagnostic_view: DiagnosticViewState,
    pub(super) show_exposure_scan: bool,
    pub(super) scan_set_focus: bool,
    pub(super) ui_error: Option<String>,
}

impl App {
    fn new() -> Self {
        let (progress_tx, progress_rx) = mpsc::channel();
        let (auth_event_tx, auth_event_rx) = mpsc::channel();
        let app = Self {
            scan_form: ScanForm::default(),
            auth_store: auth::AuthStore::shared(),
            show_auth_profiles: false,
            profile_editor_open: false,
            editing_auth_profile: None,
            profile_draft: ProfileInput::default(),
            auth_busy: None,
            auth_cancel: None,
            auth_notice: None,
            auth_event_tx,
            auth_event_rx,
            history: Vec::new(),
            selected_scan: None,
            active: None,
            next_scan_number: 1,
            progress_tx,
            progress_rx,
            exposure_live: None,
            exposure_detail_tab: ExposureDetailTab::Diagnostics,
            diagnostic_view: DiagnosticViewState::default(),
            show_exposure_scan: true,
            scan_set_focus: true,
            ui_error: None,
        };
        app.spawn_fingerprint_initialization(false);
        app
    }

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
        let scan_number = self.next_scan_number;
        self.next_scan_number += 1;
        let cancel = CancellationToken::new();
        self.active = Some(ActiveScan {
            scan_number,
            cancel: cancel.clone(),
        });
        self.selected_scan = Some(scan_number);
        self.exposure_detail_tab = ExposureDetailTab::Diagnostics;
        self.diagnostic_view = DiagnosticViewState::default();
        self.exposure_live = Some(ExposureLiveState {
            message: "Starting public exposure scan...".to_owned(),
            completed: 0,
            total: 0,
            open_endpoints: Vec::new(),
            last_endpoint: None,
        });
        self.spawn_scan(request, cancel);
        Ok(())
    }

    fn start_scan_form(&mut self) -> Result<(), String> {
        let request = self.scan_form.to_request(&self.auth_store)?;
        self.start_scan(request)
    }

    fn process_progress(&mut self) {
        while let Ok(update) = self.progress_rx.try_recv() {
            match update {
                ExposureScanProgress::Resolving { target } => {
                    if let Some(live) = &mut self.exposure_live {
                        live.message = format!("Resolving {target}...");
                    }
                }
                ExposureScanProgress::Resolved {
                    public_addresses,
                    total_endpoints,
                } => {
                    if let Some(live) = &mut self.exposure_live {
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
                    if let Some(live) = &mut self.exposure_live {
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
                ExposureScanProgress::CrawlProgress {
                    origin,
                    queued,
                    completed,
                    current_url,
                } => {
                    if let Some(live) = &mut self.exposure_live {
                        live.message =
                            format!("Crawling {origin}: {completed}/{queued} — {current_url}");
                    }
                }
                ExposureScanProgress::Completed(report) => {
                    let scan_number = self
                        .active
                        .as_ref()
                        .map(|active| active.scan_number)
                        .unwrap_or_else(|| self.next_scan_number.saturating_sub(1));
                    self.history.insert(
                        0,
                        history::HistoryEntry {
                            scan_number,
                            report,
                        },
                    );
                    self.selected_scan = Some(scan_number);
                    self.diagnostic_view = DiagnosticViewState::default();
                    self.active = None;
                    self.exposure_live = None;
                }
            }
        }
    }

    fn spawn_scan(&self, request: ExposureScanRequest, cancel: CancellationToken) {
        let progress = self.progress_tx.clone();
        let auth_store = self.auth_store.clone();
        thread::spawn(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => {
                    runtime.block_on(run_exposure_scan_with_auth_store(
                        request,
                        auth_store,
                        cancel,
                        Some(progress),
                    ));
                }
                Err(error) => {
                    let report = ExposureScanReport {
                        request,
                        hostname: String::new(),
                        supplied_port: None,
                        resolved_addresses: Vec::new(),
                        ignored_addresses: Vec::new(),
                        warnings: Vec::new(),
                        endpoints: Vec::new(),
                        findings: Vec::new(),
                        crawl_observed_web_surfaces: Vec::new(),
                        crawl_origins: Vec::new(),
                        crawled_resources: Vec::new(),
                        crawl_forms: Vec::new(),
                        crawl_external_indicators: Vec::new(),
                        crawl_skipped_urls: Vec::new(),
                        timings: ExposureScanTimings::default(),
                        status: ExposureScanStatus::Failed,
                        error: Some(format!("Unable to create async runtime: {error}")),
                    };
                    let _ = progress.send(ExposureScanProgress::Completed(report));
                }
            }
        });
    }

    fn spawn_fingerprint_initialization(&self, force: bool) {
        if !fingerprints::start_initialization(force) {
            return;
        }
        thread::spawn(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(fingerprints::run_started_initialization()),
                Err(error) => fingerprints::complete_runtime_failure(format!(
                    "unable to create fingerprint initialization runtime: {error}"
                )),
            }
        });
    }

    fn process_auth_events(&mut self) {
        while let Ok(event) = self.auth_event_rx.try_recv() {
            if self.auth_busy == Some(event.profile_id) {
                self.auth_busy = None;
                self.auth_cancel = None;
            }
            match event.result {
                Ok(message) => {
                    self.auth_notice = Some(message);
                    self.ui_error = None;
                }
                Err(error) => self.ui_error = Some(error),
            }
        }
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
        let events = self.auth_event_tx.clone();
        thread::spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("Unable to create authentication runtime: {error}"))
                .and_then(|runtime| {
                    runtime.block_on(auth::sign_in_interactive(store, profile_id, cancel))
                });
            let _ = events.send(AuthEvent { profile_id, result });
        });
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
        let events = self.auth_event_tx.clone();
        thread::spawn(move || {
            let result = auth::capture_browser_cookies(store, profile_id, &target, cancel);
            let _ = events.send(AuthEvent { profile_id, result });
        });
    }

    pub(super) fn new_profile_draft(&self) -> ProfileInput {
        let mut draft = ProfileInput::default();
        if let Ok(url) = normalized_url(&self.scan_form.diagnostic.url) {
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
        self.process_progress();
        self.process_auth_events();
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
                    if *using_curated_fallback && ui.button("Retry fingerprint catalog").clicked() {
                        self.spawn_fingerprint_initialization(true);
                    }
                }
                InitializationStatus::Ready { warning: None, .. } => {}
            }
        });

        let previous_scan = self.selected_scan;
        let rescan = history::show(
            ctx,
            &self.history,
            &mut self.selected_scan,
            self.active.is_some() || !fingerprints_ready,
        );
        if self.selected_scan != previous_scan {
            self.diagnostic_view = DiagnosticViewState::default();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(scan_number) = self.selected_scan {
                if let Some(report) = self
                    .history
                    .iter()
                    .find(|entry| entry.scan_number == scan_number)
                    .map(|entry| &entry.report)
                {
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
                } else if let Some(live) = &self.exposure_live {
                    exposure_view::show_live(ui, live);
                } else {
                    ui.spinner();
                }
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
            match self.start_scan_form() {
                Ok(()) => {
                    self.show_exposure_scan = false;
                    self.ui_error = None;
                }
                Err(error) => self.ui_error = Some(error),
            }
        }
        if let Some(request) = rescan {
            if let Err(error) = self.start_scan(request) {
                self.ui_error = Some(error);
            } else {
                self.ui_error = None;
            }
        }
        if self.active.is_some() || self.auth_busy.is_some() || !fingerprints_ready {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
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
            .with_inner_size([1700.0, 900.0])
            .with_maximized(true)
            .with_active(true),
        ..Default::default()
    };
    eframe::run_native(
        "Nancy Web Debugger",
        options,
        Box::new(|_cc| Ok(Box::new(App::new()))),
    )
}
