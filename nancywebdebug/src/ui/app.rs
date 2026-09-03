use crate::auth::{self, ProfileInput, SharedAuthStore};
use crate::diagnostics::*;
use crate::request;
use eframe::egui;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use super::details::{
    BodyView, DetailTab, show_body, show_http, show_network, show_summary, show_tls,
};
use super::request_form::{self, TimeoutInputs};
use super::widgets::normalized_url;
use super::{auth_profiles, history};

struct ActiveRequest {
    index: usize,
    request_number: usize,
    cancel: CancellationToken,
    redirects_followed: usize,
    visited_urls: HashSet<String>,
}

const MAX_REDIRECTS: usize = 10;

struct AuthEvent {
    profile_id: u64,
    result: Result<String, String>,
}

pub(super) struct App {
    pub(super) show_new_request: bool,
    pub(super) set_focus: bool,
    pub(super) request_method: String,
    pub(super) request_url: String,
    pub(super) request_headers: String,
    pub(super) request_body: String,
    pub(super) request_protocol: ProtocolPreference,
    pub(super) request_follow_redirects: bool,
    pub(super) selected_auth_profile: Option<u64>,
    pub(super) timeout_inputs: TimeoutInputs,
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
    selected_index: Option<usize>,
    active: Option<ActiveRequest>,
    next_index: usize,
    next_request_number: usize,
    progress_tx: Sender<DiagnosticProgress>,
    progress_rx: Receiver<DiagnosticProgress>,
    detail_tab: DetailTab,
    body_view: BodyView,
    pub(super) ui_error: Option<String>,
}

impl App {
    fn new() -> Self {
        let (progress_tx, progress_rx) = mpsc::channel();
        let (auth_event_tx, auth_event_rx) = mpsc::channel();
        Self {
            show_new_request: false,
            set_focus: false,
            request_method: "GET".to_owned(),
            request_url: String::new(),
            request_headers: String::new(),
            request_body: String::new(),
            request_protocol: ProtocolPreference::Auto,
            request_follow_redirects: false,
            selected_auth_profile: None,
            timeout_inputs: TimeoutInputs::default(),
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
            selected_index: None,
            active: None,
            next_index: 1,
            next_request_number: 1,
            progress_tx,
            progress_rx,
            detail_tab: DetailTab::Summary,
            body_view: BodyView::Decoded,
            ui_error: None,
        }
    }

    fn start_request(&mut self, diagnostic_request: DiagnosticRequest) -> Result<(), String> {
        if self.active.is_some() {
            return Err("A diagnostic request is already running".to_owned());
        }
        if diagnostic_request.url.trim().is_empty() {
            return Err("URL is empty".to_owned());
        }
        let index = self.next_index;
        self.next_index += 1;
        let request_number = self.next_request_number;
        self.next_request_number += 1;
        let cancel = CancellationToken::new();
        self.active = Some(ActiveRequest {
            index,
            request_number,
            cancel: cancel.clone(),
            redirects_followed: 0,
            visited_urls: HashSet::new(),
        });
        self.selected_index = Some(index);
        self.detail_tab = DetailTab::Summary;
        self.spawn_request(index, diagnostic_request, cancel);
        Ok(())
    }

    fn start_form_request(&mut self) -> Result<(), String> {
        let selected_auth = match self.selected_auth_profile {
            Some(id) => Some(
                self.auth_store
                    .lock()
                    .map_err(|_| "Authentication profile store is unavailable".to_owned())?
                    .metadata(id)
                    .ok_or_else(|| "Selected authentication profile no longer exists".to_owned())?,
            ),
            None => None,
        };
        let diagnostic_request = DiagnosticRequest {
            method: self.request_method.clone(),
            url: self.request_url.trim().to_owned(),
            headers: self.request_headers.clone(),
            body: Arc::from(self.request_body.as_bytes()),
            protocol: self.request_protocol,
            timeouts: self.timeout_inputs.to_timeouts(),
            auth: selected_auth,
            follow_redirects: self.request_follow_redirects,
        };
        self.start_request(diagnostic_request)
    }

    fn process_progress(&mut self) {
        while let Ok(update) = self.progress_rx.try_recv() {
            let (mut trace, completed) = match update {
                DiagnosticProgress::Running(trace) => (trace, false),
                DiagnosticProgress::Finished(trace) => (trace, true),
            };
            let index = trace.index;
            self.next_index = self.next_index.max(index + 1);
            let request_number = self
                .active
                .as_ref()
                .filter(|active| active.index == index)
                .map(|active| active.request_number)
                .or_else(|| {
                    self.history
                        .iter()
                        .find(|item| item.trace.index == index)
                        .map(|item| item.request_number)
                })
                .unwrap_or(index);
            let mut redirect_request = None;
            if completed
                && self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.index == index)
            {
                redirect_request = self.prepare_redirect(&mut trace);
            }
            if let Some(existing) = self
                .history
                .iter_mut()
                .find(|item| item.trace.index == trace.index)
            {
                existing.trace = trace;
            } else {
                self.history.insert(
                    0,
                    history::HistoryEntry {
                        request_number,
                        trace,
                    },
                );
            }
            if completed
                && self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.index == index)
            {
                if let Some(request) = redirect_request {
                    let next_index = self.next_index;
                    self.next_index += 1;
                    if let Some(active) = &mut self.active {
                        active.index = next_index;
                        active.redirects_followed += 1;
                        let cancel = active.cancel.clone();
                        self.selected_index = Some(next_index);
                        self.spawn_request(next_index, request, cancel);
                    }
                } else {
                    self.active = None;
                    self.selected_index = Some(index);
                }
            }
        }
    }

    fn prepare_redirect(&mut self, trace: &mut DiagnosticTrace) -> Option<DiagnosticRequest> {
        let active = self.active.as_mut()?;
        if !trace.url.normalized.is_empty() {
            active.visited_urls.insert(trace.url.normalized.clone());
        }
        if !trace.request.follow_redirects {
            return None;
        }
        let target = trace.redirect_target.as_ref()?.clone();
        if trace.outcome != TraceOutcome::Success {
            trace.redirect_stop_reason = Some(
                "Redirect not followed because the request did not complete successfully"
                    .to_owned(),
            );
            return None;
        }
        if !matches!(trace.http.status, Some(301 | 302 | 303 | 307 | 308)) {
            trace.redirect_stop_reason = Some(format!(
                "HTTP status {} is not followed automatically",
                trace.http.status.unwrap_or_default()
            ));
            return None;
        }
        if active.redirects_followed >= MAX_REDIRECTS {
            trace.redirect_stop_reason = Some(format!("Redirect limit of {MAX_REDIRECTS} reached"));
            return None;
        }
        if active.visited_urls.contains(&target) {
            trace.redirect_stop_reason = Some("Redirect loop detected".to_owned());
            return None;
        }
        trace.redirect_followed = true;
        trace.redirect_stop_reason = None;
        Some(redirect_request(trace, target))
    }

    fn spawn_request(
        &self,
        index: usize,
        diagnostic_request: DiagnosticRequest,
        cancel: CancellationToken,
    ) {
        let progress = self.progress_tx.clone();
        let auth_store = self.auth_store.clone();
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            match runtime {
                Ok(runtime) => runtime.block_on(request::run_diagnostic(
                    index,
                    diagnostic_request,
                    auth_store,
                    cancel,
                    progress,
                )),
                Err(error) => {
                    let mut trace = DiagnosticTrace::new(index, diagnostic_request);
                    trace.outcome = TraceOutcome::Failed;
                    trace.complete = true;
                    if let Some(stage) = trace.stages.first_mut() {
                        stage.status = StageStatus::Failed;
                        stage.detail = format!("Unable to create async runtime: {error}");
                    }
                    trace.error = Some(TraceError {
                        stage: StageKind::Url,
                        message: format!("Unable to create async runtime: {error}"),
                    });
                    let _ = progress.send(DiagnosticProgress::Finished(trace));
                }
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
        let target = self.request_url.trim().to_owned();
        if target.is_empty() {
            self.ui_error = Some("Enter the request URL before capturing cookies".to_owned());
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
        if let Ok(url) = normalized_url(&self.request_url) {
            draft.login_url = url.origin().ascii_serialization();
            draft.host_scope = url.host_str().unwrap_or_default().to_owned();
        }
        draft
    }
}

fn redirect_request(trace: &DiagnosticTrace, target: String) -> DiagnosticRequest {
    let mut request = trace.request.clone();
    request.url = target.clone();
    let mut removed_headers = vec!["host"];
    let switch_to_get = matches!(trace.http.status, Some(303))
        && !trace.request.method.eq_ignore_ascii_case("HEAD")
        || matches!(trace.http.status, Some(301 | 302))
            && trace.request.method.eq_ignore_ascii_case("POST");
    if switch_to_get {
        request.method = "GET".to_owned();
        request.body = Arc::from([]);
        removed_headers.extend([
            "content-encoding",
            "content-length",
            "content-type",
            "transfer-encoding",
        ]);
    }
    if redirect_crosses_origin(&trace.url.normalized, &target) {
        removed_headers.extend(["authorization", "cookie", "proxy-authorization"]);
        request.auth = None;
    }
    request.headers = remove_headers(&request.headers, &removed_headers);
    request
}

fn redirect_crosses_origin(source: &str, target: &str) -> bool {
    match (url::Url::parse(source), url::Url::parse(target)) {
        (Ok(source), Ok(target)) => source.origin() != target.origin(),
        _ => true,
    }
}

fn remove_headers(headers: &str, names: &[&str]) -> String {
    headers
        .lines()
        .filter(|line| {
            line.split_once(':').is_none_or(|(name, _)| {
                !names
                    .iter()
                    .any(|removed| name.trim().eq_ignore_ascii_case(removed))
            })
        })
        .collect::<Vec<_>>()
        .join("\n")
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
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Nancy API Debugger");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(active) = &self.active {
                        if ui.button("Cancel Request").clicked() {
                            active.cancel.cancel();
                        }
                        ui.spinner();
                    } else if ui.button("Create Request").clicked() {
                        self.show_new_request = true;
                        self.set_focus = true;
                    }
                });
            });
            if let Some(error) = &self.ui_error {
                ui.colored_label(egui::Color32::RED, error);
            }
            if let Some(notice) = &self.auth_notice {
                ui.weak(notice);
            }
        });

        let resend = history::show(
            ctx,
            &self.history,
            &mut self.selected_index,
            self.active.is_some(),
        );

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(index) = self.selected_index {
                ui.horizontal_wrapped(|ui| {
                    for tab in DetailTab::ALL {
                        ui.selectable_value(&mut self.detail_tab, tab, tab.label());
                    }
                });
                ui.separator();
                if let Some(trace) = self
                    .history
                    .iter()
                    .find(|item| item.trace.index == index)
                    .map(|item| &item.trace)
                {
                    match self.detail_tab {
                        DetailTab::Summary => show_summary(ui, trace),
                        DetailTab::Network => show_network(ui, trace),
                        DetailTab::Tls => show_tls(ui, trace),
                        DetailTab::Http => show_http(ui, trace),
                        DetailTab::Body => show_body(ui, trace, &mut self.body_view),
                    }
                } else {
                    ui.spinner();
                    ui.label("Waiting for the first trace stage...");
                }
            } else {
                ui.centered_and_justified(|ui| {
                    ui.weak("Create a request to begin diagnostics.");
                });
            }
        });

        let send_form = request_form::show(ctx, self);

        if self.show_auth_profiles {
            auth_profiles::show(ctx, self);
        }

        if send_form && self.active.is_none() {
            match self.start_form_request() {
                Ok(()) => {
                    self.show_new_request = false;
                    self.ui_error = None;
                }
                Err(error) => self.ui_error = Some(error),
            }
        }
        if let Some(request) = resend {
            if let Err(error) = self.start_request(request) {
                self.ui_error = Some(error);
            } else {
                self.ui_error = None;
            }
        }
        if self.active.is_some() || self.auth_busy.is_some() {
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
            .with_active(true),
        ..Default::default()
    };
    eframe::run_native(
        "Nancy Web Debugger",
        options,
        Box::new(|_cc| Ok(Box::new(App::new()))),
    )
}
