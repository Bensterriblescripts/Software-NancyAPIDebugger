use crate::diagnostics::{DiagnosticTrace, TraceOutcome};
use eframe::egui;

pub(in crate::ui) fn display_url(trace: &DiagnosticTrace) -> &str {
    if trace.url.normalized.is_empty() {
        &trace.request.url
    } else {
        &trace.url.normalized
    }
}

pub(in crate::ui) fn outcome_label(ui: &mut egui::Ui, outcome: TraceOutcome) {
    let color = match outcome {
        TraceOutcome::Running => egui::Color32::LIGHT_BLUE,
        TraceOutcome::Success => egui::Color32::LIGHT_GREEN,
        TraceOutcome::Cancelled => egui::Color32::YELLOW,
        TraceOutcome::Failed | TraceOutcome::TimedOut => egui::Color32::LIGHT_RED,
    };
    ui.colored_label(color, outcome.to_string());
}

pub(in crate::ui) fn normalized_url(input: &str) -> Result<url::Url, url::ParseError> {
    url::Url::parse(&crate::diagnostics::normalize_url_input(input))
}
