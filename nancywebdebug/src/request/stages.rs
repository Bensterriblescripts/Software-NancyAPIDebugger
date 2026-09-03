use crate::diagnostics::{
    DiagnosticProgress, DiagnosticTrace, StageKind, StageStatus, TraceError, TraceOutcome,
};
use std::future::Future;
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use super::body::decode_body;
use super::http::apply_redirect_report;

#[derive(Debug)]
pub(super) enum WaitError {
    Cancelled,
    TimedOut,
}

pub(super) fn begin_stage(
    trace: &mut DiagnosticTrace,
    kind: StageKind,
    progress: &Sender<DiagnosticProgress>,
) -> Instant {
    if let Some(stage) = trace
        .stages
        .iter_mut()
        .find(|stage| stage.kind == kind && stage.status == StageStatus::Pending)
    {
        stage.status = StageStatus::Running;
        stage.duration_ms = None;
        stage.detail.clear();
    }
    publish(trace, progress);
    Instant::now()
}

pub(super) fn finish_stage(
    trace: &mut DiagnosticTrace,
    kind: StageKind,
    status: StageStatus,
    started: Instant,
    detail: String,
    progress: &Sender<DiagnosticProgress>,
) {
    set_stage(trace, kind, status, started, detail);
    publish(trace, progress);
}

pub(super) fn set_stage(
    trace: &mut DiagnosticTrace,
    kind: StageKind,
    status: StageStatus,
    started: Instant,
    detail: String,
) {
    if let Some(stage) = trace
        .stages
        .iter_mut()
        .find(|stage| stage.kind == kind && stage.status == StageStatus::Running)
    {
        stage.status = status;
        stage.duration_ms = Some(elapsed_ms(started));
        stage.detail = detail;
    }
}

pub(super) fn fail_trace(
    mut trace: DiagnosticTrace,
    stage: StageKind,
    status: StageStatus,
    started: Instant,
    message: String,
    _progress: &Sender<DiagnosticProgress>,
) -> DiagnosticTrace {
    if matches!(stage, StageKind::FirstByte | StageKind::Body) && !trace.body.raw.is_empty() {
        decode_body(&mut trace);
    }
    let detail = if stage == StageKind::Body {
        format!(
            "{message}; raw: {}; decoded: {}",
            trace.body.raw_capture_status(),
            trace.body.decoded_capture_status()
        )
    } else {
        message.clone()
    };
    set_stage(&mut trace, stage, status, started, detail);
    trace.outcome = match status {
        StageStatus::TimedOut => TraceOutcome::TimedOut,
        StageStatus::Cancelled => TraceOutcome::Cancelled,
        _ => TraceOutcome::Failed,
    };
    trace.complete = true;
    trace.error = Some(TraceError { stage, message });
    apply_redirect_report(&mut trace);
    trace
}

pub(super) fn publish(trace: &DiagnosticTrace, progress: &Sender<DiagnosticProgress>) {
    let _ = progress.send(DiagnosticProgress::Running(trace.clone()));
}

pub(super) async fn wait_for<T, F>(
    duration: Duration,
    cancel: &CancellationToken,
    future: F,
) -> Result<T, WaitError>
where
    F: Future<Output = T>,
{
    tokio::select! {
        _ = cancel.cancelled() => Err(WaitError::Cancelled),
        result = tokio::time::timeout(duration, future) => {
            result.map_err(|_| WaitError::TimedOut)
        }
    }
}

pub(super) fn address_family(ip: IpAddr) -> String {
    if ip.is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()
}

pub(super) fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}
