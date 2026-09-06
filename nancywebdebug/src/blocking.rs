use std::fmt;
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub(crate) enum Error {
    Cancelled,
    Worker(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("Processing cancelled"),
            Self::Worker(message) => write!(formatter, "Processing worker failed: {message}"),
        }
    }
}

pub(crate) async fn run<T, F>(cancel: &CancellationToken, work: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce(&CancellationToken) -> T + Send + 'static,
{
    static GATE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let gate = GATE.get_or_init(|| {
        let parallelism = std::thread::available_parallelism().map_or(1, usize::from);
        Arc::new(Semaphore::new(parallelism.saturating_sub(1).max(1)))
    });
    let permit = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(Error::Cancelled),
        permit = gate.clone().acquire_owned() => {
            permit.map_err(|error| Error::Worker(error.to_string()))?
        }
    };
    let worker_cancel = cancel.child_token();
    let _cancel_on_drop = worker_cancel.clone().drop_guard();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if worker_cancel.is_cancelled() {
            return None;
        }
        let result = work(&worker_cancel);
        (!worker_cancel.is_cancelled()).then_some(result)
    });
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(Error::Cancelled),
        result = task => {
            let result = result.map_err(|error| Error::Worker(error.to_string()))?;
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            result.ok_or(Error::Cancelled)
        }
    }
}
