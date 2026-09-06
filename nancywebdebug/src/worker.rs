use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::thread;

pub(crate) fn spawn<T, F, C>(name: &'static str, work: F, complete: C)
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
    C: Fn(Result<T, String>) + Send + Sync + 'static,
{
    let complete = Arc::new(complete);
    let worker_complete = complete.clone();
    let result = thread::Builder::new()
        .name(name.to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(work))
                .unwrap_or_else(|payload| {
                    Err(format!("Worker panicked: {}", panic_message(&*payload)))
                })
                .map_err(|error| format!("{name}: {error}"));
            worker_complete(result);
        });
    if let Err(error) = result {
        complete(Err(format!(
            "{name}: Unable to start worker thread: {error}"
        )));
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<String>() {
        message
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        message
    } else {
        "Unknown panic payload"
    }
}
