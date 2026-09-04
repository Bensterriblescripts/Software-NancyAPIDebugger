pub mod auth;
pub mod diagnostics;
mod exposure;
mod persistence;
mod request;
mod ui;
mod web_server;

pub use exposure::*;
pub use request::run_diagnostic_session;

pub fn run_gui() -> Result<(), eframe::Error> {
    ui::run()
}
