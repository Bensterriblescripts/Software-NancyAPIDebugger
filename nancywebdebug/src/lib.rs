pub mod auth;
mod cli;
pub mod diagnostics;
mod request;
mod ui;

pub use request::run_diagnostic_session;

pub fn run_gui() -> Result<(), eframe::Error> {
    ui::run()
}

pub fn run_cli() -> std::process::ExitCode {
    cli::run()
}
