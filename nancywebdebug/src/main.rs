mod auth;
mod diagnostics;
mod request;
mod ui;

fn main() -> Result<(), eframe::Error> {
    ui::run()
}
