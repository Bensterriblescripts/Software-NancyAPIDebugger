macro_rules! labeled_enum {
    ($(#[$meta:meta])* $vis:vis enum $name:ident[$count:literal] { $($(#[$variant_meta:meta])* $variant:ident => $label:literal),+ $(,)? }) => {
        $(#[$meta])*
        $vis enum $name { $($(#[$variant_meta])* $variant),+ }
        impl $name {
            $vis const ALL: [Self; $count] = [$(Self::$variant),+];
            $vis const fn label(self) -> &'static str {
                match self { $(Self::$variant => $label),+ }
            }
        }
    };
}

macro_rules! display_enum {
    ($(#[$meta:meta])* pub enum $name:ident { $($(#[$variant_meta:meta])* $variant:ident => $label:literal),+ $(,)? }) => {
        $(#[$meta])*
        pub enum $name { $($(#[$variant_meta])* $variant),+ }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(match self { $(Self::$variant => $label),+ })
            }
        }
    };
}

pub mod auth;
pub mod diagnostics;
mod exposure;
mod network;
mod persistence;
mod request;
mod ui;
mod web_server;

pub use exposure::*;
pub use request::run_diagnostic_session;

pub(crate) fn matches_ascii(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

pub fn run_gui() -> Result<(), eframe::Error> {
    ui::run()
}
