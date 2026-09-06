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
mod blocking;
pub mod diagnostics;
mod exposure;
mod network;
mod dns_lookup;
mod persistence;
mod product_catalog;
mod request;
mod scan_limits;
mod ui;
mod web_server;
mod worker;

pub use exposure::*;
pub use request::run_diagnostic_session;

pub use ui::run as run_gui;
