mod body;
mod http;
mod network;
mod summary;
mod timeline;
mod tls;

pub(super) use body::show as show_body;
pub(super) use http::show as show_http;
pub(super) use network::show as show_network;
pub(super) use summary::show as show_summary;
pub(super) use tls::show as show_tls;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DetailTab {
    Summary,
    Network,
    Tls,
    Http,
    Body,
}

impl DetailTab {
    pub(super) const ALL: [Self; 5] = [
        Self::Summary,
        Self::Network,
        Self::Tls,
        Self::Http,
        Self::Body,
    ];

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Network => "DNS / Connections",
            Self::Tls => "TLS",
            Self::Http => "HTTP",
            Self::Body => "Body",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyView {
    Decoded,
    Hex,
}
