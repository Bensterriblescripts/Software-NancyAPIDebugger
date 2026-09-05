mod body;
mod http;
mod network;
mod summary;
mod tls;

pub(super) use body::show as show_body;
pub(super) use http::show as show_http;
pub(super) use network::show as show_network;
pub(super) use summary::show as show_summary;
pub(super) use tls::show as show_tls;

labeled_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum DetailTab[5] {
        Summary => "Summary",
        Network => "DNS / Connections",
        Tls => "TLS",
        Http => "HTTP",
        Body => "Body",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyView {
    Decoded,
    Hex,
}
