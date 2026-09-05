mod body;
mod dns;
mod fingerprint;
mod http;
mod http3;
mod runner;
mod stages;
mod tls;
mod transport;

pub(crate) use dns::{resolve_host, resolve_host_exhaustive};
pub(crate) use tls::{
    CertificateCapture, make_exposure_tls_config, parse_certificate, tls_trace_from_capture,
    tls_trace_from_stream,
};
pub(crate) use transport::{TcpCandidate, connect_tcp_endpoint};

pub use runner::run_diagnostic_session;
pub(crate) use runner::run_diagnostic_session_for_exposure;
