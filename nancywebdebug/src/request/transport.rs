use crate::auth::LoadedClientCertificate;
use crate::diagnostics::{ConnectionAttempt, ConnectionOutcome, ProtocolPreference};
use crate::exposure::endpoint_health;
use crate::network::ConnectionRateLimiter;
use futures_util::future::join_all;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use super::stages::{WaitError, wait_for};
use super::tls::{CertificateCapture, make_tls_config};

pub(crate) struct TcpCandidate {
    pub(crate) attempt: ConnectionAttempt,
    pub(crate) attempted: bool,
    pub(crate) stream: Option<TcpStream>,
}

pub(super) struct QuicCandidate {
    pub(super) attempt: ConnectionAttempt,
    pub(super) endpoint: Option<quinn::Endpoint>,
    pub(super) connection: Option<quinn::Connection>,
    pub(super) capture: Arc<Mutex<CertificateCapture>>,
}

pub(super) enum IoStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for IoStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for IoStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(super) struct RecordingIo {
    pub(super) inner: IoStream,
    pub(super) writes: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for RecordingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RecordingIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                this.writes
                    .lock()
                    .unwrap()
                    .extend_from_slice(&buf[..written]);
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub(super) async fn connect_tcp_all(
    addresses: &[IpAddr],
    port: u16,
    timeout: Duration,
    cancel: &CancellationToken,
    limiter: Option<&ConnectionRateLimiter>,
) -> Vec<TcpCandidate> {
    let futures = addresses.iter().copied().map(|ip| {
        let cancel = cancel.clone();
        async move {
            let remote = SocketAddr::new(ip, port);
            let started = Instant::now();
            let health_attempt = match endpoint_health::begin(ip, port, &cancel).await {
                Ok(attempt) => attempt,
                Err(error) => {
                    return TcpCandidate {
                        attempted: false,
                        attempt: ConnectionAttempt {
                            remote,
                            local: None,
                            family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                            duration_ms: 0.0,
                            outcome: if cancel.is_cancelled() {
                                ConnectionOutcome::Cancelled
                            } else {
                                ConnectionOutcome::Failed
                            },
                            error: Some(error),
                            os_error: None,
                            selected: false,
                        },
                        stream: None,
                    };
                }
            };
            if let Some(limiter) = limiter
                && limiter.wait(&cancel).await.is_err()
            {
                return TcpCandidate {
                    attempted: false,
                    attempt: ConnectionAttempt {
                        remote,
                        local: None,
                        family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                        duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                        outcome: ConnectionOutcome::Cancelled,
                        error: Some("Scan cancelled".to_owned()),
                        os_error: None,
                        selected: false,
                    },
                    stream: None,
                };
            }
            let socket = if ip.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            };
            let socket = match socket {
                Ok(socket) => socket,
                Err(error) => {
                    return TcpCandidate {
                        attempted: false,
                        attempt: ConnectionAttempt {
                            remote,
                            local: None,
                            family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                            duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                            outcome: ConnectionOutcome::Failed,
                            error: Some(error.to_string()),
                            os_error: error.raw_os_error(),
                            selected: false,
                        },
                        stream: None,
                    };
                }
            };
            let bind = if ip.is_ipv4() {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            };
            if let Err(error) = socket.bind(bind) {
                return TcpCandidate {
                    attempted: false,
                    attempt: ConnectionAttempt {
                        remote,
                        local: None,
                        family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                        duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                        outcome: ConnectionOutcome::Failed,
                        error: Some(error.to_string()),
                        os_error: error.raw_os_error(),
                        selected: false,
                    },
                    stream: None,
                };
            }
            let local = socket.local_addr().ok();
            let mut attempted = false;
            let result = if cancel.is_cancelled() {
                Err(WaitError::Cancelled)
            } else {
                wait_for(timeout, &cancel, async {
                    attempted = true;
                    socket.connect(remote).await
                })
                .await
            };
            let candidate = match result {
                Ok(Ok(stream)) => TcpCandidate {
                    attempted,
                    attempt: ConnectionAttempt {
                        remote,
                        local: stream.local_addr().ok(),
                        family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                        duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                        outcome: ConnectionOutcome::Succeeded,
                        error: None,
                        os_error: None,
                        selected: false,
                    },
                    stream: Some(stream),
                },
                Ok(Err(error)) => TcpCandidate {
                    attempted,
                    attempt: ConnectionAttempt {
                        remote,
                        local,
                        family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                        duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                        outcome: ConnectionOutcome::Failed,
                        error: Some(error.to_string()),
                        os_error: error.raw_os_error(),
                        selected: false,
                    },
                    stream: None,
                },
                Err(WaitError::TimedOut) => TcpCandidate {
                    attempted,
                    attempt: ConnectionAttempt {
                        remote,
                        local,
                        family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                        duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                        outcome: ConnectionOutcome::TimedOut,
                        error: Some("Connection timed out".to_owned()),
                        os_error: None,
                        selected: false,
                    },
                    stream: None,
                },
                Err(WaitError::Cancelled) => TcpCandidate {
                    attempted,
                    attempt: ConnectionAttempt {
                        remote,
                        local,
                        family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                        duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                        outcome: ConnectionOutcome::Cancelled,
                        error: Some("Request cancelled".to_owned()),
                        os_error: None,
                        selected: false,
                    },
                    stream: None,
                },
            };
            if let Some(attempt) = health_attempt {
                attempt.finish_tcp(&candidate, timeout, &cancel).await;
            }
            candidate
        }
    });
    join_all(futures).await
}

pub(crate) async fn connect_tcp_endpoint(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    cancel: &CancellationToken,
) -> TcpCandidate {
    connect_tcp_all(&[ip], port, timeout, cancel, None)
        .await
        .pop()
        .expect("one TCP candidate")
}

pub(super) fn select_tcp_candidate(candidates: &mut [TcpCandidate]) -> Option<TcpStream> {
    let index = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.stream.is_some())
        .min_by(|(_, a), (_, b)| a.attempt.duration_ms.total_cmp(&b.attempt.duration_ms))
        .map(|(index, _)| index)?;
    candidates[index].attempt.selected = true;
    candidates[index].stream.take()
}

pub(super) async fn connect_quic_all(
    addresses: &[IpAddr],
    port: u16,
    host: &str,
    timeout: Duration,
    cancel: &CancellationToken,
    limiter: Option<&ConnectionRateLimiter>,
    client_certificate: Option<LoadedClientCertificate>,
) -> Vec<QuicCandidate> {
    let futures = addresses.iter().copied().map(|ip| {
        let host = host.to_owned();
        let cancel = cancel.clone();
        let client_certificate = client_certificate.clone();
        async move {
            let remote = SocketAddr::new(ip, port);
            let started = Instant::now();
            let capture = Arc::new(Mutex::new(CertificateCapture::default()));
            if let Some(limiter) = limiter
                && limiter.wait(&cancel).await.is_err()
            {
                return QuicCandidate {
                    attempt: ConnectionAttempt {
                        remote,
                        local: None,
                        family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                        duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                        outcome: ConnectionOutcome::Cancelled,
                        error: Some("Scan cancelled".to_owned()),
                        os_error: None,
                        selected: false,
                    },
                    endpoint: None,
                    connection: None,
                    capture,
                };
            }
            let bind = if ip.is_ipv4() {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            };
            let mut endpoint = match quinn::Endpoint::client(bind) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    return QuicCandidate {
                        attempt: ConnectionAttempt {
                            remote,
                            local: None,
                            family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                            duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                            outcome: ConnectionOutcome::Failed,
                            error: Some(error.to_string()),
                            os_error: None,
                            selected: false,
                        },
                        endpoint: None,
                        connection: None,
                        capture,
                    };
                }
            };
            let local = endpoint.local_addr().ok();
            let result = async {
                let tls = make_tls_config(
                    ProtocolPreference::Http3,
                    capture.clone(),
                    true,
                    client_certificate.as_ref(),
                )?;
                let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                    .map_err(|error| error.to_string())?;
                let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
                endpoint.set_default_client_config(client_config);
                let connecting = endpoint
                    .connect(remote, &host)
                    .map_err(|error| error.to_string())?;
                let connection = connecting.await.map_err(|error| error.to_string())?;
                Ok::<_, String>((endpoint, connection))
            };
            match wait_for(timeout, &cancel, result).await {
                Ok(Ok((endpoint, connection))) => QuicCandidate {
                    attempt: ConnectionAttempt {
                        remote,
                        local: endpoint.local_addr().ok(),
                        family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                        duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                        outcome: ConnectionOutcome::Succeeded,
                        error: None,
                        os_error: None,
                        selected: false,
                    },
                    endpoint: Some(endpoint),
                    connection: Some(connection),
                    capture,
                },
                Ok(Err(error)) => QuicCandidate {
                    attempt: ConnectionAttempt {
                        remote,
                        local,
                        family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                        duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                        outcome: ConnectionOutcome::Failed,
                        error: Some(error),
                        os_error: None,
                        selected: false,
                    },
                    endpoint: None,
                    connection: None,
                    capture,
                },
                Err(WaitError::TimedOut) => QuicCandidate {
                    attempt: ConnectionAttempt {
                        remote,
                        local,
                        family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                        duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                        outcome: ConnectionOutcome::TimedOut,
                        error: Some("QUIC handshake timed out".to_owned()),
                        os_error: None,
                        selected: false,
                    },
                    endpoint: None,
                    connection: None,
                    capture,
                },
                Err(WaitError::Cancelled) => QuicCandidate {
                    attempt: ConnectionAttempt {
                        remote,
                        local,
                        family: (if (ip).is_ipv4() { "IPv4" } else { "IPv6" }.to_owned()),
                        duration_ms: ((started).elapsed().as_secs_f64() * 1000.0),
                        outcome: ConnectionOutcome::Cancelled,
                        error: Some("Request cancelled".to_owned()),
                        os_error: None,
                        selected: false,
                    },
                    endpoint: None,
                    connection: None,
                    capture,
                },
            }
        }
    });
    join_all(futures).await
}
