use super::*;
use hickory_resolver::proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use std::future::Future;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

pub(crate) const STOP_REASON: &str =
    "Skipped: sustained target-specific failure; automated blocking suspected";

tokio::task_local! {
    static TRACKER: Arc<Tracker>;
    static INSIDE_ATTEMPT: bool;
}

struct Tracker {
    started: Instant,
    addresses: Mutex<HashSet<IpAddr>>,
    endpoints: Mutex<BTreeMap<SocketAddr, Arc<Endpoint>>>,
}

struct Endpoint {
    gate: Arc<AsyncMutex<()>>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    attempts: usize,
    streak: usize,
    onset: Option<(usize, f64)>,
    timeouts: usize,
    rejections: usize,
    baseline: Option<Baseline>,
    last_check: Option<Instant>,
    observations: Vec<EndpointHealthObservation>,
    stopped: bool,
    http_observed: bool,
}

#[derive(Clone)]
pub(super) enum Baseline {
    Tcp(Duration),
    Http(HttpBaseline),
}

#[derive(Clone)]
pub(super) struct HttpBaseline {
    pub hostname: String,
    pub scheme: String,
    pub method: String,
    pub bytes: Vec<u8>,
    pub client_certificate: Option<LoadedClientCertificate>,
    pub connection_timeout: Duration,
    pub probe_timeout: Duration,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    Success,
    Timeout,
    Rejected,
    Other,
    Ignored,
}

pub(super) fn outcome(status: Option<u16>, error: Option<&str>) -> Outcome {
    if let Some(status) = status {
        return match status {
            403 | 429 => Outcome::Rejected,
            200..=399 => Outcome::Success,
            _ => Outcome::Other,
        };
    }
    let error = error.unwrap_or_default().to_ascii_lowercase();
    if error.contains("cancelled") || error.contains("skipped:") {
        Outcome::Ignored
    } else if error.contains("timed out") || error.contains("timeout") || error.contains("10060") {
        Outcome::Timeout
    } else if [
        "refused",
        "reset",
        "forcibly closed",
        "broken pipe",
        "connection aborted",
        "peer closed connection",
        "incomplete http headers",
        "unexpected eof",
        "10053",
        "10054",
        "10061",
    ]
    .iter()
    .any(|value| error.contains(value))
    {
        Outcome::Rejected
    } else {
        Outcome::Other
    }
}

pub(super) async fn scope<T>(future: impl Future<Output = T>) -> T {
    TRACKER
        .scope(
            Arc::new(Tracker {
                started: Instant::now(),
                addresses: Mutex::new(HashSet::new()),
                endpoints: Mutex::new(BTreeMap::new()),
            }),
            future,
        )
        .await
}

pub(crate) async fn inside<T>(future: impl Future<Output = T>) -> T {
    INSIDE_ATTEMPT.scope(true, future).await
}

pub(super) fn register(ip: IpAddr) {
    let _ = TRACKER.try_with(|tracker| tracker.addresses.lock().unwrap().insert(ip));
}

pub(crate) fn stopped(ip: IpAddr, port: u16) -> bool {
    TRACKER
        .try_with(|tracker| {
            tracker
                .endpoints
                .lock()
                .unwrap()
                .get(&SocketAddr::new(ip, port))
                .is_some_and(|endpoint| endpoint.state.lock().unwrap().stopped)
        })
        .unwrap_or(false)
}

pub(super) fn observations() -> Vec<EndpointHealthObservation> {
    TRACKER
        .try_with(|tracker| {
            tracker
                .endpoints
                .lock()
                .unwrap()
                .values()
                .flat_map(|endpoint| endpoint.state.lock().unwrap().observations.clone())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) struct Attempt {
    endpoint: Arc<Endpoint>,
    remote: SocketAddr,
    elapsed_ms: f64,
    _guard: OwnedMutexGuard<()>,
}

pub(crate) async fn begin(
    ip: IpAddr,
    port: u16,
    cancel: &CancellationToken,
) -> Result<Option<Attempt>, String> {
    if stopped(ip, port) {
        return Err(STOP_REASON.to_owned());
    }
    if INSIDE_ATTEMPT.try_with(|inside| *inside).unwrap_or(false) {
        return Ok(None);
    }
    let Ok(tracker) = TRACKER.try_with(Arc::clone) else {
        return Ok(None);
    };
    if !tracker.addresses.lock().unwrap().contains(&ip) {
        return Ok(None);
    }
    let remote = SocketAddr::new(ip, port);
    let endpoint = tracker
        .endpoints
        .lock()
        .unwrap()
        .entry(remote)
        .or_insert_with(|| {
            Arc::new(Endpoint {
                gate: Arc::new(AsyncMutex::new(())),
                state: Mutex::new(State::default()),
            })
        })
        .clone();
    let guard = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err("Scan cancelled".to_owned()),
        guard = endpoint.gate.clone().lock_owned() => guard,
    };
    if endpoint.state.lock().unwrap().stopped {
        return Err(STOP_REASON.to_owned());
    }
    Ok(Some(Attempt {
        endpoint,
        remote,
        elapsed_ms: ((tracker.started).elapsed().as_secs_f64() * 1000.0),
        _guard: guard,
    }))
}

impl Attempt {
    pub(super) async fn finish_http(
        self,
        result: Outcome,
        baseline: Option<Baseline>,
        cancel: &CancellationToken,
    ) {
        if result != Outcome::Ignored {
            let mut state = self.endpoint.state.lock().unwrap();
            state.http_observed = true;
            if matches!(state.baseline, Some(Baseline::Tcp(_))) {
                state.baseline = None;
            }
        }
        self.finish(result, baseline, cancel).await;
    }

    pub(crate) async fn finish_tcp(
        self,
        candidate: &TcpCandidate,
        timeout: Duration,
        cancel: &CancellationToken,
    ) {
        let result = if candidate.stream.is_some() {
            if self.endpoint.state.lock().unwrap().http_observed {
                Outcome::Ignored
            } else {
                Outcome::Success
            }
        } else if !candidate.attempted {
            Outcome::Ignored
        } else {
            outcome(None, candidate.attempt.error.as_deref())
        };
        self.finish(result, Some(Baseline::Tcp(timeout)), cancel)
            .await;
    }

    pub(super) async fn finish(
        self,
        result: Outcome,
        baseline: Option<Baseline>,
        cancel: &CancellationToken,
    ) {
        let confirmation = {
            let mut state = self.endpoint.state.lock().unwrap();
            if result == Outcome::Ignored || cancel.is_cancelled() {
                return;
            }
            state.attempts += 1;
            if result == Outcome::Success {
                if let Some(baseline) = baseline {
                    if matches!(baseline, Baseline::Http(_)) || state.baseline.is_none() {
                        state.baseline = Some(baseline);
                    }
                }
            }
            if !matches!(result, Outcome::Timeout | Outcome::Rejected) {
                state.streak = 0;
                state.onset = None;
                state.timeouts = 0;
                state.rejections = 0;
                if let Some(last) = state.observations.last_mut() {
                    if last.resolution == EndpointHealthResolution::Inconclusive
                        && result == Outcome::Success
                    {
                        last.resolution = EndpointHealthResolution::Recovered;
                        last.detail = "Subsequent requests responded; probing continued".to_owned();
                    }
                }
                return;
            }
            if state.streak == 0 {
                state.onset = Some((state.attempts, self.elapsed_ms));
            }
            state.streak += 1;
            state.timeouts += usize::from(result == Outcome::Timeout);
            state.rejections += usize::from(result == Outcome::Rejected);
            let onset = state.onset.unwrap();
            let timeouts = state.timeouts;
            let rejections = state.rejections;
            if let Some(last) = state.observations.last_mut() {
                if last.request_number == onset.0 {
                    last.timeouts = timeouts;
                    last.rejections = rejections;
                }
            }
            if state.streak < 3 {
                return;
            }
            let rate_limited = state
                .last_check
                .is_some_and(|last| last.elapsed() < Duration::from_secs(60));
            let same_episode = state
                .observations
                .last()
                .is_some_and(|last| last.request_number == onset.0);
            if rate_limited && same_episode {
                return;
            }
            let observation = EndpointHealthObservation {
                ip: self.remote.ip(), port: self.remote.port(), transport: TransportProtocol::Tcp,
                request_number: onset.0, elapsed_ms: onset.1, timeouts, rejections,
                had_baseline: state.baseline.is_some(),
                connectivity: Vec::new(), retries: Vec::new(),
                resolution: EndpointHealthResolution::Inconclusive,
                detail: "No previously successful safe baseline; endpoint unresponsive or rejecting requests".to_owned(),
            };
            if same_episode {
                *state.observations.last_mut().unwrap() = observation;
            } else {
                state.observations.push(observation);
            }
            if rate_limited {
                if state.baseline.is_some() {
                    state.observations.last_mut().unwrap().detail = "Sustained failures; confirmation rate-limited to once per minute; probing continued".to_owned();
                }
                return;
            }
            state.last_check = Some(Instant::now());
            state.baseline.clone()
        };
        let Some(baseline) = confirmation else {
            return;
        };
        let operation = async {
            let (dns, https) = tokio::join!(
                {
                    let (ipv6,): (bool,) = (self.remote.ip().is_ipv6(),);
                    async move {
                        let resolver = if ipv6 {
                            "[2606:4700:4700::1111]:53"
                        } else {
                            "1.1.1.1:53"
                        };
                        ({
                            let (label, future): (String, _) =
                                (format!("DNS via {resolver}"), async {
                                    let socket =
                                        UdpSocket::bind(if ipv6 { "[::]:0" } else { "0.0.0.0:0" })
                                            .await
                                            .map_err(|e| e.to_string())?;
                                    socket.connect(resolver).await.map_err(|e| e.to_string())?;
                                    let name = Name::from_str("www.google.com.")
                                        .map_err(|e| e.to_string())?;
                                    let record_type = if ipv6 {
                                        RecordType::AAAA
                                    } else {
                                        RecordType::A
                                    };
                                    let query = Query::query(name, record_type);
                                    let mut message = Message::query();
                                    let id = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .subsec_nanos()
                                        as u16;
                                    message.metadata.id = id;
                                    message.metadata.recursion_desired = true;
                                    message.add_query(query.clone());
                                    socket
                                        .send(&message.to_vec().map_err(|e| e.to_string())?)
                                        .await
                                        .map_err(|e| e.to_string())?;
                                    let mut bytes = [0u8; 4096];
                                    let size =
                                        socket.recv(&mut bytes).await.map_err(|e| e.to_string())?;
                                    let response = Message::from_vec(&bytes[..size])
                                        .map_err(|e| e.to_string())?;
                                    if response.metadata.id != id
                                        || response.metadata.message_type != MessageType::Response
                                        || response.metadata.response_code != ResponseCode::NoError
                                        || response.metadata.truncation
                                        || response.queries != [query]
                                        || !response.answers.iter().any(|answer| {
                                            matches!(
                                                (&answer.data, ipv6),
                                                (RData::A(_), false) | (RData::AAAA(_), true)
                                            )
                                        })
                                    {
                                        return Err("No valid matching DNS answer".to_owned());
                                    }
                                    Ok(())
                                });
                            async move {
                                let inlined_result: ConnectivityCheck = {
                                    let result =
                                        tokio::time::timeout(Duration::from_secs(5), future)
                                            .await
                                            .unwrap_or_else(|_| {
                                                Err("Timed out after 5 seconds".to_owned())
                                            });
                                    ConnectivityCheck {
                                        label,
                                        passed: result.is_ok(),
                                        detail: result
                                            .err()
                                            .unwrap_or_else(|| "Succeeded".to_owned()),
                                    }
                                };
                                inlined_result
                            }
                        })
                        .await
                    }
                },
                {
                    let (ipv6,): (bool,) = (self.remote.ip().is_ipv6(),);
                    async move {
                        ({
                            let (label, future): (String, _) =
                                ("Verified HTTPS to www.google.com".to_owned(), async {
                                    let addresses =
                                        tokio::net::lookup_host(("www.google.com", 443))
                                            .await
                                            .map_err(|e| e.to_string())?;
                                    let addresses: Vec<_> = addresses
                                        .filter(|address| address.is_ipv6() == ipv6)
                                        .collect();
                                    let mut last_error =
                                        "No address matching the target IP family".to_owned();
                                    for address in addresses.into_iter().take(2) {
                                        let result = async {
                                            let stream = TcpStream::connect(address)
                                                .await
                                                .map_err(|e| e.to_string())?;
                                            let config = make_exposure_tls_config(
                                                None,
                                                false,
                                                false,
                                                Arc::new(Mutex::new(CertificateCapture::default())),
                                                None,
                                            )?;
                                            let mut stream = TlsConnector::from(config)
                                                .connect(
                                                    ServerName::try_from("www.google.com").unwrap(),
                                                    stream,
                                                )
                                                .await
                                                .map_err(|e| e.to_string())?;
                                            stream
                    .write_all(
                        b"HEAD / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                                            let mut response = Vec::new();
                                            let mut bytes = [0u8; 1024];
                                            loop {
                                                let size = stream
                                                    .read(&mut bytes)
                                                    .await
                                                    .map_err(|e| e.to_string())?;
                                                if size == 0 {
                                                    return Err(
                                                        "Response ended before headers".to_owned()
                                                    );
                                                }
                                                response.extend_from_slice(&bytes[..size]);
                                                if response
                                                    .windows(4)
                                                    .any(|window| window == b"\r\n\r\n")
                                                {
                                                    break;
                                                }
                                                if response.len() > 16 * 1024 {
                                                    return Err(
                                                        "Response headers too large".to_owned()
                                                    );
                                                }
                                            }
                                            let status = String::from_utf8_lossy(&response)
                                                .split_whitespace()
                                                .nth(1)
                                                .and_then(|status| status.parse::<u16>().ok());
                                            if !status
                                                .is_some_and(|status| (200..400).contains(&status))
                                            {
                                                return Err(format!(
                                                    "Unexpected HTTPS status: {status:?}"
                                                ));
                                            }
                                            Ok(())
                                        }
                                        .await;
                                        match result {
                                            Ok(()) => return Ok(()),
                                            Err(error) => last_error = error,
                                        }
                                    }
                                    Err(last_error)
                                });
                            async move {
                                let inlined_result: ConnectivityCheck = {
                                    let result =
                                        tokio::time::timeout(Duration::from_secs(5), future)
                                            .await
                                            .unwrap_or_else(|_| {
                                                Err("Timed out after 5 seconds".to_owned())
                                            });
                                    ConnectivityCheck {
                                        label,
                                        passed: result.is_ok(),
                                        detail: result
                                            .err()
                                            .unwrap_or_else(|| "Succeeded".to_owned()),
                                    }
                                };
                                inlined_result
                            }
                        })
                        .await
                    }
                }
            );
            let checks = vec![dns, https];
            if checks.iter().any(|check| !check.passed) {
                return (
                    checks,
                    Vec::new(),
                    EndpointHealthResolution::Inconclusive,
                    "External connectivity could not be verified; probing continued".to_owned(),
                );
            }
            let mut retries = Vec::new();
            for index in 0..2 {
                if index > 0 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                let retry = inside({
                    let (baseline, remote, cancel): (&Baseline, SocketAddr, &CancellationToken) =
                        (&baseline, self.remote, cancel);
                    async move {
                        match baseline {
                            Baseline::Tcp(timeout) => {
                                tokio::time::timeout(*timeout, TcpStream::connect(remote))
                                    .await
                                    .map_err(|_| "Connection timed out".to_owned())?
                                    .map(|_| 200)
                                    .map_err(|error| error.to_string())
                            }
                            Baseline::Http(baseline) => {
                                exposure_probe::replay_health_baseline(baseline, remote, cancel)
                                    .await
                            }
                        }
                    }
                })
                .await;
                let result = match &retry {
                    Ok(status) => outcome(Some(*status), None),
                    Err(error) => outcome(None, Some(error)),
                };
                retries.push(match retry {
                    Ok(status) => format!("Baseline retry {}: response {status}", index + 1),
                    Err(error) => format!("Baseline retry {}: {error}", index + 1),
                });
                if result == Outcome::Success {
                    return (
                        checks,
                        retries,
                        EndpointHealthResolution::Recovered,
                        "Baseline responded; probing resumed".to_owned(),
                    );
                }
                if !matches!(result, Outcome::Timeout | Outcome::Rejected) {
                    return (
                        checks,
                        retries,
                        EndpointHealthResolution::Inconclusive,
                        "Baseline result does not establish sustained blocking; probing continued"
                            .to_owned(),
                    );
                }
            }
            (checks, retries, EndpointHealthResolution::Stopped,
                "Sustained target-specific failure; automated blocking suspected. Remaining endpoint work skipped; coverage is partial.".to_owned())
        };
        let (checks, retries, resolution, detail) = tokio::select! {
            biased;
            _ = cancel.cancelled() => (Vec::new(), Vec::new(), EndpointHealthResolution::Inconclusive,
                "Confirmation interrupted by user cancellation".to_owned()),
            result = operation => result,
        };
        let mut state = self.endpoint.state.lock().unwrap();
        state.stopped = resolution == EndpointHealthResolution::Stopped;
        if resolution == EndpointHealthResolution::Recovered {
            state.streak = 0;
            state.onset = None;
            state.timeouts = 0;
            state.rejections = 0;
        }
        if let Some(last) = state.observations.last_mut() {
            last.connectivity = checks;
            last.retries = retries;
            last.resolution = resolution;
            last.detail = detail;
        }
    }
}
