use super::*;
use regex::Regex;
use sha1::{Digest, Sha1};
use std::collections::HashSet;
use std::sync::LazyLock;

static EVENT_SOURCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)new\s+EventSource\s*\(\s*["']([^"']+)["']"#).expect("valid regex")
});
static WEB_SOCKET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)new\s+WebSocket\s*\(\s*["']([^"']+)["']"#).expect("valid regex")
});
static MEDIA_SOURCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<(?:video|audio|source)\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']"#)
        .expect("valid regex")
});
static FETCH_SOURCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)fetch\s*\(\s*["']([^"']+)["']([^)]{0,1024})\)"#).expect("valid regex")
});
static XHR_SOURCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\.open\s*\(\s*["'](GET|POST)["']\s*,\s*["']([^"']+)["']"#)
        .expect("valid regex")
});
static POST_HELPER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:\$\.post|axios\.post)\s*\(\s*["']([^"']+)["']"#).expect("valid regex")
});
static QUOTED_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["']((?:https?://|/|\./|\.\./)[^"'\s<>]{1,2048})["']"#).expect("valid regex")
});

pub(super) fn collect(
    endpoints: &[EndpointScan],
    crawl: &crawl::CrawlReport,
    scripts: &[fingerprints::CapturedScriptResponse],
) -> Vec<StreamObservation> {
    let mut observations = Vec::new();
    for endpoint in endpoints {
        for response in &endpoint.http {
            ({
                let (response, observations): (&HttpObservation, &mut Vec<StreamObservation>) =
                    (response, &mut observations);

                collect_body(
                    &response.url,
                    &response.headers,
                    &response.body,
                    Some(&response.framing),
                    Some(response.status),
                    observations,
                );
            });
        }
    }
    for resource in &crawl.technology_resources {
        collect_body(
            &resource.url,
            &resource.headers,
            &resource.body,
            None,
            Some(resource.status),
            &mut observations,
        );
    }
    for script in scripts {
        ({
            let (response, observations): (&HttpObservation, &mut Vec<StreamObservation>) =
                (&script.response, &mut observations);

            collect_body(
                &response.url,
                &response.headers,
                &response.body,
                Some(&response.framing),
                Some(response.status),
                observations,
            );
        });
    }
    observations.extend(crawl.stream_observations.clone());
    for form in &crawl.forms {
        if form.method.eq_ignore_ascii_case("POST") {
            observations.push(StreamObservation {
                source_url: form.source_url.clone(),
                kind: StreamKind::ChunkedIncremental,
                status: StreamStatus::Candidate,
                confidence: Confidence::Low,
                evidence: vec![
                    "POST-only form action discovered; automatic stream validation uses GET only"
                        .to_owned(),
                ],
                endpoints: vec![form.action_url.clone()],
            });
        }
    }
    ({
        let (observations, resources): (&mut Vec<StreamObservation>, &[CrawledResource]) =
            (&mut observations, &crawl.resources);

        let confirmed = observations
            .iter()
            .filter(|observation| observation.status == StreamStatus::Confirmed)
            .flat_map(|observation| observation.endpoints.iter().cloned())
            .collect::<HashSet<_>>();
        let mut additions = Vec::new();
        for observation in observations
            .iter()
            .filter(|observation| observation.status == StreamStatus::Candidate)
        {
            if observation
                .evidence
                .iter()
                .any(|evidence| evidence.contains("POST-only"))
            {
                continue;
            }
            for endpoint in &observation.endpoints {
                let Some(resource) = resources.iter().find(|resource| resource.url == *endpoint)
                else {
                    continue;
                };
                let (status, evidence) = match resource.status {
                    Some(401 | 403) => (
                        StreamStatus::Protected,
                        format!(
                            "Safe GET returned HTTP {}",
                            resource.status.unwrap_or_default()
                        ),
                    ),
                    Some(status)
                        if (200..300).contains(&status) && !confirmed.contains(endpoint) =>
                    {
                        (
                            StreamStatus::Inconclusive,
                            format!(
                                "Safe GET returned HTTP {status} without recognizable streaming evidence"
                            ),
                        )
                    }
                    _ => continue,
                };
                let mut result = observation.clone();
                result.source_url = endpoint.clone();
                result.status = status;
                result.evidence = vec![evidence];
                additions.push(result);
            }
        }
        observations.extend(additions);
    });
    merge_observations(&mut observations);
    observations
}

fn merge_observations(observations: &mut Vec<StreamObservation>) {
    observations.sort_by(|left, right| {
        left.source_url
            .cmp(&right.source_url)
            .then(left.kind.cmp(&right.kind))
            .then(left.status.cmp(&right.status))
    });
    let mut merged: Vec<StreamObservation> = Vec::new();
    for mut observation in std::mem::take(observations) {
        observation.endpoints.sort();
        observation.endpoints.dedup();
        observation.evidence.sort();
        observation.evidence.dedup();
        if let Some(existing) = merged.iter_mut().find(|existing| {
            existing.source_url == observation.source_url
                && existing.kind == observation.kind
                && existing.status == observation.status
        }) {
            existing.endpoints.extend(observation.endpoints);
            existing.evidence.extend(observation.evidence);
            existing.confidence = existing.confidence.max(observation.confidence);
            existing.endpoints.sort();
            existing.endpoints.dedup();
            existing.evidence.sort();
            existing.evidence.dedup();
        } else {
            merged.push(observation);
        }
    }
    *observations = merged;
    observations.truncate(500);
}

pub(super) fn observations_for_response(response: &HttpObservation) -> Vec<StreamObservation> {
    let mut observations = Vec::new();
    ({
        let (response, observations): (&HttpObservation, &mut Vec<StreamObservation>) =
            (response, &mut observations);

        collect_body(
            &response.url,
            &response.headers,
            &response.body,
            Some(&response.framing),
            Some(response.status),
            observations,
        );
    });
    observations
}

fn collect_body(
    source_url: &str,
    headers: &[(String, String)],
    body: &[u8],
    framing: Option<&ResponseFraming>,
    status: Option<u16>,
    observations: &mut Vec<StreamObservation>,
) {
    let content_type = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&body[..body.len().min(256 * 1024)]);
    let successful = status.is_none_or(|status| (200..300).contains(&status));
    if successful {
        ({
            let (source_url, content_type, text, framing, observations): (
                &str,
                &str,
                &str,
                Option<&ResponseFraming>,
                &mut Vec<StreamObservation>,
            ) = (source_url, &content_type, &text, framing, observations);

            let sse_frames = text
                .lines()
                .filter(|line| line.trim_start().starts_with("data:"))
                .count();
            if content_type.contains("text/event-stream") || sse_frames >= 2 {
                confirmed(
                    observations,
                    source_url,
                    StreamKind::ServerSentEvents,
                    if content_type.contains("text/event-stream") {
                        "Content-Type is text/event-stream"
                    } else {
                        "Multiple SSE data frames were observed"
                    },
                );
            }
            let json_lines = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .take(16)
                .filter(|line| serde_json::from_str::<serde_json::Value>(line.trim()).is_ok())
                .count();
            if content_type.contains("ndjson")
                || content_type.contains("x-ndjson")
                || json_lines >= 2
            {
                confirmed(
                    observations,
                    source_url,
                    StreamKind::Ndjson,
                    if content_type.contains("ndjson") {
                        "NDJSON content type observed"
                    } else {
                        "Multiple newline-delimited JSON values were observed"
                    },
                );
            }
            let json_sequence_records =
                text.as_bytes().iter().filter(|byte| **byte == 0x1e).count();
            if content_type.contains("application/json-seq") || json_sequence_records >= 2 {
                confirmed(
                    observations,
                    source_url,
                    StreamKind::JsonSequence,
                    "JSON text-sequence content type or record separators observed",
                );
            }
            if content_type.contains("mpegurl") || text.trim_start().starts_with("#EXTM3U") {
                confirmed(
                    observations,
                    source_url,
                    StreamKind::Hls,
                    "HLS content type or #EXTM3U playlist framing observed",
                );
            }
            let lower = text.trim_start().to_ascii_lowercase();
            if content_type.contains("dash+xml")
                || lower.starts_with("<mpd")
                || lower.starts_with("<?xml") && lower.contains("<mpd")
            {
                confirmed(
                    observations,
                    source_url,
                    StreamKind::Dash,
                    "DASH content type or MPD document observed",
                );
            }
            if let Some(framing) = framing.filter(|framing| framing.transfer_chunked) {
                let incremental = !framing.completed && framing.decoded_chunks >= 2;
                observations.push(StreamObservation {
            source_url: source_url.to_owned(),
            kind: StreamKind::ChunkedIncremental,
            status: if incremental {
                StreamStatus::Confirmed
            } else {
                StreamStatus::Inconclusive
            },
            confidence: if incremental {
                Confidence::Medium
            } else {
                Confidence::Low
            },
            evidence: vec![if incremental {
                format!(
                    "Incomplete chunked delivery produced {} chunks across {} reads",
                    framing.decoded_chunks, framing.body_read_events
                )
            } else {
                "Transfer-Encoding: chunked alone is weak evidence; no sustained incremental delivery was established".to_owned()
            }],
            endpoints: vec![source_url.to_owned()],
        });
            }
        });
    }
    let sdp = content_type.contains("application/sdp")
        || text.lines().take(10).any(|line| line.trim() == "v=0")
            && text.lines().any(|line| line.starts_with("m="));
    if sdp {
        let endpoints = text
            .lines()
            .map(str::trim)
            .filter(|line| {
                line.starts_with("m=")
                    || line.starts_with("c=")
                    || line.starts_with("a=candidate:")
                    || line.starts_with("a=ice-options:")
            })
            .take(64)
            .map(|line| line.chars().take(300).collect())
            .collect::<Vec<String>>();
        observations.push(StreamObservation {
            source_url: source_url.to_owned(),
            kind: StreamKind::WebRtcSdp,
            status: if successful {
                StreamStatus::Confirmed
            } else {
                StreamStatus::Candidate
            },
            confidence: Confidence::High,
            evidence: vec![if content_type.contains("application/sdp") {
                "Content-Type is application/sdp".to_owned()
            } else {
                "Recognizable SDP v= and m= framing".to_owned()
            }],
            endpoints,
        });
    }
    let mut ice = text
        .split(|character: char| {
            character.is_whitespace() || matches!(character, '\"' | '\'' | '`' | '<' | '>')
        })
        .map(|value| value.trim_matches([',', ';', ')', '(', '[', ']']))
        .filter(|value| {
            value.starts_with("stun:")
                || value.starts_with("stuns:")
                || value.starts_with("turn:")
                || value.starts_with("turns:")
        })
        .map(|value| {
            value
                .split('?')
                .next()
                .unwrap_or(value)
                .chars()
                .take(300)
                .collect()
        })
        .collect::<Vec<String>>();
    ice.sort();
    ice.dedup();
    if !ice.is_empty() {
        observations.push(StreamObservation {
            source_url: source_url.to_owned(),
            kind: StreamKind::StunTurn,
            status: StreamStatus::Candidate,
            confidence: Confidence::High,
            evidence: vec!["STUN or TURN URI found in response content".to_owned()],
            endpoints: ice,
        });
    }
    ({
        let (source_url, text, observations): (&str, &str, &mut Vec<StreamObservation>) =
            (source_url, &text, observations);

        for capture in EVENT_SOURCE.captures_iter(text).take(64) {
            ({
                let (observations, source_url, kind, endpoint, evidence, post_only): (
                    &mut Vec<StreamObservation>,
                    &str,
                    StreamKind,
                    Option<&str>,
                    &str,
                    bool,
                ) = (
                    observations,
                    source_url,
                    StreamKind::EventSource,
                    capture.get(1).map(|value| value.as_str()),
                    "JavaScript EventSource constructor",
                    false,
                );
                'inlined_candidate: {
                    let Some(endpoint) =
                        endpoint.and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                    else {
                        break 'inlined_candidate;
                    };
                    let mut evidence = vec![evidence.to_owned()];
                    if post_only {
                        evidence.push(
                            "POST-only candidate; automatic validation was not attempted"
                                .to_owned(),
                        );
                    }
                    observations.push(StreamObservation {
                        source_url: source_url.to_owned(),
                        kind,
                        status: StreamStatus::Candidate,
                        confidence: if post_only {
                            Confidence::Low
                        } else {
                            Confidence::Medium
                        },
                        evidence,
                        endpoints: vec![endpoint],
                    });
                }
            });
        }
        for capture in WEB_SOCKET.captures_iter(text).take(64) {
            ({
                let (observations, source_url, kind, endpoint, evidence, post_only): (
                    &mut Vec<StreamObservation>,
                    &str,
                    StreamKind,
                    Option<&str>,
                    &str,
                    bool,
                ) = (
                    observations,
                    source_url,
                    StreamKind::WebSocket,
                    capture.get(1).map(|value| value.as_str()),
                    "JavaScript WebSocket constructor",
                    false,
                );
                'inlined_candidate: {
                    let Some(endpoint) =
                        endpoint.and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                    else {
                        break 'inlined_candidate;
                    };
                    let mut evidence = vec![evidence.to_owned()];
                    if post_only {
                        evidence.push(
                            "POST-only candidate; automatic validation was not attempted"
                                .to_owned(),
                        );
                    }
                    observations.push(StreamObservation {
                        source_url: source_url.to_owned(),
                        kind,
                        status: StreamStatus::Candidate,
                        confidence: if post_only {
                            Confidence::Low
                        } else {
                            Confidence::Medium
                        },
                        evidence,
                        endpoints: vec![endpoint],
                    });
                }
            });
        }
        for capture in MEDIA_SOURCE.captures_iter(text).take(128) {
            ({
                let (observations, source_url, kind, endpoint, evidence, post_only): (
                    &mut Vec<StreamObservation>,
                    &str,
                    StreamKind,
                    Option<&str>,
                    &str,
                    bool,
                ) = (
                    observations,
                    source_url,
                    StreamKind::MediaElement,
                    capture.get(1).map(|value| value.as_str()),
                    "HTML video, audio, or source element",
                    false,
                );
                'inlined_candidate: {
                    let Some(endpoint) =
                        endpoint.and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                    else {
                        break 'inlined_candidate;
                    };
                    let mut evidence = vec![evidence.to_owned()];
                    if post_only {
                        evidence.push(
                            "POST-only candidate; automatic validation was not attempted"
                                .to_owned(),
                        );
                    }
                    observations.push(StreamObservation {
                        source_url: source_url.to_owned(),
                        kind,
                        status: StreamStatus::Candidate,
                        confidence: if post_only {
                            Confidence::Low
                        } else {
                            Confidence::Medium
                        },
                        evidence,
                        endpoints: vec![endpoint],
                    });
                }
            });
        }
        let readable = text.contains("ReadableStream")
            || text.contains("response.body")
            || text.contains("getReader(");
        if readable {
            let mut found = false;
            for capture in FETCH_SOURCE.captures_iter(text).take(64) {
                found = true;
                let options = capture.get(2).map_or("", |value| value.as_str());
                ({
                    let (observations, source_url, kind, endpoint, evidence, post_only): (
                        &mut Vec<StreamObservation>,
                        &str,
                        StreamKind,
                        Option<&str>,
                        &str,
                        bool,
                    ) = (
                        observations,
                        source_url,
                        StreamKind::ReadableStream,
                        capture.get(1).map(|value| value.as_str()),
                        "JavaScript fetch associated with ReadableStream consumption",
                        options.to_ascii_lowercase().contains("method")
                            && options.to_ascii_lowercase().contains("post"),
                    );
                    'inlined_candidate: {
                        let Some(endpoint) =
                            endpoint.and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                        else {
                            break 'inlined_candidate;
                        };
                        let mut evidence = vec![evidence.to_owned()];
                        if post_only {
                            evidence.push(
                                "POST-only candidate; automatic validation was not attempted"
                                    .to_owned(),
                            );
                        }
                        observations.push(StreamObservation {
                            source_url: source_url.to_owned(),
                            kind,
                            status: StreamStatus::Candidate,
                            confidence: if post_only {
                                Confidence::Low
                            } else {
                                Confidence::Medium
                            },
                            evidence,
                            endpoints: vec![endpoint],
                        });
                    }
                });
            }
            if !found {
                observations.push(StreamObservation {
                    source_url: source_url.to_owned(),
                    kind: StreamKind::ReadableStream,
                    status: StreamStatus::Candidate,
                    confidence: Confidence::Low,
                    evidence: vec![
                    "JavaScript ReadableStream usage found without a safely extractable endpoint"
                        .to_owned(),
                ],
                    endpoints: Vec::new(),
                });
            }
        }
        for capture in XHR_SOURCE.captures_iter(text).take(64) {
            let post = capture
                .get(1)
                .is_some_and(|method| method.as_str().eq_ignore_ascii_case("POST"));
            ({
                let (observations, source_url, kind, endpoint, evidence, post_only): (
                    &mut Vec<StreamObservation>,
                    &str,
                    StreamKind,
                    Option<&str>,
                    &str,
                    bool,
                ) = (
                    observations,
                    source_url,
                    StreamKind::ChunkedIncremental,
                    capture.get(2).map(|value| value.as_str()),
                    "JavaScript XMLHttpRequest API endpoint",
                    post,
                );
                'inlined_candidate: {
                    let Some(endpoint) =
                        endpoint.and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                    else {
                        break 'inlined_candidate;
                    };
                    let mut evidence = vec![evidence.to_owned()];
                    if post_only {
                        evidence.push(
                            "POST-only candidate; automatic validation was not attempted"
                                .to_owned(),
                        );
                    }
                    observations.push(StreamObservation {
                        source_url: source_url.to_owned(),
                        kind,
                        status: StreamStatus::Candidate,
                        confidence: if post_only {
                            Confidence::Low
                        } else {
                            Confidence::Medium
                        },
                        evidence,
                        endpoints: vec![endpoint],
                    });
                }
            });
        }
        for capture in POST_HELPER.captures_iter(text).take(64) {
            ({
                let (observations, source_url, kind, endpoint, evidence, post_only): (
                    &mut Vec<StreamObservation>,
                    &str,
                    StreamKind,
                    Option<&str>,
                    &str,
                    bool,
                ) = (
                    observations,
                    source_url,
                    StreamKind::ChunkedIncremental,
                    capture.get(1).map(|value| value.as_str()),
                    "JavaScript POST API endpoint",
                    true,
                );
                'inlined_candidate: {
                    let Some(endpoint) =
                        endpoint.and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                    else {
                        break 'inlined_candidate;
                    };
                    let mut evidence = vec![evidence.to_owned()];
                    if post_only {
                        evidence.push(
                            "POST-only candidate; automatic validation was not attempted"
                                .to_owned(),
                        );
                    }
                    observations.push(StreamObservation {
                        source_url: source_url.to_owned(),
                        kind,
                        status: StreamStatus::Candidate,
                        confidence: if post_only {
                            Confidence::Low
                        } else {
                            Confidence::Medium
                        },
                        evidence,
                        endpoints: vec![endpoint],
                    });
                }
            });
        }
        for capture in FETCH_SOURCE.captures_iter(text).take(64) {
            let endpoint = capture.get(1).map(|value| value.as_str());
            let Some(endpoint) = endpoint else { continue };
            let lower = endpoint.to_ascii_lowercase();
            let options = capture.get(2).map_or("", |value| value.as_str());
            let post = options.to_ascii_lowercase().contains("method")
                && options.to_ascii_lowercase().contains("post");
            ({
                let (observations, source_url, kind, endpoint, evidence, post_only): (
                    &mut Vec<StreamObservation>,
                    &str,
                    StreamKind,
                    Option<&str>,
                    &str,
                    bool,
                ) = (
                    observations,
                    source_url,
                    if lower.contains(".m3u8") {
                        StreamKind::Hls
                    } else if lower.contains(".mpd") {
                        StreamKind::Dash
                    } else {
                        StreamKind::ChunkedIncremental
                    },
                    Some(endpoint),
                    if lower.contains(".m3u8") || lower.contains(".mpd") {
                        "Streaming playlist URL referenced by JavaScript"
                    } else {
                        "JavaScript fetch API endpoint"
                    },
                    post,
                );
                'inlined_candidate: {
                    let Some(endpoint) =
                        endpoint.and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                    else {
                        break 'inlined_candidate;
                    };
                    let mut evidence = vec![evidence.to_owned()];
                    if post_only {
                        evidence.push(
                            "POST-only candidate; automatic validation was not attempted"
                                .to_owned(),
                        );
                    }
                    observations.push(StreamObservation {
                        source_url: source_url.to_owned(),
                        kind,
                        status: StreamStatus::Candidate,
                        confidence: if post_only {
                            Confidence::Low
                        } else {
                            Confidence::Medium
                        },
                        evidence,
                        endpoints: vec![endpoint],
                    });
                }
            });
        }
        if readable {
            for capture in QUOTED_PATH.captures_iter(text).take(64) {
                ({
                    let (observations, source_url, kind, endpoint, evidence, post_only): (
                        &mut Vec<StreamObservation>,
                        &str,
                        StreamKind,
                        Option<&str>,
                        &str,
                        bool,
                    ) = (
                        observations,
                        source_url,
                        StreamKind::ReadableStream,
                        capture.get(1).map(|value| value.as_str()),
                        "URL literal near JavaScript streaming APIs",
                        false,
                    );
                    'inlined_candidate: {
                        let Some(endpoint) =
                            endpoint.and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                        else {
                            break 'inlined_candidate;
                        };
                        let mut evidence = vec![evidence.to_owned()];
                        if post_only {
                            evidence.push(
                                "POST-only candidate; automatic validation was not attempted"
                                    .to_owned(),
                            );
                        }
                        observations.push(StreamObservation {
                            source_url: source_url.to_owned(),
                            kind,
                            status: StreamStatus::Candidate,
                            confidence: if post_only {
                                Confidence::Low
                            } else {
                                Confidence::Medium
                            },
                            evidence,
                            endpoints: vec![endpoint],
                        });
                    }
                });
            }
        }
    });
    if source_url
        .split(['?', '#'])
        .next()
        .is_some_and(|url| url.to_ascii_lowercase().ends_with(".map"))
        && let Ok(map) = serde_json::from_slice::<serde_json::Value>(body)
        && let Some(contents) = map
            .get("sourcesContent")
            .and_then(serde_json::Value::as_array)
    {
        for content in contents
            .iter()
            .filter_map(serde_json::Value::as_str)
            .take(256)
        {
            ({
                let (source_url, text, observations): (&str, &str, &mut Vec<StreamObservation>) =
                    (source_url, content, observations);

                for capture in EVENT_SOURCE.captures_iter(text).take(64) {
                    ({
                        let (observations, source_url, kind, endpoint, evidence, post_only): (
                            &mut Vec<StreamObservation>,
                            &str,
                            StreamKind,
                            Option<&str>,
                            &str,
                            bool,
                        ) = (
                            observations,
                            source_url,
                            StreamKind::EventSource,
                            capture.get(1).map(|value| value.as_str()),
                            "JavaScript EventSource constructor",
                            false,
                        );
                        'inlined_candidate: {
                            let Some(endpoint) = endpoint
                                .and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                            else {
                                break 'inlined_candidate;
                            };
                            let mut evidence = vec![evidence.to_owned()];
                            if post_only {
                                evidence.push(
                                    "POST-only candidate; automatic validation was not attempted"
                                        .to_owned(),
                                );
                            }
                            observations.push(StreamObservation {
                                source_url: source_url.to_owned(),
                                kind,
                                status: StreamStatus::Candidate,
                                confidence: if post_only {
                                    Confidence::Low
                                } else {
                                    Confidence::Medium
                                },
                                evidence,
                                endpoints: vec![endpoint],
                            });
                        }
                    });
                }
                for capture in WEB_SOCKET.captures_iter(text).take(64) {
                    ({
                        let (observations, source_url, kind, endpoint, evidence, post_only): (
                            &mut Vec<StreamObservation>,
                            &str,
                            StreamKind,
                            Option<&str>,
                            &str,
                            bool,
                        ) = (
                            observations,
                            source_url,
                            StreamKind::WebSocket,
                            capture.get(1).map(|value| value.as_str()),
                            "JavaScript WebSocket constructor",
                            false,
                        );
                        'inlined_candidate: {
                            let Some(endpoint) = endpoint
                                .and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                            else {
                                break 'inlined_candidate;
                            };
                            let mut evidence = vec![evidence.to_owned()];
                            if post_only {
                                evidence.push(
                                    "POST-only candidate; automatic validation was not attempted"
                                        .to_owned(),
                                );
                            }
                            observations.push(StreamObservation {
                                source_url: source_url.to_owned(),
                                kind,
                                status: StreamStatus::Candidate,
                                confidence: if post_only {
                                    Confidence::Low
                                } else {
                                    Confidence::Medium
                                },
                                evidence,
                                endpoints: vec![endpoint],
                            });
                        }
                    });
                }
                for capture in MEDIA_SOURCE.captures_iter(text).take(128) {
                    ({
                        let (observations, source_url, kind, endpoint, evidence, post_only): (
                            &mut Vec<StreamObservation>,
                            &str,
                            StreamKind,
                            Option<&str>,
                            &str,
                            bool,
                        ) = (
                            observations,
                            source_url,
                            StreamKind::MediaElement,
                            capture.get(1).map(|value| value.as_str()),
                            "HTML video, audio, or source element",
                            false,
                        );
                        'inlined_candidate: {
                            let Some(endpoint) = endpoint
                                .and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                            else {
                                break 'inlined_candidate;
                            };
                            let mut evidence = vec![evidence.to_owned()];
                            if post_only {
                                evidence.push(
                                    "POST-only candidate; automatic validation was not attempted"
                                        .to_owned(),
                                );
                            }
                            observations.push(StreamObservation {
                                source_url: source_url.to_owned(),
                                kind,
                                status: StreamStatus::Candidate,
                                confidence: if post_only {
                                    Confidence::Low
                                } else {
                                    Confidence::Medium
                                },
                                evidence,
                                endpoints: vec![endpoint],
                            });
                        }
                    });
                }
                let readable = text.contains("ReadableStream")
                    || text.contains("response.body")
                    || text.contains("getReader(");
                if readable {
                    let mut found = false;
                    for capture in FETCH_SOURCE.captures_iter(text).take(64) {
                        found = true;
                        let options = capture.get(2).map_or("", |value| value.as_str());
                        ({
                            let (observations, source_url, kind, endpoint, evidence, post_only): (
                                &mut Vec<StreamObservation>,
                                &str,
                                StreamKind,
                                Option<&str>,
                                &str,
                                bool,
                            ) = (
                                observations,
                                source_url,
                                StreamKind::ReadableStream,
                                capture.get(1).map(|value| value.as_str()),
                                "JavaScript fetch associated with ReadableStream consumption",
                                options.to_ascii_lowercase().contains("method")
                                    && options.to_ascii_lowercase().contains("post"),
                            );
                            'inlined_candidate: {
                                let Some(endpoint) = endpoint
                                    .and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                                else {
                                    break 'inlined_candidate;
                                };
                                let mut evidence = vec![evidence.to_owned()];
                                if post_only {
                                    evidence.push("POST-only candidate; automatic validation was not attempted".to_owned());
                                }
                                observations.push(StreamObservation {
                                    source_url: source_url.to_owned(),
                                    kind,
                                    status: StreamStatus::Candidate,
                                    confidence: if post_only {
                                        Confidence::Low
                                    } else {
                                        Confidence::Medium
                                    },
                                    evidence,
                                    endpoints: vec![endpoint],
                                });
                            }
                        });
                    }
                    if !found {
                        observations.push(StreamObservation {
                            source_url: source_url.to_owned(),
                            kind: StreamKind::ReadableStream,
                            status: StreamStatus::Candidate,
                            confidence: Confidence::Low,
                            evidence: vec![
                    "JavaScript ReadableStream usage found without a safely extractable endpoint"
                        .to_owned(),
                ],
                            endpoints: Vec::new(),
                        });
                    }
                }
                for capture in XHR_SOURCE.captures_iter(text).take(64) {
                    let post = capture
                        .get(1)
                        .is_some_and(|method| method.as_str().eq_ignore_ascii_case("POST"));
                    ({
                        let (observations, source_url, kind, endpoint, evidence, post_only): (
                            &mut Vec<StreamObservation>,
                            &str,
                            StreamKind,
                            Option<&str>,
                            &str,
                            bool,
                        ) = (
                            observations,
                            source_url,
                            StreamKind::ChunkedIncremental,
                            capture.get(2).map(|value| value.as_str()),
                            "JavaScript XMLHttpRequest API endpoint",
                            post,
                        );
                        'inlined_candidate: {
                            let Some(endpoint) = endpoint
                                .and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                            else {
                                break 'inlined_candidate;
                            };
                            let mut evidence = vec![evidence.to_owned()];
                            if post_only {
                                evidence.push(
                                    "POST-only candidate; automatic validation was not attempted"
                                        .to_owned(),
                                );
                            }
                            observations.push(StreamObservation {
                                source_url: source_url.to_owned(),
                                kind,
                                status: StreamStatus::Candidate,
                                confidence: if post_only {
                                    Confidence::Low
                                } else {
                                    Confidence::Medium
                                },
                                evidence,
                                endpoints: vec![endpoint],
                            });
                        }
                    });
                }
                for capture in POST_HELPER.captures_iter(text).take(64) {
                    ({
                        let (observations, source_url, kind, endpoint, evidence, post_only): (
                            &mut Vec<StreamObservation>,
                            &str,
                            StreamKind,
                            Option<&str>,
                            &str,
                            bool,
                        ) = (
                            observations,
                            source_url,
                            StreamKind::ChunkedIncremental,
                            capture.get(1).map(|value| value.as_str()),
                            "JavaScript POST API endpoint",
                            true,
                        );
                        'inlined_candidate: {
                            let Some(endpoint) = endpoint
                                .and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                            else {
                                break 'inlined_candidate;
                            };
                            let mut evidence = vec![evidence.to_owned()];
                            if post_only {
                                evidence.push(
                                    "POST-only candidate; automatic validation was not attempted"
                                        .to_owned(),
                                );
                            }
                            observations.push(StreamObservation {
                                source_url: source_url.to_owned(),
                                kind,
                                status: StreamStatus::Candidate,
                                confidence: if post_only {
                                    Confidence::Low
                                } else {
                                    Confidence::Medium
                                },
                                evidence,
                                endpoints: vec![endpoint],
                            });
                        }
                    });
                }
                for capture in FETCH_SOURCE.captures_iter(text).take(64) {
                    let endpoint = capture.get(1).map(|value| value.as_str());
                    let Some(endpoint) = endpoint else { continue };
                    let lower = endpoint.to_ascii_lowercase();
                    let options = capture.get(2).map_or("", |value| value.as_str());
                    let post = options.to_ascii_lowercase().contains("method")
                        && options.to_ascii_lowercase().contains("post");
                    ({
                        let (observations, source_url, kind, endpoint, evidence, post_only): (
                            &mut Vec<StreamObservation>,
                            &str,
                            StreamKind,
                            Option<&str>,
                            &str,
                            bool,
                        ) = (
                            observations,
                            source_url,
                            if lower.contains(".m3u8") {
                                StreamKind::Hls
                            } else if lower.contains(".mpd") {
                                StreamKind::Dash
                            } else {
                                StreamKind::ChunkedIncremental
                            },
                            Some(endpoint),
                            if lower.contains(".m3u8") || lower.contains(".mpd") {
                                "Streaming playlist URL referenced by JavaScript"
                            } else {
                                "JavaScript fetch API endpoint"
                            },
                            post,
                        );
                        'inlined_candidate: {
                            let Some(endpoint) = endpoint
                                .and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                            else {
                                break 'inlined_candidate;
                            };
                            let mut evidence = vec![evidence.to_owned()];
                            if post_only {
                                evidence.push(
                                    "POST-only candidate; automatic validation was not attempted"
                                        .to_owned(),
                                );
                            }
                            observations.push(StreamObservation {
                                source_url: source_url.to_owned(),
                                kind,
                                status: StreamStatus::Candidate,
                                confidence: if post_only {
                                    Confidence::Low
                                } else {
                                    Confidence::Medium
                                },
                                evidence,
                                endpoints: vec![endpoint],
                            });
                        }
                    });
                }
                if readable {
                    for capture in QUOTED_PATH.captures_iter(text).take(64) {
                        ({
                            let (observations, source_url, kind, endpoint, evidence, post_only): (
                                &mut Vec<StreamObservation>,
                                &str,
                                StreamKind,
                                Option<&str>,
                                &str,
                                bool,
                            ) = (
                                observations,
                                source_url,
                                StreamKind::ReadableStream,
                                capture.get(1).map(|value| value.as_str()),
                                "URL literal near JavaScript streaming APIs",
                                false,
                            );
                            'inlined_candidate: {
                                let Some(endpoint) = endpoint
                                    .and_then(|endpoint| resolve_endpoint(source_url, endpoint))
                                else {
                                    break 'inlined_candidate;
                                };
                                let mut evidence = vec![evidence.to_owned()];
                                if post_only {
                                    evidence.push("POST-only candidate; automatic validation was not attempted".to_owned());
                                }
                                observations.push(StreamObservation {
                                    source_url: source_url.to_owned(),
                                    kind,
                                    status: StreamStatus::Candidate,
                                    confidence: if post_only {
                                        Confidence::Low
                                    } else {
                                        Confidence::Medium
                                    },
                                    evidence,
                                    endpoints: vec![endpoint],
                                });
                            }
                        });
                    }
                }
            });
        }
    }
}

fn confirmed(
    observations: &mut Vec<StreamObservation>,
    source_url: &str,
    kind: StreamKind,
    evidence: &str,
) {
    observations.push(StreamObservation {
        source_url: source_url.to_owned(),
        kind,
        status: StreamStatus::Confirmed,
        confidence: Confidence::High,
        evidence: vec![evidence.to_owned()],
        endpoints: vec![source_url.to_owned()],
    });
}

fn resolve_endpoint(source_url: &str, endpoint: &str) -> Option<String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() || endpoint.starts_with("data:") || endpoint.starts_with("javascript:") {
        return None;
    }
    let base = Url::parse(source_url).ok()?;
    let mut url = base.join(endpoint).ok()?;
    url.set_fragment(None);
    Some(url.to_string())
}

pub(super) fn post_only_endpoints(source_url: &str, text: &str) -> HashSet<String> {
    let mut endpoints = HashSet::new();
    for capture in FETCH_SOURCE.captures_iter(text).take(64) {
        let options = capture.get(2).map_or("", |value| value.as_str());
        if options.to_ascii_lowercase().contains("method")
            && options.to_ascii_lowercase().contains("post")
            && let Some(endpoint) = capture
                .get(1)
                .and_then(|value| resolve_endpoint(source_url, value.as_str()))
        {
            endpoints.insert(endpoint);
        }
    }
    for capture in XHR_SOURCE.captures_iter(text).take(64) {
        if capture
            .get(1)
            .is_some_and(|method| method.as_str().eq_ignore_ascii_case("POST"))
            && let Some(endpoint) = capture
                .get(2)
                .and_then(|value| resolve_endpoint(source_url, value.as_str()))
        {
            endpoints.insert(endpoint);
        }
    }
    for capture in POST_HELPER.captures_iter(text).take(64) {
        if let Some(endpoint) = capture
            .get(1)
            .and_then(|value| resolve_endpoint(source_url, value.as_str()))
        {
            endpoints.insert(endpoint);
        }
    }
    endpoints
}

pub(super) async fn probe_candidates(
    observations: &mut Vec<StreamObservation>,
    target_hostname: &str,
    target_addresses: &[IpAddr],
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
    http_auth: Option<&auth::ResolvedAuth>,
    client_certificate: Option<&auth::LoadedClientCertificate>,
) {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    for observation in observations.iter().filter(|observation| {
        observation.status == StreamStatus::Candidate
            && !observation
                .evidence
                .iter()
                .any(|evidence| evidence.contains("POST-only"))
    }) {
        for endpoint in &observation.endpoints {
            let Ok(url) = Url::parse(endpoint) else {
                continue;
            };
            if matches!(url.scheme(), "http" | "https")
                && url
                    .host_str()
                    .is_some_and(|host| crawl::hostname_in_scope(target_hostname, host))
                && seen.insert((observation.kind, url.to_string()))
            {
                candidates.push((observation.kind, url));
            }
        }
    }
    candidates.truncate(64);
    let mut bounded_request = request.clone();
    bounded_request.probe_timeout = bounded_request.probe_timeout.min(Duration::from_secs(5));
    bounded_request.connection_timeout = bounded_request
        .connection_timeout
        .min(Duration::from_secs(5));
    let mut additions = Vec::new();
    for (kind, url) in candidates {
        if cancel.is_cancelled() {
            break;
        }
        let Some(hostname) = url.host_str().map(str::to_owned) else {
            continue;
        };
        let port = url
            .port_or_known_default()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let addresses = if hostname.eq_ignore_ascii_case(target_hostname) {
            target_addresses.to_vec()
        } else {
            let mut dns = DnsTrace::default();
            if resolve_host(&hostname, &mut dns).await.is_err() {
                Vec::new()
            } else {
                dns.addresses
                    .into_iter()
                    .filter(|address| non_public_reason(*address).is_none())
                    .collect()
            }
        };
        if addresses.is_empty() {
            continue;
        }
        let auth = http_auth.filter(|_| hostname.eq_ignore_ascii_case(target_hostname));
        let auth_headers = auth
            .map(|auth| vec![(auth.header_name, auth.header_value.as_str())])
            .unwrap_or_default();
        let path = url_path(&url);
        let scan = ScanContext {
            hostname: &hostname,
            request: &bounded_request,
            cancel,
            limiter,
            client_certificate: client_certificate
                .filter(|certificate| certificate.applies_to(&hostname)),
        };
        let mut response = None;
        let mut last_error = None;
        for ip in addresses {
            match single_http_request(
                ProbeContext { ip, port, scan },
                url.scheme(),
                "GET",
                &path,
                &auth_headers,
                64 * 1024,
                None,
            )
            .await
            {
                Ok(mut result) => {
                    result.url = url.to_string();
                    response = Some(result);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        match response {
            Some(response) if matches!(response.status, 401 | 403) => {
                additions.push(StreamObservation {
                    source_url: url.to_string(),
                    kind,
                    status: StreamStatus::Protected,
                    confidence: Confidence::Medium,
                    evidence: vec![format!(
                        "Bounded safe GET returned HTTP {}",
                        response.status
                    )],
                    endpoints: vec![url.to_string()],
                });
            }
            Some(response) => {
                let before = additions.len();
                ({
                    let (response, observations): (&HttpObservation, &mut Vec<StreamObservation>) =
                        (&response, &mut additions);

                    collect_body(
                        &response.url,
                        &response.headers,
                        &response.body,
                        Some(&response.framing),
                        Some(response.status),
                        observations,
                    );
                });
                let classified = additions[before..].iter().any(|observation| {
                    observation.source_url == url.as_str()
                        && observation.status == StreamStatus::Confirmed
                });
                if !classified {
                    additions.push(StreamObservation {
                        source_url: url.to_string(),
                        kind,
                        status: StreamStatus::Inconclusive,
                        confidence: Confidence::Low,
                        evidence: vec![format!(
                            "Bounded safe GET completed with HTTP {} without recognizable stream framing",
                            response.status
                        )],
                        endpoints: vec![url.to_string()],
                    });
                }
            }
            None => additions.push(StreamObservation {
                source_url: url.to_string(),
                kind,
                status: StreamStatus::Inconclusive,
                confidence: Confidence::Low,
                evidence: vec![
                    last_error.unwrap_or_else(|| "Bounded safe GET could not connect".to_owned()),
                ],
                endpoints: vec![url.to_string()],
            }),
        }
    }
    observations.extend(additions);
    merge_observations(observations);
}

pub(super) async fn websocket_checks(
    crawl: &crawl::CrawlReport,
    target_hostname: &str,
    request: &ExposureScanRequest,
    cancel: &CancellationToken,
    limiter: &ConnectionRateLimiter,
    http_auth: Option<&auth::ResolvedAuth>,
    client_certificate: Option<&auth::LoadedClientCertificate>,
) -> Vec<ServiceAccessResult> {
    let target_domain = asset_dns::registrable_domain(target_hostname);
    let mut urls = crawl
        .skipped_urls
        .iter()
        .filter(|skipped| skipped.reason == "Non-HTTP scheme")
        .filter_map(|skipped| Url::parse(&skipped.url).ok())
        .filter(|url| matches!(url.scheme(), "ws" | "wss"))
        .filter(|url| {
            let Some(host) = url.host_str() else {
                return false;
            };
            host.eq_ignore_ascii_case(target_hostname)
                || target_domain.as_deref().is_some_and(|domain| {
                    host.eq_ignore_ascii_case(domain)
                        || host
                            .to_ascii_lowercase()
                            .strip_suffix(domain)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                })
        })
        .collect::<Vec<_>>();
    urls.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    urls.dedup_by(|left, right| left == right);
    urls.truncate(32);
    let mut results = Vec::new();
    for url in urls {
        if cancel.is_cancelled() {
            break;
        }
        let hostname = url.host_str().unwrap_or_default().to_owned();
        let port = url
            .port()
            .unwrap_or(if url.scheme() == "wss" { 443 } else { 80 });
        let mut dns = DnsTrace::default();
        if resolve_host(&hostname, &mut dns).await.is_err() {
            continue;
        }
        let Some(ip) = dns
            .addresses
            .into_iter()
            .find(|address| non_public_reason(*address).is_none())
        else {
            continue;
        };
        let context = ProbeContext {
            ip,
            port,
            scan: ScanContext {
                hostname: &hostname,
                request,
                cancel,
                limiter,
                client_certificate: client_certificate
                    .filter(|certificate| certificate.applies_to(&hostname)),
            },
        };
        let path = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };
        let key = "TmFuY3lXZWJEZWJ1ZzEyMw==";
        let default_port = if url.scheme() == "wss" { 443 } else { 80 };
        let host = if hostname.contains(':') {
            format!("[{hostname}]")
        } else {
            hostname.clone()
        };
        let host = if port == default_port {
            host
        } else {
            format!("{host}:{port}")
        };
        let mut upgrade = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nancywebdebug-exposure/{}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n",
            env!("CARGO_PKG_VERSION")
        );
        if hostname.eq_ignore_ascii_case(target_hostname)
            && let Some(auth) = http_auth
        {
            upgrade.push_str(auth.header_name);
            upgrade.push_str(": ");
            upgrade.push_str(auth.header_value.as_str());
            upgrade.push_str("\r\n");
        }
        upgrade.push_str("\r\n");
        let response = websocket_upgrade_exchange(
            context,
            if url.scheme() == "wss" {
                "https"
            } else {
                "http"
            },
            upgrade.as_bytes(),
        )
        .await;
        let displayed_url = url.to_string();
        let (status, summary, mut evidence) = match response {
            Ok(response)
                if ({
                    let (response, key): (&[u8], &str) = (&response, key);
                    {
                        'inlined_valid_websocket_upgrade: {
                            let Some(header_end) =
                                response.windows(4).position(|window| window == b"\r\n\r\n")
                            else {
                                break 'inlined_valid_websocket_upgrade false;
                            };
                            let headers = String::from_utf8_lossy(&response[..header_end]);
                            if ({
                                let (response,): (&[u8],) = (response,);
                                {
                                    'inlined_http_status: {
                                        let first =
                                            match response.split(|byte| *byte == b'\n').next() {
                                                Some(value) => value,
                                                None => break 'inlined_http_status None,
                                            };
                                        let first = match std::str::from_utf8(first).ok() {
                                            Some(value) => value,
                                            None => break 'inlined_http_status None,
                                        }
                                        .trim_end_matches('\r');
                                        let mut fields = first.split_ascii_whitespace();
                                        if !matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
                                            break 'inlined_http_status None;
                                        }
                                        let status = match fields.next() {
                                            Some(value) => value,
                                            None => break 'inlined_http_status None,
                                        };
                                        if status.len() != 3
                                            || !status.bytes().all(|byte| byte.is_ascii_digit())
                                        {
                                            break 'inlined_http_status None;
                                        }
                                        let status = match status.parse().ok() {
                                            Some(value) => value,
                                            None => break 'inlined_http_status None,
                                        };
                                        (100..=599).contains(&status).then_some(status)
                                    }
                                }
                            }) != Some(101)
                                || !headers
                                    .lines()
                                    .next()
                                    .is_some_and(|line| line.starts_with("HTTP/1.1 "))
                            {
                                break 'inlined_valid_websocket_upgrade false;
                            }
                            let header = |expected: &str| {
                                headers.lines().find_map(|line| {
                                    let (name, value) =
                                        line.trim_end_matches('\r').split_once(':')?;
                                    name.eq_ignore_ascii_case(expected).then(|| value.trim())
                                })
                            };
                            let accept = header("sec-websocket-accept");
                            let upgrade = header("upgrade");
                            let connection = header("connection");
                            let mut digest = Sha1::new();
                            digest.update(key.as_bytes());
                            digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                            let expected =
                                base64::engine::general_purpose::STANDARD.encode(digest.finalize());
                            accept.is_some_and(|accept| accept == expected)
                                && upgrade
                                    .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
                                && connection.is_some_and(|value| {
                                    value
                                        .split(',')
                                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
                                })
                        }
                    }
                }) =>
            {
                (
                    ServiceAccessStatus::Offered,
                    "WebSocket upgrade succeeded; no frames were sent or consumed",
                    vec!["HTTP 101 Switching Protocols".to_owned()],
                )
            }
            Ok(response)
                if matches!(
                    {
                        let (response,): (&[u8],) = (&response,);
                        let inlined_result: Option<u16> = {
                            'inlined_http_status: {
                                let first = match response.split(|byte| *byte == b'\n').next() {
                                    Some(value) => value,
                                    None => break 'inlined_http_status None,
                                };
                                let first = match std::str::from_utf8(first).ok() {
                                    Some(value) => value,
                                    None => break 'inlined_http_status None,
                                }
                                .trim_end_matches('\r');
                                let mut fields = first.split_ascii_whitespace();
                                if !matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
                                    break 'inlined_http_status None;
                                }
                                let status = match fields.next() {
                                    Some(value) => value,
                                    None => break 'inlined_http_status None,
                                };
                                if status.len() != 3
                                    || !status.bytes().all(|byte| byte.is_ascii_digit())
                                {
                                    break 'inlined_http_status None;
                                }
                                let status = match status.parse().ok() {
                                    Some(value) => value,
                                    None => break 'inlined_http_status None,
                                };
                                (100..=599).contains(&status).then_some(status)
                            }
                        };
                        inlined_result
                    },
                    Some(401 | 403)
                ) =>
            {
                (
                    ServiceAccessStatus::Protected,
                    "WebSocket upgrade required authorization",
                    vec![format!(
                        "HTTP {}",
                        ({
                            let (response,): (&[u8],) = (&response,);
                            let inlined_result: Option<u16> = {
                                'inlined_http_status: {
                                    let first = match response.split(|byte| *byte == b'\n').next() {
                                        Some(value) => value,
                                        None => break 'inlined_http_status None,
                                    };
                                    let first = match std::str::from_utf8(first).ok() {
                                        Some(value) => value,
                                        None => break 'inlined_http_status None,
                                    }
                                    .trim_end_matches('\r');
                                    let mut fields = first.split_ascii_whitespace();
                                    if !matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
                                        break 'inlined_http_status None;
                                    }
                                    let status = match fields.next() {
                                        Some(value) => value,
                                        None => break 'inlined_http_status None,
                                    };
                                    if status.len() != 3
                                        || !status.bytes().all(|byte| byte.is_ascii_digit())
                                    {
                                        break 'inlined_http_status None;
                                    }
                                    let status = match status.parse().ok() {
                                        Some(value) => value,
                                        None => break 'inlined_http_status None,
                                    };
                                    (100..=599).contains(&status).then_some(status)
                                }
                            };
                            inlined_result
                        })
                        .unwrap_or_default()
                    )],
                )
            }
            Ok(response) => (
                ServiceAccessStatus::Inconclusive,
                "The discovered URL did not accept a WebSocket upgrade",
                vec![
                    ({
                        let (response,): (&[u8],) = (&response,);
                        let inlined_result: Option<u16> = {
                            'inlined_http_status: {
                                let first = match response.split(|byte| *byte == b'\n').next() {
                                    Some(value) => value,
                                    None => break 'inlined_http_status None,
                                };
                                let first = match std::str::from_utf8(first).ok() {
                                    Some(value) => value,
                                    None => break 'inlined_http_status None,
                                }
                                .trim_end_matches('\r');
                                let mut fields = first.split_ascii_whitespace();
                                if !matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
                                    break 'inlined_http_status None;
                                }
                                let status = match fields.next() {
                                    Some(value) => value,
                                    None => break 'inlined_http_status None,
                                };
                                if status.len() != 3
                                    || !status.bytes().all(|byte| byte.is_ascii_digit())
                                {
                                    break 'inlined_http_status None;
                                }
                                let status = match status.parse().ok() {
                                    Some(value) => value,
                                    None => break 'inlined_http_status None,
                                };
                                (100..=599).contains(&status).then_some(status)
                            }
                        };
                        inlined_result
                    })
                    .map(|status| format!("HTTP {status}"))
                    .unwrap_or_else(|| "Invalid HTTP response".to_owned()),
                ],
            ),
            Err(error) => (
                ServiceAccessStatus::Inconclusive,
                "The discovered WebSocket upgrade could not be completed",
                vec![error],
            ),
        };
        evidence.insert(0, format!("URL: {displayed_url}"));
        results.push(ServiceAccessResult {
            ip,
            port,
            transport: TransportProtocol::Tcp,
            service: ServiceKind::WebSocket,
            method: "HTTP Upgrade only".to_owned(),
            status,
            summary: summary.to_owned(),
            evidence,
        });
    }
    results
}

pub(super) fn include_websocket_results(
    observations: &mut Vec<StreamObservation>,
    results: &[ServiceAccessResult],
) {
    for result in results
        .iter()
        .filter(|result| result.service == ServiceKind::WebSocket)
    {
        let source_url = result
            .evidence
            .iter()
            .find_map(|evidence| evidence.strip_prefix("URL: "))
            .unwrap_or("Discovered WebSocket endpoint")
            .to_owned();
        let status = match result.status {
            ServiceAccessStatus::Offered => StreamStatus::Confirmed,
            ServiceAccessStatus::Protected => StreamStatus::Protected,
            _ => StreamStatus::Inconclusive,
        };
        observations.push(StreamObservation {
            source_url: source_url.clone(),
            kind: StreamKind::WebSocket,
            status,
            confidence: if status == StreamStatus::Confirmed {
                Confidence::High
            } else {
                Confidence::Medium
            },
            evidence: result.evidence.clone(),
            endpoints: vec![source_url],
        });
    }
    merge_observations(observations);
}
