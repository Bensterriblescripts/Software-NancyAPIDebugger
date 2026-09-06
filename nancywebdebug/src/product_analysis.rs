use super::*;
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::{
    BufferQueue, EndTag, StartTag, Tag, TagToken, Token, TokenSink, TokenSinkResult, Tokenizer,
    states::RawKind,
};
use std::cell::RefCell;

#[derive(Clone)]
struct ProductSignal {
    observations: Vec<TechnologyEvidence>,
    source: String,
    evidence: String,
    kind: ProductSignalKind,
    version: Option<String>,
}

#[derive(Clone, Copy)]
enum ProductSignalKind {
    Validated,
    CatalogHigh,
    StrongExplicit,
    Strong,
    Indirect,
}

pub(super) fn apply_product_rules(endpoint: &mut EndpointScan, cancel: &CancellationToken) {
    exposure_probe::product_identification::record_captured(endpoint, cancel);
    let evidence_response: Option<&HttpObservation> = None;
    let mut web_observations = HashMap::<String, Vec<TechnologyEvidence>>::new();
    let mut signals: HashMap<(&'static str, ProductLayer), Vec<ProductSignal>> = HashMap::new();
    for response in &endpoint.http {
        let evidence_response = Some(response);
        if cancel.is_cancelled() {
            return;
        }
        let web_detections = detect_web_servers(
            response
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            &response.body,
            Some(response.status),
            Some(&response.url),
        );
        for detection in web_detections {
            for mut record in detection.observations {
                technology_evidence::locate(&mut record, &response.url, Some(std::net::SocketAddr::new(endpoint.ip, endpoint.port).to_string()), Some(&response.method), Some(response.status), response.body_truncated);
                web_observations.entry(detection.product.to_ascii_lowercase()).or_default().push(record);
            }
            let layer = match detection.role {
                WebProductRole::Server => ProductLayer::Server,
                WebProductRole::Proxy => ProductLayer::Proxy,
                WebProductRole::Framework => ProductLayer::Framework,
                WebProductRole::Runtime => ProductLayer::Runtime,
            };
            let kind = match detection.confidence {
                FingerprintConfidence::High => ProductSignalKind::CatalogHigh,
                FingerprintConfidence::Medium => ProductSignalKind::StrongExplicit,
            };
            for evidence in detection.evidence {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        &mut signals,
                        detection.product,
                        layer,
                        format!("web-server:{}", detection.identifier),
                        evidence,
                        kind,
                        detection.version.clone(),
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
        }
    }
    for response in &endpoint.http {
        let evidence_response = Some(response);
        if cancel.is_cancelled() {
            return;
        }
        for (name, value) in &response.headers {
            let header = name.to_ascii_lowercase();
            let lower = value.to_ascii_lowercase();
            if header == "server" {
                for (needle, product, layer) in [
                    ("cloudflare", "Cloudflare", ProductLayer::Cdn),
                    ("gws", "Google Frontend", ProductLayer::Cloud),
                    ("google frontend", "Google Frontend", ProductLayer::Cloud),
                ] {
                    if lower.contains(needle) {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                &mut signals,
                                product,
                                layer,
                                "header:server".to_owned(),
                                format!("Server: {value}"),
                                ProductSignalKind::StrongExplicit,
                                ({
                                    let (value, product): (&str, &str) = (value, needle);
                                    let inlined_result: Option<String> = {
                                        'inlined_extract_version: {
                                            let lower = value.to_ascii_lowercase();
                                            let index =
                                                match lower.find(&product.to_ascii_lowercase()) {
                                                    Some(value) => value,
                                                    None => break 'inlined_extract_version None,
                                                } + product.len();
                                            let remainder = value[index..]
                                                .trim_start_matches(['/', ' ', '-', '_']);
                                            let version = remainder
                                                .chars()
                                                .take_while(|character| {
                                                    character.is_ascii_alphanumeric()
                                                        || matches!(character, '.' | '-' | '_')
                                                })
                                                .collect::<String>();
                                            if version
                                                .chars()
                                                .any(|character| character.is_ascii_digit())
                                            {
                                                Some(version)
                                            } else {
                                                None
                                            }
                                        }
                                    };
                                    inlined_result
                                }),
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                }
                if lower.contains("amazons3") || lower.contains("amazon") {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            &mut signals,
                            "AWS",
                            ProductLayer::Cloud,
                            "header:server".to_owned(),
                            format!("Server: {value}"),
                            ProductSignalKind::StrongExplicit,
                            ({
                                let (value, product): (&str, &str) = (value, "amazon");
                                let inlined_result: Option<String> = {
                                    'inlined_extract_version: {
                                        let lower = value.to_ascii_lowercase();
                                        let index = match lower.find(&product.to_ascii_lowercase())
                                        {
                                            Some(value) => value,
                                            None => break 'inlined_extract_version None,
                                        } + product.len();
                                        let remainder =
                                            value[index..].trim_start_matches(['/', ' ', '-', '_']);
                                        let version = remainder
                                            .chars()
                                            .take_while(|character| {
                                                character.is_ascii_alphanumeric()
                                                    || matches!(character, '.' | '-' | '_')
                                            })
                                            .collect::<String>();
                                        if version
                                            .chars()
                                            .any(|character| character.is_ascii_digit())
                                        {
                                            Some(version)
                                        } else {
                                            None
                                        }
                                    }
                                };
                                inlined_result
                            }),
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
            }
            if header == "x-powered-by" {
                for (needle, product, layer) in [
                    ("express", "Express", ProductLayer::Framework),
                    ("asp.net", "ASP.NET", ProductLayer::Framework),
                    ("php", "PHP", ProductLayer::Runtime),
                ] {
                    if {
                        let (value, needle): (&str, &str) = (&lower, needle);
                        {
                            value.match_indices(needle).any(|(start, _)| {
                                let end = start + needle.len();
                                !value[..start]
                                    .chars()
                                    .next_back()
                                    .is_some_and(|character| character.is_ascii_alphanumeric())
                                    && !value[end..]
                                        .chars()
                                        .next()
                                        .is_some_and(|character| character.is_ascii_alphanumeric())
                            })
                        }
                    } {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                &mut signals,
                                product,
                                layer,
                                "header:x-powered-by".to_owned(),
                                format!("X-Powered-By: {value}"),
                                ProductSignalKind::StrongExplicit,
                                ({
                                    let (value, product): (&str, &str) = (value, needle);
                                    let inlined_result: Option<String> = {
                                        'inlined_extract_version: {
                                            let lower = value.to_ascii_lowercase();
                                            let index =
                                                match lower.find(&product.to_ascii_lowercase()) {
                                                    Some(value) => value,
                                                    None => break 'inlined_extract_version None,
                                                } + product.len();
                                            let remainder = value[index..]
                                                .trim_start_matches(['/', ' ', '-', '_']);
                                            let version = remainder
                                                .chars()
                                                .take_while(|character| {
                                                    character.is_ascii_alphanumeric()
                                                        || matches!(character, '.' | '-' | '_')
                                                })
                                                .collect::<String>();
                                            if version
                                                .chars()
                                                .any(|character| character.is_ascii_digit())
                                            {
                                                Some(version)
                                            } else {
                                                None
                                            }
                                        }
                                    };
                                    inlined_result
                                }),
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                }
            }
            if matches!(header.as_str(), "server" | "x-powered-by" | "x-runtime")
                && lower
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .any(|token| token == "rust")
            {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        &mut signals,
                        "Rust",
                        ProductLayer::Runtime,
                        format!("header:{header}"),
                        format!("{name}: {value}"),
                        ProductSignalKind::StrongExplicit,
                        ({
                            let (value, product): (&str, &str) = (value, "rust");
                            let inlined_result: Option<String> = {
                                'inlined_extract_version: {
                                    let lower = value.to_ascii_lowercase();
                                    let index = match lower.find(&product.to_ascii_lowercase()) {
                                        Some(value) => value,
                                        None => break 'inlined_extract_version None,
                                    } + product.len();
                                    let remainder =
                                        value[index..].trim_start_matches(['/', ' ', '-', '_']);
                                    let version = remainder
                                        .chars()
                                        .take_while(|character| {
                                            character.is_ascii_alphanumeric()
                                                || matches!(character, '.' | '-' | '_')
                                        })
                                        .collect::<String>();
                                    if version.chars().any(|character| character.is_ascii_digit()) {
                                        Some(version)
                                    } else {
                                        None
                                    }
                                }
                            };
                            inlined_result
                        }),
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
            for (matched, product, layer) in [
                (
                    matches!(header.as_str(), "cf-cache-status" | "cf-request-id"),
                    "Cloudflare",
                    ProductLayer::Cdn,
                ),
                (
                    header.starts_with("x-amz-") || header.starts_with("x-amzn-"),
                    "AWS",
                    ProductLayer::Cloud,
                ),
                (
                    header.starts_with("x-azure-")
                        || header.starts_with("x-ms-")
                        || (header == "set-cookie" && lower.contains("arraffinity")),
                    "Azure",
                    ProductLayer::Cloud,
                ),
                (
                    matches!(
                        header.as_str(),
                        "x-cloud-trace-context" | "x-goog-generation"
                    ),
                    "Google Frontend",
                    ProductLayer::Cloud,
                ),
                (
                    header == "x-varnish" || (header == "via" && lower.contains("varnish")),
                    "Varnish",
                    ProductLayer::Proxy,
                ),
            ] {
                if matched {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            &mut signals,
                            product,
                            layer,
                            format!("header:{header}"),
                            format!("{name}: {value}"),
                            ProductSignalKind::Strong,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
            }
            if header == "set-cookie" && lower.contains("jsessionid") {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        &mut signals,
                        "Apache Tomcat",
                        ProductLayer::Server,
                        "cookie:jsessionid".to_owned(),
                        "JSESSIONID cookie".to_owned(),
                        ProductSignalKind::Indirect,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        &mut signals,
                        "Spring",
                        ProductLayer::Framework,
                        "cookie:jsessionid".to_owned(),
                        "JSESSIONID cookie".to_owned(),
                        ProductSignalKind::Indirect,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
        }
        let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
        if body.contains("whitelabel error page") || body.contains("spring boot") {
            ({
                let (signals, name, layer, source, evidence, kind, version): (
                    &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                    &'static str,
                    ProductLayer,
                    String,
                    String,
                    ProductSignalKind,
                    Option<String>,
                ) = (
                    &mut signals,
                    "Spring",
                    ProductLayer::Framework,
                    "body:spring-marker".to_owned(),
                    "Spring page marker".to_owned(),
                    ProductSignalKind::Indirect,
                    None,
                );

                signals
                    .entry((name, layer))
                    .or_default()
                    .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                        source,
                        evidence,
                        kind,
                        version,
                    });
            });
        }
        if body.contains("apache tomcat") {
            ({
                let (signals, name, layer, source, evidence, kind, version): (
                    &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                    &'static str,
                    ProductLayer,
                    String,
                    String,
                    ProductSignalKind,
                    Option<String>,
                ) = (
                    &mut signals,
                    "Apache Tomcat",
                    ProductLayer::Server,
                    "body:tomcat-marker".to_owned(),
                    "Apache Tomcat page marker".to_owned(),
                    ProductSignalKind::Indirect,
                    None,
                );

                signals
                    .entry((name, layer))
                    .or_default()
                    .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                        source,
                        evidence,
                        kind,
                        version,
                    });
            });
        }
        ({
            let (response, lower, signals): (
                &HttpObservation,
                &str,
                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
            ) = (response, &body, &mut signals);

            for (cookie, product, source) in [
                ("REVEL_SESSION", "Revel", "revel:session-cookie"),
                ("REVEL_FLASH", "Revel", "revel:flash-cookie"),
                ("beegosessionID", "Beego", "beego:session-cookie"),
                ("csrftoken", "Django", "django:csrf-cookie"),
            ] {
                if ({
                    let (response, expected): (&HttpObservation, &str) = (response, cookie);
                    let inlined_result: Option<String> = {
                        ({
                            let (response, name): (&crate::HttpObservation, &str) =
                                (response, "set-cookie");
                            response
                                .headers
                                .iter()
                                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                                .map(|(_, value)| value.as_str())
                        })
                        .find_map(|value| {
                            let pair = value.split(';').next()?.trim();
                            let (name, _) = pair.split_once('=')?;
                            name.trim()
                                .eq_ignore_ascii_case(expected)
                                .then(|| name.trim().to_owned())
                        })
                    };
                    inlined_result
                })
                .is_some()
                {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            product,
                            ProductLayer::Framework,
                            source.to_owned(),
                            format!("Framework-specific {cookie} cookie"),
                            ProductSignalKind::StrongExplicit,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
            }
            if lower.contains("name=\"csrfmiddlewaretoken\"")
                || lower.contains("name='csrfmiddlewaretoken'")
            {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "Django",
                        ProductLayer::Framework,
                        "django:csrf-form".to_owned(),
                        "Django csrfmiddlewaretoken form control".to_owned(),
                        ProductSignalKind::StrongExplicit,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
            if lower.contains("csrf verification failed. request aborted") {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "Django",
                        ProductLayer::Framework,
                        "django:csrf-error".to_owned(),
                        "Distinctive Django CSRF failure page".to_owned(),
                        ProductSignalKind::CatalogHigh,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
            if {
                let (response,): (&HttpObservation,) = (response,);
                crate::web_server::is_fastapi_branded_document(&response.url, &response.body)
            } {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "FastAPI",
                        ProductLayer::Framework,
                        "fastapi:branded-api-document".to_owned(),
                        format!(
                            "FastAPI-branded OpenAPI or Swagger content at {}",
                            response.url
                        ),
                        ProductSignalKind::CatalogHigh,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
        });
    }
    ({
        let (endpoint, signals): (
            &EndpointScan,
            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
        ) = (endpoint, &mut signals);

        for baseline in endpoint.http.iter().filter(|response| {
            response.method.eq_ignore_ascii_case("GET")
                && ({
                    let (response,): (&HttpObservation,) = (response,);
                    {
                        ({
                            let (response,): (&HttpObservation,) = (response,);
                            let inlined_result: Option<String> = {
                                Url::parse(&response.url)
                                    .ok()
                                    .map(|url| url.path().to_owned())
                            };
                            inlined_result
                        })
                        .is_some_and(|path| {
                            path.strip_prefix("/nancy-exposure-not-found-")
                                .is_some_and(|suffix| {
                                    !suffix.is_empty()
                                        && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
                                })
                        })
                    }
                })
        }) {
            let evidence_response = Some(baseline);
            if baseline.status != 404 || baseline.body_truncated {
                continue;
            }
            let root_options = endpoint.http.iter().filter(|response| {
                response.method.eq_ignore_ascii_case("OPTIONS")
                    && ({
                        let (response,): (&HttpObservation,) = (response,);
                        let inlined_result: Option<String> = {
                            Url::parse(&response.url)
                                .ok()
                                .map(|url| url.path().to_owned())
                        };
                        inlined_result
                    })
                    .as_deref()
                        == Some("/")
                    && ({
                        let (left, right): (&HttpObservation, &HttpObservation) =
                            (baseline, response);
                        {
                            Url::parse(&left.url)
                                .ok()
                                .zip(Url::parse(&right.url).ok())
                                .is_some_and(|(left, right)| same_origin(&left, &right))
                        }
                    })
            });

            if baseline.body.is_empty() {
                for options in root_options {
                    let evidence_response = Some(options);
                    if options.status != 405 || options.body_truncated || !options.body.is_empty() {
                        continue;
                    }
                    if {
                        let (response, name, expected): (&HttpObservation, &str, &str) =
                            (options, "allow", "GET,HEAD");
                        {
                            let mut values = {
                                let (response, name): (&crate::HttpObservation, &str) =
                                    (response, name);
                                response
                                    .headers
                                    .iter()
                                    .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                                    .map(|(_, value)| value.as_str())
                            };
                            values.next() == Some(expected) && values.next().is_none()
                        }
                    } {
                        ({
                            let (signals, backend, backend_layer, runtime, source, evidence, kind,): (& mut HashMap < (& 'static str , ProductLayer) , Vec < ProductSignal > >, & 'static str, ProductLayer, & 'static str, & 'static str, & str, ProductSignalKind,) = (signals, "Axum", ProductLayer::Server, "Rust", "behavior:axum-default-routing", "Random-path GET returned Axum-style empty 404 and OPTIONS / returned empty 405 with Allow: GET,HEAD", ProductSignalKind::StrongExplicit,);

                            for (name, layer) in
                                [(backend, backend_layer), (runtime, ProductLayer::Runtime)]
                            {
                                ({
                                    let (signals, name, layer, source, evidence, kind, version): (
                                        &mut HashMap<
                                            (&'static str, ProductLayer),
                                            Vec<ProductSignal>,
                                        >,
                                        &'static str,
                                        ProductLayer,
                                        String,
                                        String,
                                        ProductSignalKind,
                                        Option<String>,
                                    ) = (
                                        signals,
                                        name,
                                        layer,
                                        source.to_owned(),
                                        evidence.to_owned(),
                                        kind,
                                        None,
                                    );

                                    signals
                                        .entry((name, layer))
                                        .or_default()
                                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                            source,
                                            evidence,
                                            kind,
                                            version,
                                        });
                                });
                            }
                        });
                    } else if {
                        let (response,): (&HttpObservation,) = (options,);
                        {
                            'inlined_has_actix_allow_header: {
                                let mut values = {
                                    let (response, name): (&crate::HttpObservation, &str) =
                                        (response, "allow");
                                    response
                                        .headers
                                        .iter()
                                        .filter(move |(header, _)| {
                                            header.eq_ignore_ascii_case(name)
                                        })
                                        .map(|(_, value)| value.as_str())
                                };
                                let Some(value) = values.next() else {
                                    break 'inlined_has_actix_allow_header false;
                                };
                                if values.next().is_some() || !value.contains(", ") {
                                    break 'inlined_has_actix_allow_header false;
                                }
                                let methods = value.split(", ").collect::<Vec<_>>();
                                methods.len() >= 2
                                    && methods.iter().all(|method| {
                                        matches!(
                                            *method,
                                            "GET"
                                                | "HEAD"
                                                | "POST"
                                                | "PUT"
                                                | "DELETE"
                                                | "CONNECT"
                                                | "OPTIONS"
                                                | "TRACE"
                                                | "PATCH"
                                        )
                                    })
                            }
                        }
                    } {
                        ({
                            let (signals, backend, backend_layer, runtime, source, evidence, kind,): (& mut HashMap < (& 'static str , ProductLayer) , Vec < ProductSignal > >, & 'static str, ProductLayer, & 'static str, & 'static str, & str, ProductSignalKind,) = (signals, "Actix Web", ProductLayer::Server, "Rust", "behavior:actix-default-routing", "Random-path GET returned empty 404 and OPTIONS / returned an Actix-style empty 405 with a spaced Allow header", ProductSignalKind::StrongExplicit,);

                            for (name, layer) in
                                [(backend, backend_layer), (runtime, ProductLayer::Runtime)]
                            {
                                ({
                                    let (signals, name, layer, source, evidence, kind, version): (
                                        &mut HashMap<
                                            (&'static str, ProductLayer),
                                            Vec<ProductSignal>,
                                        >,
                                        &'static str,
                                        ProductLayer,
                                        String,
                                        String,
                                        ProductSignalKind,
                                        Option<String>,
                                    ) = (
                                        signals,
                                        name,
                                        layer,
                                        source.to_owned(),
                                        evidence.to_owned(),
                                        kind,
                                        None,
                                    );

                                    signals
                                        .entry((name, layer))
                                        .or_default()
                                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                            source,
                                            evidence,
                                            kind,
                                            version,
                                        });
                                });
                            }
                        });
                    }
                }
            } else if {
                let (response,): (&HttpObservation,) = (baseline,);
                {
                    response.body == ROCKET_NOT_FOUND
                        && ({
                            let (response, expected): (&HttpObservation, &str) =
                                (response, "text/html; charset=utf-8");
                            {
                                {
                                    let (response, name, expected): (&HttpObservation, &str, &str) =
                                        (response, "content-type", expected);
                                    {
                                        let mut values = {
                                            let (response, name): (&crate::HttpObservation, &str) =
                                                (response, name);
                                            response
                                                .headers
                                                .iter()
                                                .filter(move |(header, _)| {
                                                    header.eq_ignore_ascii_case(name)
                                                })
                                                .map(|(_, value)| value.as_str())
                                        };
                                        values.next().is_some_and(|value| {
                                            value.eq_ignore_ascii_case(expected)
                                        }) && values.next().is_none()
                                    }
                                }
                            }
                        })
                }
            } {
                ({
                    let (signals, backend, backend_layer, runtime, source, evidence, kind): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        &'static str,
                        &'static str,
                        &str,
                        ProductSignalKind,
                    ) = (
                        signals,
                        "Rocket",
                        ProductLayer::Server,
                        "Rust",
                        "behavior:rocket-default-catcher",
                        "Random-path GET returned Rocket's complete default 404 catcher document",
                        ProductSignalKind::StrongExplicit,
                    );

                    for (name, layer) in
                        [(backend, backend_layer), (runtime, ProductLayer::Runtime)]
                    {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                name,
                                layer,
                                source.to_owned(),
                                evidence.to_owned(),
                                kind,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                });
            } else if {
                let (response,): (&HttpObservation,) = (baseline,);
                {
                    response.body == b"404 page not found\n"
                        && ({
                            let (response, expected): (&HttpObservation, &str) =
                                (response, "text/plain; charset=utf-8");
                            {
                                {
                                    let (response, name, expected): (&HttpObservation, &str, &str) =
                                        (response, "content-type", expected);
                                    {
                                        let mut values = {
                                            let (response, name): (&crate::HttpObservation, &str) =
                                                (response, name);
                                            response
                                                .headers
                                                .iter()
                                                .filter(move |(header, _)| {
                                                    header.eq_ignore_ascii_case(name)
                                                })
                                                .map(|(_, value)| value.as_str())
                                        };
                                        values.next().is_some_and(|value| {
                                            value.eq_ignore_ascii_case(expected)
                                        }) && values.next().is_none()
                                    }
                                }
                            }
                        })
                        && ({
                            let (response, name, expected): (&HttpObservation, &str, &str) =
                                (response, "x-content-type-options", "nosniff");
                            {
                                let mut values = {
                                    let (response, name): (&crate::HttpObservation, &str) =
                                        (response, name);
                                    response
                                        .headers
                                        .iter()
                                        .filter(move |(header, _)| {
                                            header.eq_ignore_ascii_case(name)
                                        })
                                        .map(|(_, value)| value.as_str())
                                };
                                values
                                    .next()
                                    .is_some_and(|value| value.eq_ignore_ascii_case(expected))
                                    && values.next().is_none()
                            }
                        })
                }
            } {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "Go",
                        ProductLayer::Runtime,
                        "behavior:go-net-http-not-found".to_owned(),
                        "Random-path GET returned the canonical Go net/http 404 response"
                            .to_owned(),
                        ProductSignalKind::StrongExplicit,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            } else if ({
                let (response,): (&HttpObservation,) = (baseline,);
                {
                    response.status == 404
                        && !response.body_truncated
                        && response.body == b"404 page not found"
                        && ({
                            let (response, expected): (&HttpObservation, &str) =
                                (response, "text/plain");
                            {
                                {
                                    let (response, name, expected): (&HttpObservation, &str, &str) =
                                        (response, "content-type", expected);
                                    {
                                        let mut values = {
                                            let (response, name): (&crate::HttpObservation, &str) =
                                                (response, name);
                                            response
                                                .headers
                                                .iter()
                                                .filter(move |(header, _)| {
                                                    header.eq_ignore_ascii_case(name)
                                                })
                                                .map(|(_, value)| value.as_str())
                                        };
                                        values.next().is_some_and(|value| {
                                            value.eq_ignore_ascii_case(expected)
                                        }) && values.next().is_none()
                                    }
                                }
                            }
                        })
                }
            }) && endpoint.http.iter().any(|response| {
                response.method.eq_ignore_ascii_case("OPTIONS")
                    && ({
                        let (response,): (&HttpObservation,) = (response,);
                        let inlined_result: Option<String> = {
                            Url::parse(&response.url)
                                .ok()
                                .map(|url| url.path().to_owned())
                        };
                        inlined_result
                    })
                    .as_deref()
                        == Some("/")
                    && ({
                        let (left, right): (&HttpObservation, &HttpObservation) =
                            (baseline, response);
                        {
                            Url::parse(&left.url)
                                .ok()
                                .zip(Url::parse(&right.url).ok())
                                .is_some_and(|(left, right)| same_origin(&left, &right))
                        }
                    })
                    && ({
                        let (response,): (&HttpObservation,) = (response,);
                        {
                            response.status == 404
                                && !response.body_truncated
                                && response.body == b"404 page not found"
                                && ({
                                    let (response, expected): (&HttpObservation, &str) =
                                        (response, "text/plain");
                                    {
                                        {
                                            let (response, name, expected): (
                                                &HttpObservation,
                                                &str,
                                                &str,
                                            ) = (response, "content-type", expected);
                                            {
                                                let mut values = {
                                                    let (response, name): (
                                                        &crate::HttpObservation,
                                                        &str,
                                                    ) = (response, name);
                                                    response
                                                        .headers
                                                        .iter()
                                                        .filter(move |(header, _)| {
                                                            header.eq_ignore_ascii_case(name)
                                                        })
                                                        .map(|(_, value)| value.as_str())
                                                };
                                                values.next().is_some_and(|value| {
                                                    value.eq_ignore_ascii_case(expected)
                                                }) && values.next().is_none()
                                            }
                                        }
                                    }
                                })
                        }
                    })
            }) {
                ({
                    let (signals, backend, backend_layer, runtime, source, evidence, kind): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        &'static str,
                        &'static str,
                        &str,
                        ProductSignalKind,
                    ) = (
                        signals,
                        "Gin",
                        ProductLayer::Framework,
                        "Go",
                        "behavior:gin-default-routing",
                        "Random-path GET and OPTIONS / returned Gin's exact default no-route response",
                        ProductSignalKind::StrongExplicit,
                    );

                    for (name, layer) in
                        [(backend, backend_layer), (runtime, ProductLayer::Runtime)]
                    {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                name,
                                layer,
                                source.to_owned(),
                                evidence.to_owned(),
                                kind,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                });
            } else if ({
                let (response,): (&HttpObservation,) = (baseline,);
                {
                    'inlined_fiber_not_found: {
                        let Some(path) = ({
                            let (response,): (&HttpObservation,) = (response,);
                            let inlined_result: Option<String> = {
                                Url::parse(&response.url)
                                    .ok()
                                    .map(|url| url.path().to_owned())
                            };
                            inlined_result
                        }) else {
                            break 'inlined_fiber_not_found false;
                        };
                        response.body == format!("Cannot GET {path}").as_bytes()
                            && ({
                                let (response, expected): (&HttpObservation, &str) =
                                    (response, "text/plain; charset=utf-8");
                                {
                                    {
                                        let (response, name, expected): (
                                            &HttpObservation,
                                            &str,
                                            &str,
                                        ) = (response, "content-type", expected);
                                        {
                                            let mut values = {
                                                let (response, name): (
                                                    &crate::HttpObservation,
                                                    &str,
                                                ) = (response, name);
                                                response
                                                    .headers
                                                    .iter()
                                                    .filter(move |(header, _)| {
                                                        header.eq_ignore_ascii_case(name)
                                                    })
                                                    .map(|(_, value)| value.as_str())
                                            };
                                            values.next().is_some_and(|value| {
                                                value.eq_ignore_ascii_case(expected)
                                            }) && values.next().is_none()
                                        }
                                    }
                                }
                            })
                    }
                }
            }) && endpoint.http.iter().any(|response| {
                ({
                    let (left, right): (&HttpObservation, &HttpObservation) = (baseline, response);
                    {
                        Url::parse(&left.url)
                            .ok()
                            .zip(Url::parse(&right.url).ok())
                            .is_some_and(|(left, right)| same_origin(&left, &right))
                    }
                }) && ({
                    let (response, name): (&crate::HttpObservation, &str) = (response, "server");
                    response
                        .headers
                        .iter()
                        .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.as_str())
                })
                .any(|value| {
                    let (value, needle): (&str, &str) = (&value.to_ascii_lowercase(), "fasthttp");
                    {
                        value.match_indices(needle).any(|(start, _)| {
                            let end = start + needle.len();
                            !value[..start]
                                .chars()
                                .next_back()
                                .is_some_and(|character| character.is_ascii_alphanumeric())
                                && !value[end..]
                                    .chars()
                                    .next()
                                    .is_some_and(|character| character.is_ascii_alphanumeric())
                        })
                    }
                })
            }) {
                ({
                    let (signals, backend, backend_layer, runtime, source, evidence, kind): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        &'static str,
                        &'static str,
                        &str,
                        ProductSignalKind,
                    ) = (
                        signals,
                        "Fiber",
                        ProductLayer::Framework,
                        "Go",
                        "behavior:fiber-fasthttp-routing",
                        "Random-path GET returned Fiber's dynamic Cannot GET response and the origin exposed fasthttp",
                        ProductSignalKind::StrongExplicit,
                    );

                    for (name, layer) in
                        [(backend, backend_layer), (runtime, ProductLayer::Runtime)]
                    {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                name,
                                layer,
                                source.to_owned(),
                                evidence.to_owned(),
                                kind,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                });
            } else if {
                let (response,): (&HttpObservation,) = (baseline,);
                {
                    response.body == b"{\"message\":\"Not Found\"}\n"
                        && ({
                            let (response, expected): (&HttpObservation, &str) =
                                (response, "application/json; charset=UTF-8");
                            {
                                {
                                    let (response, name, expected): (&HttpObservation, &str, &str) =
                                        (response, "content-type", expected);
                                    {
                                        let mut values = {
                                            let (response, name): (&crate::HttpObservation, &str) =
                                                (response, name);
                                            response
                                                .headers
                                                .iter()
                                                .filter(move |(header, _)| {
                                                    header.eq_ignore_ascii_case(name)
                                                })
                                                .map(|(_, value)| value.as_str())
                                        };
                                        values.next().is_some_and(|value| {
                                            value.eq_ignore_ascii_case(expected)
                                        }) && values.next().is_none()
                                    }
                                }
                            }
                        })
                }
            } {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "Go",
                        ProductLayer::Runtime,
                        "behavior:echo-default-error-envelope".to_owned(),
                        "Random-path GET returned Echo's default JSON error envelope".to_owned(),
                        ProductSignalKind::Strong,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            } else if {
                let (response,): (&HttpObservation,) = (baseline,);
                {
                    response.body == b"{\"detail\":\"Not Found\"}"
                        && ({
                            let (response, expected): (&HttpObservation, &str) =
                                (response, "application/json");
                            {
                                {
                                    let (response, name, expected): (&HttpObservation, &str, &str) =
                                        (response, "content-type", expected);
                                    {
                                        let mut values = {
                                            let (response, name): (&crate::HttpObservation, &str) =
                                                (response, name);
                                            response
                                                .headers
                                                .iter()
                                                .filter(move |(header, _)| {
                                                    header.eq_ignore_ascii_case(name)
                                                })
                                                .map(|(_, value)| value.as_str())
                                        };
                                        values.next().is_some_and(|value| {
                                            value.eq_ignore_ascii_case(expected)
                                        }) && values.next().is_none()
                                    }
                                }
                            }
                        })
                }
            } {
                ({
                    let (signals, name, layer, source, evidence, kind, version,): (& mut HashMap < (& 'static str , ProductLayer) , Vec < ProductSignal > >, & 'static str, ProductLayer, String, String, ProductSignalKind, Option < String >,) = (signals, "Python", ProductLayer::Runtime, "behavior:starlette-default-error-envelope".to_owned(), "Random-path GET returned the generic FastAPI/Starlette JSON error envelope"
                    .to_owned(), ProductSignalKind::Strong, None,);

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            } else if {
                let (response,): (&HttpObservation,) = (baseline,);
                {
                    response.body == WERKZEUG_NOT_FOUND
                        && ({
                            let (response, expected): (&HttpObservation, &str) =
                                (response, "text/html; charset=utf-8");
                            {
                                {
                                    let (response, name, expected): (&HttpObservation, &str, &str) =
                                        (response, "content-type", expected);
                                    {
                                        let mut values = {
                                            let (response, name): (&crate::HttpObservation, &str) =
                                                (response, name);
                                            response
                                                .headers
                                                .iter()
                                                .filter(move |(header, _)| {
                                                    header.eq_ignore_ascii_case(name)
                                                })
                                                .map(|(_, value)| value.as_str())
                                        };
                                        values.next().is_some_and(|value| {
                                            value.eq_ignore_ascii_case(expected)
                                        }) && values.next().is_none()
                                    }
                                }
                            }
                        })
                }
            } {
                ({
                    let (signals, backend, backend_layer, runtime, source, evidence, kind): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        &'static str,
                        &'static str,
                        &str,
                        ProductSignalKind,
                    ) = (
                        signals,
                        "Werkzeug",
                        ProductLayer::Server,
                        "Python",
                        "behavior:werkzeug-default-not-found",
                        "Random-path GET returned Werkzeug's complete default 404 exception page",
                        ProductSignalKind::StrongExplicit,
                    );

                    for (name, layer) in
                        [(backend, backend_layer), (runtime, ProductLayer::Runtime)]
                    {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                name,
                                layer,
                                source.to_owned(),
                                evidence.to_owned(),
                                kind,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                });
            } else if {
                let (response,): (&HttpObservation,) = (baseline,);
                {
                    response.body == DJANGO_NOT_FOUND
                        && ({
                            let (response, expected): (&HttpObservation, &str) =
                                (response, "text/html; charset=utf-8");
                            {
                                {
                                    let (response, name, expected): (&HttpObservation, &str, &str) =
                                        (response, "content-type", expected);
                                    {
                                        let mut values = {
                                            let (response, name): (&crate::HttpObservation, &str) =
                                                (response, name);
                                            response
                                                .headers
                                                .iter()
                                                .filter(move |(header, _)| {
                                                    header.eq_ignore_ascii_case(name)
                                                })
                                                .map(|(_, value)| value.as_str())
                                        };
                                        values.next().is_some_and(|value| {
                                            value.eq_ignore_ascii_case(expected)
                                        }) && values.next().is_none()
                                    }
                                }
                            }
                        })
                }
            } {
                ({
                    let (signals, backend, backend_layer, runtime, source, evidence, kind): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        &'static str,
                        &'static str,
                        &str,
                        ProductSignalKind,
                    ) = (
                        signals,
                        "Django",
                        ProductLayer::Framework,
                        "Python",
                        "behavior:django-production-not-found",
                        "Random-path GET returned Django's complete production 404 page",
                        ProductSignalKind::StrongExplicit,
                    );

                    for (name, layer) in
                        [(backend, backend_layer), (runtime, ProductLayer::Runtime)]
                    {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                name,
                                layer,
                                source.to_owned(),
                                evidence.to_owned(),
                                kind,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                });
            }
        }

        ({
            let (endpoint, signals): (
                &EndpointScan,
                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
            ) = (endpoint, signals);

            let mut cookie_names = endpoint
                .http
                .iter()
                .flat_map(|response| {
                    let (response, name): (&crate::HttpObservation, &str) =
                        (response, "set-cookie");
                    response
                        .headers
                        .iter()
                        .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.as_str())
                })
                .filter_map(|value| value.split(';').next())
                .filter_map(|pair| pair.split_once('=').map(|(name, _)| name.trim()))
                .filter(|name| {
                    let (name,): (&str,) = (name,);
                    {
                        let lower = name.to_ascii_lowercase();
                        name.eq_ignore_ascii_case(".AspNetCore.Session")
                            || name.eq_ignore_ascii_case(".AspNetCore.Cookies")
                            || name.eq_ignore_ascii_case(".AspNetCore.Mvc.CookieTempDataProvider")
                            || [
                                ".AspNetCore.Antiforgery.",
                                ".AspNetCore.Identity.",
                                ".AspNetCore.Correlation.",
                                ".AspNetCore.OpenIdConnect.Nonce.",
                            ]
                            .iter()
                            .map(|prefix| prefix.to_ascii_lowercase())
                            .any(|prefix| lower.len() > prefix.len() && lower.starts_with(&prefix))
                    }
                })
                .map(str::to_owned)
                .collect::<Vec<_>>();
            cookie_names.sort_by_key(|name| name.to_ascii_lowercase());
            cookie_names.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
            if !cookie_names.is_empty() {
                let evidence = format!(
                    "ASP.NET Core framework-specific cookie{}: {}",
                    if cookie_names.len() == 1 { "" } else { "s" },
                    cookie_names.join(", ")
                );
                ({
                    let (signals, backend, backend_layer, runtime, source, evidence, kind): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        &'static str,
                        &'static str,
                        &str,
                        ProductSignalKind,
                    ) = (
                        signals,
                        "ASP.NET Core",
                        ProductLayer::Framework,
                        ".NET",
                        "behavior:aspnet-core-cookies",
                        &evidence,
                        ProductSignalKind::StrongExplicit,
                    );

                    for (name, layer) in
                        [(backend, backend_layer), (runtime, ProductLayer::Runtime)]
                    {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                name,
                                layer,
                                source.to_owned(),
                                evidence.to_owned(),
                                kind,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                });
            }

            if endpoint.http.iter().any(|response: &HttpObservation| {
                if response.status < 500 {
                    return false;
                }
                let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
                let hosting_error = lower.contains("http error 500.")
                    && lower.contains("asp.net core")
                    && lower.contains("common solutions to this issue");
                let startup_error = lower
                    .contains("an error occurred while starting the application.")
                    && lower.contains("microsoft.aspnetcore.hosting version")
                    && lower.contains("show raw exception details");
                let developer_error = lower
                    .contains("an unhandled exception occurred while processing the request.")
                    && lower.contains("<div class=\"titleerror\">")
                    && lower.contains("<li id=\"stack\"")
                    && lower.contains("<li id=\"query\"")
                    && lower.contains("<li id=\"cookies\"")
                    && lower.contains("<li id=\"headers\"")
                    && lower.contains("<li id=\"routing\"");
                let compilation_error = lower.contains(
        "an error occurred during the compilation of a resource required to process this request.",
    ) && lower.contains("<div id=\"stackpage\" class=\"page\">")
        && lower.contains("class=\"titleerror\"")
        && lower.contains("show compilation source")
        && lower.contains("class=\"rawexceptiondetails\"");
                hosting_error || startup_error || developer_error || compilation_error
            }) {
                ({
                    let (signals, backend, backend_layer, runtime, source, evidence, kind): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        &'static str,
                        &'static str,
                        &str,
                        ProductSignalKind,
                    ) = (
                        signals,
                        "ASP.NET Core",
                        ProductLayer::Framework,
                        ".NET",
                        "behavior:aspnet-core-branded-page",
                        "ASP.NET Core branded hosting or developer error page",
                        ProductSignalKind::StrongExplicit,
                    );

                    for (name, layer) in
                        [(backend, backend_layer), (runtime, ProductLayer::Runtime)]
                    {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                name,
                                layer,
                                source.to_owned(),
                                evidence.to_owned(),
                                kind,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                });
            }
        });
    });
    for tls in &endpoint.tls {
        if cancel.is_cancelled() {
            return;
        }
        for certificate in &tls.certificates {
            let identity =
                format!("{} {}", certificate.subject, certificate.issuer).to_ascii_lowercase();
            for (needle, product, layer) in [
                ("cloudflare", "Cloudflare", ProductLayer::Cdn),
                ("amazon", "AWS", ProductLayer::Cloud),
                ("microsoft", "Azure", ProductLayer::Cloud),
                ("google", "Google Frontend", ProductLayer::Cloud),
            ] {
                if identity.contains(needle) {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            &mut signals,
                            product,
                            layer,
                            "tls:certificate-identity".to_owned(),
                            format!("TLS certificate subject/issuer contains {needle}"),
                            ProductSignalKind::Indirect,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: vec![{ let mut record = technology_evidence::observation("TLS certificate subject / issuer", &format!("{} / {}", certificate.subject, certificate.issuer)); record.endpoint = Some(std::net::SocketAddr::new(endpoint.ip, endpoint.port).to_string()); record }],
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
            }
        }
    }
    ({
        let (endpoint, signals): (
            &EndpointScan,
            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
        ) = (endpoint, &mut signals);

        let mut generic = HashMap::<&'static str, String>::new();
        let baselines = endpoint
            .http
            .iter()
            .filter(|response| response.url.contains("/nancy-exposure-not-found-"))
            .collect::<Vec<_>>();
        for response in &endpoint.http {
        let evidence_response = Some(response);
        if cancel.is_cancelled() {
            return;
        }
            if !({
                let (response, endpoint_port): (&HttpObservation, u16) = (response, endpoint.port);
                {
                    Url::parse(&response.url)
                        .ok()
                        .and_then(|url| url.port_or_known_default())
                        == Some(endpoint_port)
                }
            }) || (!((200..300).contains(&response.status))
                && !matches!(response.status, 401 | 403))
                || response.url.contains("/nancy-exposure-not-found-")
                || response_is_soft_404(response, &baselines)
            {
                continue;
            }
            let body = String::from_utf8_lossy(&response.body);
            let lower = body.to_ascii_lowercase();
            let generators = {
                let (body,): (&str,) = (&body,);
                let inlined_result: Vec<String> = {
                    product_html_tags(body)
                        .iter()
                        .filter(|tag| tag.kind == StartTag && tag.name.as_ref() == "meta")
                        .filter(|tag| {
                            ({
                                let (tag, name): (&'_ Tag, &str) = (tag, "name");
                                let inlined_result: Option<&'_ str> = {
                                    tag.attrs
                                        .iter()
                                        .find(|attribute| attribute.name.local.as_ref() == name)
                                        .map(|attribute| attribute.value.as_ref())
                                };
                                inlined_result
                            })
                            .is_some_and(|value| value.eq_ignore_ascii_case("generator"))
                        })
                        .filter_map(|tag| {
                            ({
                                let (tag, name): (&'_ Tag, &str) = (tag, "content");
                                let inlined_result: Option<&'_ str> = {
                                    tag.attrs
                                        .iter()
                                        .find(|attribute| attribute.name.local.as_ref() == name)
                                        .map(|attribute| attribute.value.as_ref())
                                };
                                inlined_result
                            })
                            .map(str::to_owned)
                        })
                        .collect()
                };
                inlined_result
            };
            let generator = generators.first().cloned();
            let generator_lower = generator
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let path = {
                let (response,): (&HttpObservation,) = (response,);
                {
                    Url::parse(&response.url)
                        .ok()
                        .map(|url| url_path(&url))
                        .unwrap_or_default()
                        .to_ascii_lowercase()
                }
            };
            for generator in generators {
                ({
                    let (generator, signals): (
                        &str,
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                    ) = (&generator, signals);
                    'inlined_record_known_generator_signal: {
                        let lower = generator.to_ascii_lowercase();
                        let (needle, product, layer) = if lower.trim() == "anywarecms" {
                            ("anywarecms", "ANYWARECMS", ProductLayer::Cms)
                        } else if lower.contains("totara") {
                            ("totara", "Totara", ProductLayer::Cms)
                        } else if lower.contains("moodle") {
                            ("moodle", "Moodle", ProductLayer::Cms)
                        } else if lower.contains("woocommerce") {
                            ("woocommerce", "WooCommerce", ProductLayer::Ecommerce)
                        } else if lower.contains("wordpress") {
                            ("wordpress", "WordPress", ProductLayer::Cms)
                        } else if lower.contains("adobe commerce") {
                            ("adobe commerce", "Adobe Commerce", ProductLayer::Ecommerce)
                        } else if lower.contains("magento") {
                            ("magento", "Magento", ProductLayer::Ecommerce)
                        } else if lower.contains("shopify") {
                            ("shopify", "Shopify", ProductLayer::Ecommerce)
                        } else if lower.contains("sulu") {
                            ("sulu", "Sulu", ProductLayer::Cms)
                        } else if lower.contains("silverstripe") {
                            ("silverstripe", "Silverstripe", ProductLayer::Cms)
                        } else if lower.contains("bigcommerce") {
                            ("bigcommerce", "BigCommerce", ProductLayer::Ecommerce)
                        } else if lower.contains("prestashop") {
                            ("prestashop", "PrestaShop", ProductLayer::Ecommerce)
                        } else if lower.contains("opencart") {
                            ("opencart", "OpenCart", ProductLayer::Ecommerce)
                        } else {
                            break 'inlined_record_known_generator_signal;
                        };
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                product,
                                layer,
                                format!("{needle}:generator"),
                                format!("Generator metadata: {generator}"),
                                ProductSignalKind::StrongExplicit,
                                ({
                                    let (value, product): (&str, &str) = (generator, product);
                                    let inlined_result: Option<String> = {
                                        'inlined_extract_version: {
                                            let lower = value.to_ascii_lowercase();
                                            let index =
                                                match lower.find(&product.to_ascii_lowercase()) {
                                                    Some(value) => value,
                                                    None => break 'inlined_extract_version None,
                                                } + product.len();
                                            let remainder = value[index..]
                                                .trim_start_matches(['/', ' ', '-', '_']);
                                            let version = remainder
                                                .chars()
                                                .take_while(|character| {
                                                    character.is_ascii_alphanumeric()
                                                        || matches!(character, '.' | '-' | '_')
                                                })
                                                .collect::<String>();
                                            if version
                                                .chars()
                                                .any(|character| character.is_ascii_digit())
                                            {
                                                Some(version)
                                            } else {
                                                None
                                            }
                                        }
                                    };
                                    inlined_result
                                }),
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                });
                if generator.trim().eq_ignore_ascii_case("ANYWARECMS") {
                    ({
                        let (response, body, signals): (
                            &HttpObservation,
                            &str,
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        ) = (response, &body, signals);
                        'inlined_record_anyware_asset_signals: {
                            let Ok(base) = Url::parse(&response.url) else {
                                break 'inlined_record_anyware_asset_signals;
                            };
                            for tag in product_html_tags(body)
                                .iter()
                                .filter(|tag| tag.kind == StartTag)
                            {
                                let attribute = match tag.name.as_ref() {
                                    "script" | "img" | "source" | "audio" | "video" => "src",
                                    "link"
                                        if ({
                                            let (tag, name): (&'_ Tag, &str) = (tag, "rel");
                                            let inlined_result: Option<&'_ str> = {
                                                tag.attrs
                                                    .iter()
                                                    .find(|attribute| {
                                                        attribute.name.local.as_ref() == name
                                                    })
                                                    .map(|attribute| attribute.value.as_ref())
                                            };
                                            inlined_result
                                        })
                                        .is_some_and(|rel| {
                                            rel.split_ascii_whitespace().any(|value| {
                                                matches!(
                                                    value.to_ascii_lowercase().as_str(),
                                                    "stylesheet"
                                                        | "icon"
                                                        | "preload"
                                                        | "modulepreload"
                                                        | "manifest"
                                                )
                                            })
                                        }) =>
                                    {
                                        "href"
                                    }
                                    _ => continue,
                                };
                                if let Some(reference) = ({
                                    let (tag, name): (&'_ Tag, &str) = (tag, attribute);
                                    let inlined_result: Option<&'_ str> = {
                                        tag.attrs
                                            .iter()
                                            .find(|attribute| attribute.name.local.as_ref() == name)
                                            .map(|attribute| attribute.value.as_ref())
                                    };
                                    inlined_result
                                }) && let Ok(url) = base.join(reference.trim())
                                    && matches!(url.scheme(), "http" | "https")
                                    && url.host_str() == Some("cm.anyware.co.nz")
                                {
                                    ({
                                        let (signals, name, layer, source, evidence, kind, version,): (& mut HashMap < (& 'static str , ProductLayer) , Vec < ProductSignal > >, & 'static str, ProductLayer, String, String, ProductSignalKind, Option < String >,) = (signals, "ANYWARECMS", ProductLayer::Cms, "anywarecms:asset-host".to_owned(), format!("ANYWARECMS supporting asset reference: {url}"), ProductSignalKind::Indirect, None,);

                                        signals.entry((name, layer)).or_default().push(
                                            ProductSignal {
                                                observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                                source,
                                                evidence,
                                                kind,
                                                version,
                                            },
                                        );
                                    });
                                }
                            }
                        }
                    });
                }
            }
            ({
                let (response, signals): (
                    &HttpObservation,
                    &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                ) = (response, signals);

                for (name, value) in &response.headers {
                    let header = name.to_ascii_lowercase();
                    let value = value.to_ascii_lowercase();
                    for (needle, product, layer, prefix) in [
                        ("sulu", "Sulu", ProductLayer::Cms, "x-sulu-"),
                        ("wordpress", "WordPress", ProductLayer::Cms, "x-wordpress-"),
                        (
                            "woocommerce",
                            "WooCommerce",
                            ProductLayer::Ecommerce,
                            "x-wc-",
                        ),
                        (
                            "prestashop",
                            "PrestaShop",
                            ProductLayer::Ecommerce,
                            "x-prestashop-",
                        ),
                        (
                            "opencart",
                            "OpenCart",
                            ProductLayer::Ecommerce,
                            "x-opencart-",
                        ),
                    ] {
                        let named = header.starts_with(prefix);
                        let valued = matches!(
                            header.as_str(),
                            "x-powered-by" | "x-generator" | "x-platform"
                        ) && value.contains(needle);
                        if named || valued {
                            ({
                                let (signals, name, layer, source, evidence, kind, version): (
                                    &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                    &'static str,
                                    ProductLayer,
                                    String,
                                    String,
                                    ProductSignalKind,
                                    Option<String>,
                                ) = (
                                    signals,
                                    product,
                                    layer,
                                    format!("{needle}:vendor-header"),
                                    format!("Vendor-specific {name} response header"),
                                    ProductSignalKind::StrongExplicit,
                                    valued
                                        .then(|| {
                                            let (value, product): (&str, &str) = (&value, needle);
                                            let inlined_result: Option<String> = {
                                                'inlined_extract_version: {
                                                    let lower = value.to_ascii_lowercase();
                                                    let index = match lower
                                                        .find(&product.to_ascii_lowercase())
                                                    {
                                                        Some(value) => value,
                                                        None => {
                                                            break 'inlined_extract_version None;
                                                        }
                                                    } + product.len();
                                                    let remainder = value[index..]
                                                        .trim_start_matches(['/', ' ', '-', '_']);
                                                    let version = remainder
                                                        .chars()
                                                        .take_while(|character| {
                                                            character.is_ascii_alphanumeric()
                                                                || matches!(
                                                                    character,
                                                                    '.' | '-' | '_'
                                                                )
                                                        })
                                                        .collect::<String>();
                                                    if version
                                                        .chars()
                                                        .any(|character| character.is_ascii_digit())
                                                    {
                                                        Some(version)
                                                    } else {
                                                        None
                                                    }
                                                }
                                            };
                                            inlined_result
                                        })
                                        .flatten(),
                                );

                                signals
                                    .entry((name, layer))
                                    .or_default()
                                    .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                        source,
                                        evidence,
                                        kind,
                                        version,
                                    });
                            });
                        }
                    }
                }
            });
            ({
                let (response, body, lower, path, signals): (
                    &HttpObservation,
                    &str,
                    &str,
                    &str,
                    &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                ) = (response, &body, &lower, &path, signals);

                if let Some(name) = {
                    let (response, prefix): (&HttpObservation, &str) = (response, "MoodleSession");
                    let inlined_result: Option<String> = {
                        ({
                            let (response, name): (&crate::HttpObservation, &str) =
                                (response, "set-cookie");
                            response
                                .headers
                                .iter()
                                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                                .map(|(_, value)| value.as_str())
                        })
                        .find_map(|value| {
                            let pair = value.split(';').next()?.trim();
                            let (name, _) = pair.split_once('=')?;
                            name.trim()
                                .to_ascii_lowercase()
                                .starts_with(&prefix.to_ascii_lowercase())
                                .then(|| name.trim().to_owned())
                        })
                    };
                    inlined_result
                } {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Moodle",
                            ProductLayer::Cms,
                            "moodle:session-cookie".to_owned(),
                            format!("Moodle session cookie: {name}"),
                            ProductSignalKind::StrongExplicit,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if {
                    let (body, variable, keys): (&str, &str, &[&str]) = (
                        lower,
                        "m.cfg",
                        &["wwwroot", "sesskey", "theme", "contextid"],
                    );
                    {
                        'inlined_structured_javascript_config: {
                            let mut position = 0usize;
                            while let Some(relative) = body[position..].find(variable) {
                                let start = position + relative + variable.len();
                                let remainder = body[start..].trim_start();
                                let Some(object) = remainder.strip_prefix('=').map(str::trim_start)
                                else {
                                    position = start;
                                    continue;
                                };
                                if !object.starts_with('{') {
                                    position = start;
                                    continue;
                                }
                                let Some(end) = ({
                                    let (value,): (&str,) = (object,);
                                    {
                                        'inlined_javascript_object_end: {
                                            let mut depth = 0usize;
                                            let mut quote = None;
                                            let mut escaped = false;
                                            for (index, byte) in value.bytes().enumerate() {
                                                if let Some(active_quote) = quote {
                                                    if escaped {
                                                        escaped = false;
                                                    } else if byte == b'\\' {
                                                        escaped = true;
                                                    } else if byte == active_quote {
                                                        quote = None;
                                                    }
                                                    continue;
                                                }
                                                if matches!(byte, b'\'' | b'"') {
                                                    quote = Some(byte);
                                                } else if byte == b'{' {
                                                    depth += 1;
                                                } else if byte == b'}' {
                                                    depth = match depth.checked_sub(1) { Some(value) => value, None => break 'inlined_javascript_object_end None };
                                                    if depth == 0 {
                                                        break 'inlined_javascript_object_end Some(
                                                            index + 1,
                                                        );
                                                    }
                                                }
                                            }
                                            None
                                        }
                                    }
                                }) else {
                                    position = start;
                                    continue;
                                };
                                let object = &object[..end];
                                let matched = keys
                                    .iter()
                                    .filter(|key| {
                                        object.contains(&format!("\"{key}\""))
                                            || object.contains(&format!("'{key}'"))
                                    })
                                    .count();
                                if matched >= 2 {
                                    break 'inlined_structured_javascript_config true;
                                }
                                position = start;
                            }
                            false
                        }
                    }
                } {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Moodle",
                            ProductLayer::Cms,
                            "moodle:page-config".to_owned(),
                            "Structured Moodle M.cfg page configuration".to_owned(),
                            ProductSignalKind::Strong,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                for route in [
                    "/theme/yui_combo.php",
                    "/theme/styles.php",
                    "/theme/image.php",
                    "/lib/javascript.php",
                    "/lib/requirejs.php",
                    "/lib/requirejs/config.php",
                    "/lib/ajax/service.php",
                    "/pluginfile.php/",
                ] {
                    if lower.contains(route) || path.starts_with(route) {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                "Moodle",
                                ProductLayer::Cms,
                                "moodle:php-assets".to_owned(),
                                format!("Moodle PHP asset route: {route}"),
                                ProductSignalKind::Strong,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                }
                if {
                    let (body, product, domains): (&str, &str, &[&str]) =
                        (body, "Moodle", &["moodle.com", "moodle.org"]);
                    {
                        'inlined_canonical_powered_by_link: {
                            let lower = body.to_ascii_lowercase();
                            let product = product.to_ascii_lowercase();
                            let mut position = 0usize;
                            while let Some(relative) = lower[position..].find("<a") {
                                let start = position + relative;
                                let Some(relative_open_end) = lower[start..].find('>') else {
                                    break;
                                };
                                let open_end = start + relative_open_end + 1;
                                let Some(relative_close) = lower[open_end..].find("</a>") else {
                                    break;
                                };
                                let close = open_end + relative_close;
                                let tag = &body[start..open_end];
                                let official = html_attribute(tag, "href").is_some_and(|href| {
                                    let parsed = if href.starts_with("//") {
                                        Url::parse(&format!("https:{href}"))
                                    } else {
                                        Url::parse(&href)
                                    };
                                    parsed
                                        .ok()
                                        .filter(|url| matches!(url.scheme(), "http" | "https"))
                                        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
                                        .is_some_and(|host| {
                                            domains.iter().any(|domain| {
                                                host == *domain
                                                    || host.ends_with(&format!(".{domain}"))
                                            })
                                        })
                                });
                                if official {
                                    let inner = &lower[open_end..close];
                                    let before = &lower[..start];
                                    let before = before
                                        .rsplit_once('>')
                                        .map(|(_, text)| text)
                                        .unwrap_or(before);
                                    if inner.contains(&product)
                                        && (inner.contains("powered by")
                                            || before.trim_end().ends_with("powered by"))
                                    {
                                        break 'inlined_canonical_powered_by_link true;
                                    }
                                }
                                position = close + 4;
                            }
                            false
                        }
                    }
                } {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Moodle",
                            ProductLayer::Cms,
                            "moodle:powered-by".to_owned(),
                            "Canonical Powered by Moodle attribution".to_owned(),
                            ProductSignalKind::StrongExplicit,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if {
                    let (body, product): (&str, &str) = (lower, "moodle");
                    {
                        body.contains(product)
                            && ["copyright", "licence", "license", "licensed", "powered by"]
                                .iter()
                                .any(|marker| body.contains(marker))
                    }
                } {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Moodle",
                            ProductLayer::Cms,
                            "moodle:generic-prose".to_owned(),
                            "Generic Moodle copyright, licence, or powered-by prose".to_owned(),
                            ProductSignalKind::Indirect,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }

                if let Some(name) = {
                    let (response, prefix): (&HttpObservation, &str) = (response, "TotaraSession");
                    let inlined_result: Option<String> = {
                        ({
                            let (response, name): (&crate::HttpObservation, &str) =
                                (response, "set-cookie");
                            response
                                .headers
                                .iter()
                                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                                .map(|(_, value)| value.as_str())
                        })
                        .find_map(|value| {
                            let pair = value.split(';').next()?.trim();
                            let (name, _) = pair.split_once('=')?;
                            name.trim()
                                .to_ascii_lowercase()
                                .starts_with(&prefix.to_ascii_lowercase())
                                .then(|| name.trim().to_owned())
                        })
                    };
                    inlined_result
                } {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Totara",
                            ProductLayer::Cms,
                            "totara:session-cookie".to_owned(),
                            format!("Totara session cookie: {name}"),
                            ProductSignalKind::StrongExplicit,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if lower.contains("/totara/tui/") || path.starts_with("/totara/tui/") {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Totara",
                            ProductLayer::Cms,
                            "totara:tui-assets".to_owned(),
                            "Totara Tui asset route".to_owned(),
                            ProductSignalKind::Strong,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if lower.contains("totara_core") || path.contains("/totara_core/") {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Totara",
                            ProductLayer::Cms,
                            "totara:core-resource".to_owned(),
                            "Totara core resource or module".to_owned(),
                            ProductSignalKind::Strong,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if {
                    let (body, variable, keys): (&str, &str, &[&str]) = (
                        lower,
                        "_pageconfig",
                        &["wwwroot", "sesskey", "rev", "theme", "context", "locale"],
                    );
                    {
                        'inlined_structured_javascript_config: {
                            let mut position = 0usize;
                            while let Some(relative) = body[position..].find(variable) {
                                let start = position + relative + variable.len();
                                let remainder = body[start..].trim_start();
                                let Some(object) = remainder.strip_prefix('=').map(str::trim_start)
                                else {
                                    position = start;
                                    continue;
                                };
                                if !object.starts_with('{') {
                                    position = start;
                                    continue;
                                }
                                let Some(end) = ({
                                    let (value,): (&str,) = (object,);
                                    {
                                        'inlined_javascript_object_end: {
                                            let mut depth = 0usize;
                                            let mut quote = None;
                                            let mut escaped = false;
                                            for (index, byte) in value.bytes().enumerate() {
                                                if let Some(active_quote) = quote {
                                                    if escaped {
                                                        escaped = false;
                                                    } else if byte == b'\\' {
                                                        escaped = true;
                                                    } else if byte == active_quote {
                                                        quote = None;
                                                    }
                                                    continue;
                                                }
                                                if matches!(byte, b'\'' | b'"') {
                                                    quote = Some(byte);
                                                } else if byte == b'{' {
                                                    depth += 1;
                                                } else if byte == b'}' {
                                                    depth = match depth.checked_sub(1) { Some(value) => value, None => break 'inlined_javascript_object_end None };
                                                    if depth == 0 {
                                                        break 'inlined_javascript_object_end Some(
                                                            index + 1,
                                                        );
                                                    }
                                                }
                                            }
                                            None
                                        }
                                    }
                                }) else {
                                    position = start;
                                    continue;
                                };
                                let object = &object[..end];
                                let matched = keys
                                    .iter()
                                    .filter(|key| {
                                        object.contains(&format!("\"{key}\""))
                                            || object.contains(&format!("'{key}'"))
                                    })
                                    .count();
                                if matched >= 2 {
                                    break 'inlined_structured_javascript_config true;
                                }
                                position = start;
                            }
                            false
                        }
                    }
                } {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Totara",
                            ProductLayer::Cms,
                            "totara:page-config".to_owned(),
                            "Structured Totara page configuration".to_owned(),
                            ProductSignalKind::Strong,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if {
                    let (body, product, domains): (&str, &str, &[&str]) =
                        (body, "Totara", &["totara.com"]);
                    {
                        'inlined_canonical_powered_by_link: {
                            let lower = body.to_ascii_lowercase();
                            let product = product.to_ascii_lowercase();
                            let mut position = 0usize;
                            while let Some(relative) = lower[position..].find("<a") {
                                let start = position + relative;
                                let Some(relative_open_end) = lower[start..].find('>') else {
                                    break;
                                };
                                let open_end = start + relative_open_end + 1;
                                let Some(relative_close) = lower[open_end..].find("</a>") else {
                                    break;
                                };
                                let close = open_end + relative_close;
                                let tag = &body[start..open_end];
                                let official = html_attribute(tag, "href").is_some_and(|href| {
                                    let parsed = if href.starts_with("//") {
                                        Url::parse(&format!("https:{href}"))
                                    } else {
                                        Url::parse(&href)
                                    };
                                    parsed
                                        .ok()
                                        .filter(|url| matches!(url.scheme(), "http" | "https"))
                                        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
                                        .is_some_and(|host| {
                                            domains.iter().any(|domain| {
                                                host == *domain
                                                    || host.ends_with(&format!(".{domain}"))
                                            })
                                        })
                                });
                                if official {
                                    let inner = &lower[open_end..close];
                                    let before = &lower[..start];
                                    let before = before
                                        .rsplit_once('>')
                                        .map(|(_, text)| text)
                                        .unwrap_or(before);
                                    if inner.contains(&product)
                                        && (inner.contains("powered by")
                                            || before.trim_end().ends_with("powered by"))
                                    {
                                        break 'inlined_canonical_powered_by_link true;
                                    }
                                }
                                position = close + 4;
                            }
                            false
                        }
                    }
                } {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Totara",
                            ProductLayer::Cms,
                            "totara:powered-by".to_owned(),
                            "Canonical Powered by Totara attribution".to_owned(),
                            ProductSignalKind::StrongExplicit,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if {
                    let (body, product): (&str, &str) = (lower, "totara");
                    {
                        body.contains(product)
                            && ["copyright", "licence", "license", "licensed", "powered by"]
                                .iter()
                                .any(|marker| body.contains(marker))
                    }
                } {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Totara",
                            ProductLayer::Cms,
                            "totara:generic-prose".to_owned(),
                            "Generic Totara copyright, licence, or powered-by prose".to_owned(),
                            ProductSignalKind::Indirect,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
            });

            if generator_lower.contains("wordpress") {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "WordPress",
                        ProductLayer::Cms,
                        "wordpress:generator".to_owned(),
                        format!(
                            "Generator metadata: {}",
                            generator.as_deref().unwrap_or_default()
                        ),
                        ProductSignalKind::StrongExplicit,
                        generator.as_deref().and_then(|value| {
                            let (value, product): (&str, &str) = (value, "WordPress");
                            let inlined_result: Option<String> = {
                                'inlined_extract_version: {
                                    let lower = value.to_ascii_lowercase();
                                    let index = match lower.find(&product.to_ascii_lowercase()) {
                                        Some(value) => value,
                                        None => break 'inlined_extract_version None,
                                    } + product.len();
                                    let remainder =
                                        value[index..].trim_start_matches(['/', ' ', '-', '_']);
                                    let version = remainder
                                        .chars()
                                        .take_while(|character| {
                                            character.is_ascii_alphanumeric()
                                                || matches!(character, '.' | '-' | '_')
                                        })
                                        .collect::<String>();
                                    if version.chars().any(|character| character.is_ascii_digit()) {
                                        Some(version)
                                    } else {
                                        None
                                    }
                                }
                            };
                            inlined_result
                        }),
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
            for (needle, source, evidence) in [
                (
                    "wp-content/",
                    "wordpress:content-path",
                    "WordPress wp-content asset path",
                ),
                (
                    "wp-includes/",
                    "wordpress:includes-path",
                    "WordPress wp-includes asset path",
                ),
                (
                    "api.w.org",
                    "wordpress:api-link",
                    "WordPress REST API link relation",
                ),
            ] {
                if lower.contains(needle) {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "WordPress",
                            ProductLayer::Cms,
                            source.to_owned(),
                            evidence.to_owned(),
                            ProductSignalKind::Strong,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
            }
            if response.headers.iter().any(|(name, value)| {
                (name.eq_ignore_ascii_case("link")
                    && value.to_ascii_lowercase().contains("wp-json"))
                    || (name.eq_ignore_ascii_case("x-pingback")
                        && value.to_ascii_lowercase().contains("xmlrpc.php"))
            }) {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "WordPress",
                        ProductLayer::Cms,
                        "wordpress:header".to_owned(),
                        "WordPress REST or XML-RPC response header".to_owned(),
                        ProductSignalKind::StrongExplicit,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
            if ({
                let (response, needle): (&HttpObservation, &str) = (response, "wordpress_");
                {
                    ({
                        let (response, name): (&crate::HttpObservation, &str) =
                            (response, "set-cookie");
                        response
                            .headers
                            .iter()
                            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                            .map(|(_, value)| value.as_str())
                    })
                    .any(|value| {
                        value
                            .to_ascii_lowercase()
                            .contains(&needle.to_ascii_lowercase())
                    })
                }
            }) || ({
                let (response, needle): (&HttpObservation, &str) = (response, "wp-settings-");
                {
                    ({
                        let (response, name): (&crate::HttpObservation, &str) =
                            (response, "set-cookie");
                        response
                            .headers
                            .iter()
                            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                            .map(|(_, value)| value.as_str())
                    })
                    .any(|value| {
                        value
                            .to_ascii_lowercase()
                            .contains(&needle.to_ascii_lowercase())
                    })
                }
            }) {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "WordPress",
                        ProductLayer::Cms,
                        "wordpress:cookie".to_owned(),
                        "WordPress cookie name".to_owned(),
                        ProductSignalKind::Strong,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
            if wordpress_login_response(response) {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "WordPress",
                        ProductLayer::Cms,
                        "wordpress:validated-login".to_owned(),
                        format!(
                            "WordPress login form targeting wp-login.php with log and pwd inputs at {}",
                            response.url
                        ),
                        ProductSignalKind::Validated,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
            if wordpress_api_response(response) {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "WordPress",
                        ProductLayer::Cms,
                        "wordpress:validated-api".to_owned(),
                        format!("Validated WordPress REST API response at {}", response.url),
                        ProductSignalKind::Validated,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }

            if generator_lower.contains("woocommerce") {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "WooCommerce",
                        ProductLayer::Ecommerce,
                        "woocommerce:generator".to_owned(),
                        format!(
                            "Generator metadata: {}",
                            generator.as_deref().unwrap_or_default()
                        ),
                        ProductSignalKind::StrongExplicit,
                        generator.as_deref().and_then(|value| {
                            let (value, product): (&str, &str) = (value, "WooCommerce");
                            let inlined_result: Option<String> = {
                                'inlined_extract_version: {
                                    let lower = value.to_ascii_lowercase();
                                    let index = match lower.find(&product.to_ascii_lowercase()) {
                                        Some(value) => value,
                                        None => break 'inlined_extract_version None,
                                    } + product.len();
                                    let remainder =
                                        value[index..].trim_start_matches(['/', ' ', '-', '_']);
                                    let version = remainder
                                        .chars()
                                        .take_while(|character| {
                                            character.is_ascii_alphanumeric()
                                                || matches!(character, '.' | '-' | '_')
                                        })
                                        .collect::<String>();
                                    if version.chars().any(|character| character.is_ascii_digit()) {
                                        Some(version)
                                    } else {
                                        None
                                    }
                                }
                            };
                            inlined_result
                        }),
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
            for (needle, source, evidence) in [
                (
                    "/plugins/woocommerce/",
                    "woocommerce:assets",
                    "WooCommerce plugin asset path",
                ),
                (
                    "class=\"woocommerce",
                    "woocommerce:class",
                    "WooCommerce HTML class",
                ),
                (
                    "wc-cart-fragments",
                    "woocommerce:cart-script",
                    "WooCommerce cart-fragments script",
                ),
                (
                    "wc_add_to_cart_params",
                    "woocommerce:global",
                    "WooCommerce storefront JavaScript global",
                ),
            ] {
                if lower.contains(needle) {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "WooCommerce",
                            ProductLayer::Ecommerce,
                            source.to_owned(),
                            evidence.to_owned(),
                            ProductSignalKind::Strong,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
            }
            if ({
                let (response, needle): (&HttpObservation, &str) = (response, "woocommerce_");
                {
                    ({
                        let (response, name): (&crate::HttpObservation, &str) =
                            (response, "set-cookie");
                        response
                            .headers
                            .iter()
                            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                            .map(|(_, value)| value.as_str())
                    })
                    .any(|value| {
                        value
                            .to_ascii_lowercase()
                            .contains(&needle.to_ascii_lowercase())
                    })
                }
            }) || ({
                let (response, needle): (&HttpObservation, &str) =
                    (response, "woocommerce_cart_hash");
                {
                    ({
                        let (response, name): (&crate::HttpObservation, &str) =
                            (response, "set-cookie");
                        response
                            .headers
                            .iter()
                            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                            .map(|(_, value)| value.as_str())
                    })
                    .any(|value| {
                        value
                            .to_ascii_lowercase()
                            .contains(&needle.to_ascii_lowercase())
                    })
                }
            }) || ({
                let (response, needle): (&HttpObservation, &str) =
                    (response, "wp_woocommerce_session_");
                {
                    ({
                        let (response, name): (&crate::HttpObservation, &str) =
                            (response, "set-cookie");
                        response
                            .headers
                            .iter()
                            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                            .map(|(_, value)| value.as_str())
                    })
                    .any(|value| {
                        value
                            .to_ascii_lowercase()
                            .contains(&needle.to_ascii_lowercase())
                    })
                }
            }) {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "WooCommerce",
                        ProductLayer::Ecommerce,
                        "woocommerce:cookie".to_owned(),
                        "WooCommerce cart or session cookie".to_owned(),
                        ProductSignalKind::Strong,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
            if woocommerce_api_response(response, &path) {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "WooCommerce",
                        ProductLayer::Ecommerce,
                        "woocommerce:validated-api".to_owned(),
                        format!(
                            "Validated WooCommerce Store API response at {}",
                            response.url
                        ),
                        ProductSignalKind::Validated,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }

            ({
                let (response, lower, generator, generator_lower, path, signals): (
                    &HttpObservation,
                    &str,
                    Option<&str>,
                    &str,
                    &str,
                    &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                ) = (
                    response,
                    &lower,
                    generator.as_deref(),
                    &generator_lower,
                    &path,
                    signals,
                );

                if generator_lower.contains("magento") || generator_lower.contains("adobe commerce")
                {
                    let product = if generator_lower.contains("adobe commerce") {
                        "Adobe Commerce"
                    } else {
                        "Magento"
                    };
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            product,
                            ProductLayer::Ecommerce,
                            "magento:generator".to_owned(),
                            format!("Generator metadata: {}", generator.unwrap_or_default()),
                            ProductSignalKind::StrongExplicit,
                            generator.and_then(|value| {
                                ({
                                    let (value, product): (&str, &str) = (value, "Magento");
                                    let inlined_result: Option<String> = {
                                        'inlined_extract_version: {
                                            let lower = value.to_ascii_lowercase();
                                            let index =
                                                match lower.find(&product.to_ascii_lowercase()) {
                                                    Some(value) => value,
                                                    None => break 'inlined_extract_version None,
                                                } + product.len();
                                            let remainder = value[index..]
                                                .trim_start_matches(['/', ' ', '-', '_']);
                                            let version = remainder
                                                .chars()
                                                .take_while(|character| {
                                                    character.is_ascii_alphanumeric()
                                                        || matches!(character, '.' | '-' | '_')
                                                })
                                                .collect::<String>();
                                            if version
                                                .chars()
                                                .any(|character| character.is_ascii_digit())
                                            {
                                                Some(version)
                                            } else {
                                                None
                                            }
                                        }
                                    };
                                    inlined_result
                                })
                                .or_else(|| {
                                    let (value, product): (&str, &str) = (value, "Adobe Commerce");
                                    let inlined_result: Option<String> = {
                                        'inlined_extract_version: {
                                            let lower = value.to_ascii_lowercase();
                                            let index =
                                                match lower.find(&product.to_ascii_lowercase()) {
                                                    Some(value) => value,
                                                    None => break 'inlined_extract_version None,
                                                } + product.len();
                                            let remainder = value[index..]
                                                .trim_start_matches(['/', ' ', '-', '_']);
                                            let version = remainder
                                                .chars()
                                                .take_while(|character| {
                                                    character.is_ascii_alphanumeric()
                                                        || matches!(character, '.' | '-' | '_')
                                                })
                                                .collect::<String>();
                                            if version
                                                .chars()
                                                .any(|character| character.is_ascii_digit())
                                            {
                                                Some(version)
                                            } else {
                                                None
                                            }
                                        }
                                    };
                                    inlined_result
                                })
                            }),
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                for (needle, source, evidence) in [
                    ("magento_", "magento:module", "Magento module marker"),
                    ("/mage/", "magento:mage-asset", "Magento mage asset path"),
                    (
                        "/static/version",
                        "magento:versioned-asset",
                        "Magento static version asset path",
                    ),
                    (
                        "mage/cookies",
                        "magento:javascript",
                        "Magento mage JavaScript module",
                    ),
                ] {
                    if lower.contains(needle) {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                "Magento",
                                ProductLayer::Ecommerce,
                                source.to_owned(),
                                evidence.to_owned(),
                                ProductSignalKind::Strong,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                }
                if response
                    .headers
                    .iter()
                    .any(|(name, _)| name.to_ascii_lowercase().starts_with("x-magento-"))
                {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Magento",
                            ProductLayer::Ecommerce,
                            "magento:header".to_owned(),
                            "Magento-specific response header".to_owned(),
                            ProductSignalKind::StrongExplicit,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if ({
                    let (response, needle): (&HttpObservation, &str) =
                        (response, "private_content_version");
                    {
                        ({
                            let (response, name): (&crate::HttpObservation, &str) =
                                (response, "set-cookie");
                            response
                                .headers
                                .iter()
                                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                                .map(|(_, value)| value.as_str())
                        })
                        .any(|value| {
                            value
                                .to_ascii_lowercase()
                                .contains(&needle.to_ascii_lowercase())
                        })
                    }
                }) || ({
                    let (response, needle): (&HttpObservation, &str) = (response, "mage-cache-");
                    {
                        ({
                            let (response, name): (&crate::HttpObservation, &str) =
                                (response, "set-cookie");
                            response
                                .headers
                                .iter()
                                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                                .map(|(_, value)| value.as_str())
                        })
                        .any(|value| {
                            value
                                .to_ascii_lowercase()
                                .contains(&needle.to_ascii_lowercase())
                        })
                    }
                }) || ({
                    let (response, needle): (&HttpObservation, &str) = (response, "form_key");
                    {
                        ({
                            let (response, name): (&crate::HttpObservation, &str) =
                                (response, "set-cookie");
                            response
                                .headers
                                .iter()
                                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                                .map(|(_, value)| value.as_str())
                        })
                        .any(|value| {
                            value
                                .to_ascii_lowercase()
                                .contains(&needle.to_ascii_lowercase())
                        })
                    }
                }) {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Magento",
                            ProductLayer::Ecommerce,
                            "magento:cookie".to_owned(),
                            "Magento storefront cookie".to_owned(),
                            ProductSignalKind::Strong,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if magento_api_response(response, path) {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Magento",
                            ProductLayer::Ecommerce,
                            "magento:validated-api".to_owned(),
                            format!(
                                "Validated Magento store configuration API at {}",
                                response.url
                            ),
                            ProductSignalKind::Validated,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
            });
            ({
                let (response, lower, generator, generator_lower, path, signals): (
                    &HttpObservation,
                    &str,
                    Option<&str>,
                    &str,
                    &str,
                    &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                ) = (
                    response,
                    &lower,
                    generator.as_deref(),
                    &generator_lower,
                    &path,
                    signals,
                );

                if generator_lower.contains("shopify") {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Shopify",
                            ProductLayer::Ecommerce,
                            "shopify:generator".to_owned(),
                            format!("Generator metadata: {}", generator.unwrap_or_default()),
                            ProductSignalKind::StrongExplicit,
                            generator.and_then(|value| {
                                let (value, product): (&str, &str) = (value, "Shopify");
                                let inlined_result: Option<String> = {
                                    'inlined_extract_version: {
                                        let lower = value.to_ascii_lowercase();
                                        let index = match lower.find(&product.to_ascii_lowercase())
                                        {
                                            Some(value) => value,
                                            None => break 'inlined_extract_version None,
                                        } + product.len();
                                        let remainder =
                                            value[index..].trim_start_matches(['/', ' ', '-', '_']);
                                        let version = remainder
                                            .chars()
                                            .take_while(|character| {
                                                character.is_ascii_alphanumeric()
                                                    || matches!(character, '.' | '-' | '_')
                                            })
                                            .collect::<String>();
                                        if version
                                            .chars()
                                            .any(|character| character.is_ascii_digit())
                                        {
                                            Some(version)
                                        } else {
                                            None
                                        }
                                    }
                                };
                                inlined_result
                            }),
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                for (needle, source, evidence) in [
                    ("cdn.shopify.com", "shopify:cdn", "Shopify CDN asset URL"),
                    (
                        "/cdn/shop/",
                        "shopify:asset-path",
                        "Shopify /cdn/shop asset path",
                    ),
                    (
                        "shopify.theme",
                        "shopify:global-theme",
                        "Shopify.theme JavaScript global",
                    ),
                    (
                        "shopify.routes",
                        "shopify:global-routes",
                        "Shopify.routes JavaScript global",
                    ),
                    (
                        "shopify-section",
                        "shopify:section-markup",
                        "Shopify product or collection section markup",
                    ),
                    (
                        "data-shopify",
                        "shopify:data-markup",
                        "Shopify data attribute markup",
                    ),
                ] {
                    if lower.contains(needle) {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                "Shopify",
                                ProductLayer::Ecommerce,
                                source.to_owned(),
                                evidence.to_owned(),
                                ProductSignalKind::Strong,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                }
                if response.headers.iter().any(|(name, _)| {
                    matches!(
                        name.to_ascii_lowercase().as_str(),
                        "x-shopid" | "x-shopify-stage" | "x-shopify-shop-api-call-limit"
                    )
                }) {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Shopify",
                            ProductLayer::Ecommerce,
                            "shopify:header".to_owned(),
                            "Shopify-specific response header".to_owned(),
                            ProductSignalKind::StrongExplicit,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if ({
                    let (response, needle): (&HttpObservation, &str) = (response, "_shopify_");
                    {
                        ({
                            let (response, name): (&crate::HttpObservation, &str) =
                                (response, "set-cookie");
                            response
                                .headers
                                .iter()
                                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                                .map(|(_, value)| value.as_str())
                        })
                        .any(|value| {
                            value
                                .to_ascii_lowercase()
                                .contains(&needle.to_ascii_lowercase())
                        })
                    }
                }) || ({
                    let (response, needle): (&HttpObservation, &str) = (response, "_shopify_y");
                    {
                        ({
                            let (response, name): (&crate::HttpObservation, &str) =
                                (response, "set-cookie");
                            response
                                .headers
                                .iter()
                                .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                                .map(|(_, value)| value.as_str())
                        })
                        .any(|value| {
                            value
                                .to_ascii_lowercase()
                                .contains(&needle.to_ascii_lowercase())
                        })
                    }
                }) {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Shopify",
                            ProductLayer::Ecommerce,
                            "shopify:cookie".to_owned(),
                            "Shopify storefront cookie".to_owned(),
                            ProductSignalKind::Strong,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if shopify_cart_response(response, path) {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Shopify",
                            ProductLayer::Ecommerce,
                            "shopify:validated-cart-api".to_owned(),
                            format!("Validated Shopify cart API response at {}", response.url),
                            ProductSignalKind::Validated,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
            });
            ({
                let (response, lower, generator, generator_lower, path, signals): (
                    &HttpObservation,
                    &str,
                    Option<&str>,
                    &str,
                    &str,
                    &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                ) = (
                    response,
                    &lower,
                    generator.as_deref(),
                    &generator_lower,
                    &path,
                    signals,
                );

                for (needle, product, layer) in [
                    ("sulu", "Sulu", ProductLayer::Cms),
                    ("silverstripe", "Silverstripe", ProductLayer::Cms),
                    ("bigcommerce", "BigCommerce", ProductLayer::Ecommerce),
                    ("prestashop", "PrestaShop", ProductLayer::Ecommerce),
                    ("opencart", "OpenCart", ProductLayer::Ecommerce),
                ] {
                    if generator_lower.contains(needle) {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                product,
                                layer,
                                format!("{needle}:generator"),
                                format!("Generator metadata: {}", generator.unwrap_or_default()),
                                ProductSignalKind::StrongExplicit,
                                generator.and_then(|value| {
                                    let (value, product): (&str, &str) = (value, product);
                                    let inlined_result: Option<String> = {
                                        'inlined_extract_version: {
                                            let lower = value.to_ascii_lowercase();
                                            let index =
                                                match lower.find(&product.to_ascii_lowercase()) {
                                                    Some(value) => value,
                                                    None => break 'inlined_extract_version None,
                                                } + product.len();
                                            let remainder = value[index..]
                                                .trim_start_matches(['/', ' ', '-', '_']);
                                            let version = remainder
                                                .chars()
                                                .take_while(|character| {
                                                    character.is_ascii_alphanumeric()
                                                        || matches!(character, '.' | '-' | '_')
                                                })
                                                .collect::<String>();
                                            if version
                                                .chars()
                                                .any(|character| character.is_ascii_digit())
                                            {
                                                Some(version)
                                            } else {
                                                None
                                            }
                                        }
                                    };
                                    inlined_result
                                }),
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                }
                for (needle, product, layer, source, evidence) in [
                    (
                        "/resources/vendor/silverstripe/",
                        "Silverstripe",
                        ProductLayer::Cms,
                        "silverstripe:resource",
                        "Silverstripe vendor resource path",
                    ),
                    (
                        "silverstripe.security",
                        "Silverstripe",
                        ProductLayer::Cms,
                        "silverstripe:global",
                        "Silverstripe client-side marker",
                    ),
                    (
                        "stencil-utils",
                        "BigCommerce",
                        ProductLayer::Ecommerce,
                        "bigcommerce:stencil",
                        "BigCommerce Stencil asset",
                    ),
                    (
                        "cdn11.bigcommerce.com",
                        "BigCommerce",
                        ProductLayer::Ecommerce,
                        "bigcommerce:cdn",
                        "BigCommerce CDN asset URL",
                    ),
                    (
                        "stencilbootstrap",
                        "BigCommerce",
                        ProductLayer::Ecommerce,
                        "bigcommerce:global",
                        "BigCommerce Stencil JavaScript global",
                    ),
                    (
                        "window.prestashop",
                        "PrestaShop",
                        ProductLayer::Ecommerce,
                        "prestashop:global",
                        "PrestaShop JavaScript global",
                    ),
                    (
                        "prestashop.modules",
                        "PrestaShop",
                        ProductLayer::Ecommerce,
                        "prestashop:module",
                        "PrestaShop module marker",
                    ),
                    (
                        "/modules/ps_",
                        "PrestaShop",
                        ProductLayer::Ecommerce,
                        "prestashop:module-path",
                        "PrestaShop module asset path",
                    ),
                    (
                        "/themes/classic/assets/",
                        "PrestaShop",
                        ProductLayer::Ecommerce,
                        "prestashop:theme-path",
                        "PrestaShop classic-theme asset path",
                    ),
                    (
                        "catalog/view/theme/",
                        "OpenCart",
                        ProductLayer::Ecommerce,
                        "opencart:theme",
                        "OpenCart theme asset path",
                    ),
                    (
                        "route=common/home",
                        "OpenCart",
                        ProductLayer::Ecommerce,
                        "opencart:route",
                        "OpenCart storefront route",
                    ),
                ] {
                    if lower.contains(needle) {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                product,
                                layer,
                                source.to_owned(),
                                evidence.to_owned(),
                                ProductSignalKind::Strong,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                }
                for (header, product, layer) in [
                    ("x-silverstripe-cache", "Silverstripe", ProductLayer::Cms),
                    (
                        "x-bigcommerce-stencil-profiler",
                        "BigCommerce",
                        ProductLayer::Ecommerce,
                    ),
                    ("x-bc-store-hash", "BigCommerce", ProductLayer::Ecommerce),
                ] {
                    if response
                        .headers
                        .iter()
                        .any(|(name, _)| name.eq_ignore_ascii_case(header))
                    {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                product,
                                layer,
                                format!("header:{header}"),
                                format!("{header} response header"),
                                ProductSignalKind::StrongExplicit,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                }
                for (needle, product, source, evidence) in [
                    (
                        "fornax_anonymousid",
                        "BigCommerce",
                        "bigcommerce:cookie",
                        "BigCommerce Fornax cookie",
                    ),
                    (
                        "shop_session_token",
                        "BigCommerce",
                        "bigcommerce:session-cookie",
                        "BigCommerce shop session cookie",
                    ),
                    (
                        "prestashop-",
                        "PrestaShop",
                        "prestashop:cookie",
                        "PrestaShop cookie name",
                    ),
                    (
                        "ocsessid",
                        "OpenCart",
                        "opencart:cookie",
                        "OpenCart session cookie",
                    ),
                ] {
                    if {
                        let (response, needle): (&HttpObservation, &str) = (response, needle);
                        {
                            ({
                                let (response, name): (&crate::HttpObservation, &str) =
                                    (response, "set-cookie");
                                response
                                    .headers
                                    .iter()
                                    .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                                    .map(|(_, value)| value.as_str())
                            })
                            .any(|value| {
                                value
                                    .to_ascii_lowercase()
                                    .contains(&needle.to_ascii_lowercase())
                            })
                        }
                    } {
                        ({
                            let (signals, name, layer, source, evidence, kind, version): (
                                &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                                &'static str,
                                ProductLayer,
                                String,
                                String,
                                ProductSignalKind,
                                Option<String>,
                            ) = (
                                signals,
                                product,
                                ProductLayer::Ecommerce,
                                source.to_owned(),
                                evidence.to_owned(),
                                ProductSignalKind::Strong,
                                None,
                            );

                            signals
                                .entry((name, layer))
                                .or_default()
                                .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                    source,
                                    evidence,
                                    kind,
                                    version,
                                });
                        });
                    }
                }
                if {
                    let (response, path): (&HttpObservation, &str) = (response, path);
                    {
                        path.trim_end_matches('/') == "/security/login"
                            && (200..300).contains(&response.status)
                            && login_page_evidence(response).is_some()
                            && String::from_utf8_lossy(&response.body)
                                .to_ascii_lowercase()
                                .contains("silverstripe")
                    }
                } {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "Silverstripe",
                            ProductLayer::Cms,
                            "silverstripe:validated-login".to_owned(),
                            format!("Validated Silverstripe login response at {}", response.url),
                            ProductSignalKind::Validated,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if bigcommerce_api_response(response, path) {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "BigCommerce",
                            ProductLayer::Ecommerce,
                            "bigcommerce:validated-api".to_owned(),
                            format!("Validated BigCommerce Storefront API at {}", response.url),
                            ProductSignalKind::Validated,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
                if {
                    let (response, path): (&HttpObservation, &str) = (response, path);
                    {
                        path.contains("route=account/login")
                            && (200..300).contains(&response.status)
                            && login_page_evidence(response).is_some()
                            && (String::from_utf8_lossy(&response.body)
                                .to_ascii_lowercase()
                                .contains("opencart")
                                || String::from_utf8_lossy(&response.body)
                                    .to_ascii_lowercase()
                                    .contains("route=account/forgotten"))
                    }
                } {
                    ({
                        let (signals, name, layer, source, evidence, kind, version): (
                            &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                            &'static str,
                            ProductLayer,
                            String,
                            String,
                            ProductSignalKind,
                            Option<String>,
                        ) = (
                            signals,
                            "OpenCart",
                            ProductLayer::Ecommerce,
                            "opencart:validated-login".to_owned(),
                            format!("Validated OpenCart account login page at {}", response.url),
                            ProductSignalKind::Validated,
                            None,
                        );

                        signals
                            .entry((name, layer))
                            .or_default()
                            .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                                source,
                                evidence,
                                kind,
                                version,
                            });
                    });
                }
            });

            if {
                let (response,): (&HttpObservation,) = (response,);
                {
                    'inlined_is_storefront_document: {
                        if !(200..300).contains(&response.status) || response.body.is_empty() {
                            break 'inlined_is_storefront_document false;
                        }
                        let path = {
                            let (response,): (&HttpObservation,) = (response,);
                            {
                                Url::parse(&response.url)
                                    .ok()
                                    .map(|url| url_path(&url))
                                    .unwrap_or_default()
                                    .to_ascii_lowercase()
                            }
                        };
                        matches!(path.as_str(), "/" | "/products" | "/products/")
                            && ({
                                let (response, name): (&crate::HttpObservation, &str) =
                                    (response, "content-type");
                                response
                                    .headers
                                    .iter()
                                    .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
                                    .map(|(_, value)| value.as_str())
                            })
                            .any(|value| value.to_ascii_lowercase().contains("html"))
                    }
                }
            } {
                ({
                    let (lower, signals): (&str, &mut HashMap<&'static str, String>) =
                        (&lower, &mut generic);

                    if lower.contains("schema.org/product")
                        || lower.contains("\"@type\":\"product\"")
                        || lower.contains("\"@type\": \"product\"")
                        || lower.contains("class=\"product-price")
                        || lower.contains("class='product-price")
                    {
                        signals.insert(
                            "product",
                            "Product structured data or product-price markup".to_owned(),
                        );
                    }
                    if lower.contains("schema.org/offer")
                        || lower.contains("\"@type\":\"offer\"")
                        || lower.contains("\"pricecurrency\"")
                        || lower.contains("itemprop=\"price\"")
                    {
                        signals.insert("offer", "Offer or price structured data".to_owned());
                    }
                    if lower.contains("add-to-cart")
                        || lower.contains("add_to_cart")
                        || lower.contains("href=\"/cart")
                        || lower.contains("href='/cart")
                        || lower.contains("cart-count")
                    {
                        signals.insert("cart", "Cart control or cart route markup".to_owned());
                    }
                    if lower.contains("href=\"/checkout")
                        || lower.contains("href='/checkout")
                        || lower.contains("checkout-button")
                        || lower.contains("begin-checkout")
                    {
                        signals.insert(
                            "checkout",
                            "Checkout control or checkout route markup".to_owned(),
                        );
                    }
                    if lower.contains("js.stripe.com")
                        || lower.contains("paypal.com/sdk/js")
                        || lower.contains("klarna")
                        || lower.contains("afterpay")
                        || lower.contains("adyen")
                    {
                        signals.insert("payment", "Third-party payment client script".to_owned());
                    }
                });
            }
        }
        let has_product = generic.contains_key("product") || generic.contains_key("offer");
        let has_transaction = generic.contains_key("checkout") || generic.contains_key("payment");
        if generic.len() >= 3 && has_product && generic.contains_key("cart") && has_transaction {
            let mut evidence = generic.into_iter().collect::<Vec<_>>();
            evidence.sort_by_key(|(category, _)| *category);
            for (category, item) in evidence {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "Generic commerce",
                        ProductLayer::Ecommerce,
                        format!("commerce:{category}"),
                        item,
                        ProductSignalKind::Indirect,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: product_signal_observations(&source, &evidence, version.as_deref(), evidence_response, endpoint),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
        }
    });
    ({
        let (signals,): (&mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,) =
            (&mut signals,);
        'inlined_record_totara_moodle_ancestry: {
            let Some(totara) = signals.get(&("Totara", ProductLayer::Cms)).cloned() else {
                break 'inlined_record_totara_moodle_ancestry;
            };
            for signal in totara {
                ({
                    let (signals, name, layer, source, evidence, kind, version): (
                        &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
                        &'static str,
                        ProductLayer,
                        String,
                        String,
                        ProductSignalKind,
                        Option<String>,
                    ) = (
                        signals,
                        "Moodle",
                        ProductLayer::Cms,
                        format!("moodle:totara-ancestry:{}", signal.source),
                        format!("Moodle-derived Totara platform: {}", signal.evidence),
                        signal.kind,
                        None,
                    );

                    signals
                        .entry((name, layer))
                        .or_default()
                        .push(ProductSignal {
                            observations: technology_evidence::inferred(&signal.observations, "Totara"),
                            source,
                            evidence,
                            kind,
                            version,
                        });
                });
            }
        }
    });
    for ((name, layer), mut product_signals) in signals {
        let observations = product_signals.iter().flat_map(|signal| signal.observations.iter().cloned()).collect::<Vec<_>>();
        product_signals.sort_by(|left, right| left.evidence.cmp(&right.evidence));
        product_signals.dedup_by(|left, right| left.evidence == right.evidence);
        let strong_count = product_signals
            .iter()
            .filter(|signal| {
                matches!(
                    signal.kind,
                    ProductSignalKind::Validated
                        | ProductSignalKind::CatalogHigh
                        | ProductSignalKind::StrongExplicit
                        | ProductSignalKind::Strong
                )
            })
            .map(|signal| signal.source.as_str())
            .collect::<HashSet<_>>()
            .len();
        let explicit = product_signals
            .iter()
            .any(|signal| matches!(signal.kind, ProductSignalKind::StrongExplicit));
        let validated = product_signals.iter().any(|signal| {
            matches!(
                signal.kind,
                ProductSignalKind::Validated | ProductSignalKind::CatalogHigh
            )
        });
        let confidence = if validated || strong_count >= 2 {
            Confidence::High
        } else if explicit {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        let version = product_signals
            .iter()
            .filter(|signal| match confidence {
                Confidence::High => matches!(
                    signal.kind,
                    ProductSignalKind::Validated
                        | ProductSignalKind::CatalogHigh
                        | ProductSignalKind::StrongExplicit
                ),
                Confidence::Medium => matches!(signal.kind, ProductSignalKind::StrongExplicit),
                _ => true,
            })
            .find_map(|signal| signal.version.clone());
        let evidence = product_signals
            .into_iter()
            .map(|signal| signal.evidence)
            .collect::<Vec<_>>();
        for item in evidence {
            add_product(endpoint, name, layer, version.clone(), confidence, item);
        }
        if let Some(product) = endpoint.products.iter_mut().find(|product| product.layer == layer && product.name.eq_ignore_ascii_case(name)) {
            product.observations.retain(|record| record.match_source != "Supporting product detection");
            product.observations.extend(observations);
            product.observations.sort();
            product.observations.dedup();
        }
    }
    for product in &mut endpoint.products {
        if let Some(records) = web_observations.remove(&product.name.to_ascii_lowercase()) {
            product.observations.retain(|record| record.match_source != "Supporting product detection");
            product.observations.extend(records);
            product.observations.sort();
            product.observations.dedup();
        }
    }
    if matches!(endpoint.service, ServiceKind::Http | ServiceKind::Https)
        && endpoint.products.is_empty()
    {
        endpoint
            .evidence
            .push("HTTP service confirmed; product undisclosed".to_owned());
    }
}

const ROCKET_NOT_FOUND: &[u8] = br#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="color-scheme" content="light dark">
    <title>404 Not Found</title>
</head>
<body align="center">
    <div role="main" align="center">
        <h1>404: Not Found</h1>
        <p>The requested resource could not be found.</p>
        <hr />
    </div>
    <div role="contentinfo" align="center">
        <small>Rocket</small>
    </div>
</body>
</html>"#;

const WERKZEUG_NOT_FOUND: &[u8] = b"<!doctype html>\n<html lang=en>\n<title>404 Not Found</title>\n<h1>Not Found</h1>\n<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>\n";

const DJANGO_NOT_FOUND: &[u8] = b"\n<!doctype html>\n<html lang=\"en\">\n<head>\n  <title>Not Found</title>\n</head>\n<body>\n  <h1>Not Found</h1><p>The requested resource was not found on this server.</p>\n</body>\n</html>\n";

pub(super) fn reconcile_web_server_products(endpoints: &mut [EndpointScan], cancel: &CancellationToken) {
    if cancel.is_cancelled() {
        return;
    }
    for endpoint in endpoints {
        if cancel.is_cancelled() {
            return;
        }
        for response in &endpoint.http {
            if cancel.is_cancelled() {
                return;
            }
            let detections = detect_web_servers(
                response
                    .headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
                &response.body,
                Some(response.status),
                Some(&response.url),
            );
            for detection in detections {
                let layer = match detection.role {
                    WebProductRole::Server => ProductLayer::Server,
                    WebProductRole::Proxy => ProductLayer::Proxy,
                    WebProductRole::Framework => ProductLayer::Framework,
                    WebProductRole::Runtime => ProductLayer::Runtime,
                };
                if let Some(product) = endpoint.products.iter_mut().find(|product| {
                    product.layer == layer && product.name.eq_ignore_ascii_case(detection.product)
                }) {
                    product.name = detection.product.to_owned();
                    let confidence = match detection.confidence {
                        FingerprintConfidence::High => Confidence::High,
                        FingerprintConfidence::Medium => Confidence::Medium,
                    };
                    if confidence > product.confidence
                        || confidence == product.confidence && detection.version.is_some()
                    {
                        product.version = detection.version;
                    }
                    product.confidence = product.confidence.max(confidence);
                    product.evidence.extend(detection.evidence);
                    for mut record in detection.observations {
                        technology_evidence::locate(&mut record, &response.url, Some(std::net::SocketAddr::new(endpoint.ip, endpoint.port).to_string()), Some(&response.method), Some(response.status), response.body_truncated);
                        product.observations.push(record);
                    }
                    product.observations.sort();
                    product.observations.dedup();
                    product.evidence.sort();
                    product.evidence.dedup();
                }
            }
        }
    }
}

#[derive(Default)]
struct ProductHtmlSink(RefCell<Vec<Tag>>);

impl TokenSink for ProductHtmlSink {
    type Handle = ();

    fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
        if let TagToken(tag) = token {
            let result = if tag.kind == StartTag {
                match tag.name.as_ref() {
                    "script" => TokenSinkResult::RawData(RawKind::ScriptData),
                    "style" | "xmp" | "iframe" | "noembed" | "noframes" => {
                        TokenSinkResult::RawData(RawKind::Rawtext)
                    }
                    "title" | "textarea" => TokenSinkResult::RawData(RawKind::Rcdata),
                    "plaintext" => TokenSinkResult::Plaintext,
                    _ => TokenSinkResult::Continue,
                }
            } else {
                TokenSinkResult::Continue
            };
            self.0.borrow_mut().push(tag);
            return result;
        }
        TokenSinkResult::Continue
    }
}

fn product_signal_observations(
    source: &str,
    evidence: &str,
    version: Option<&str>,
    response: Option<&HttpObservation>,
    endpoint: &EndpointScan,
) -> Vec<TechnologyEvidence> {
    let mut records = Vec::new();
    if let Some(response) = response {
        let body = String::from_utf8_lossy(&response.body);
        let lower = body.to_ascii_lowercase();
        if source.starts_with("header:") || source.ends_with("header") {
            for (name, value) in &response.headers {
                if source.strip_prefix("header:").is_some_and(|header| name.eq_ignore_ascii_case(header))
                    || evidence.to_ascii_lowercase().contains(&name.to_ascii_lowercase())
                {
                    records.push(technology_evidence::observation(&format!("Header {name}"), &finding_assessment::safe_evidence(&format!("{name}: {value}"))));
                }
            }
        } else if source.contains("cookie") {
            for (name, value) in &response.headers {
                if name.eq_ignore_ascii_case("set-cookie") {
                    let cookie = value.split('=').next().unwrap_or_default().trim();
                    let lower_cookie = cookie.to_ascii_lowercase();
                    let product = source.split(':').next().unwrap_or(source);
                    if !cookie.is_empty() && (source.contains(&lower_cookie) || evidence.to_ascii_lowercase().contains(&lower_cookie) || lower_cookie.contains(product)) {
                        records.push(technology_evidence::observation("Set-Cookie name", &format!("{cookie}=[value withheld]")));
                    }
                }
            }
        } else if source.contains("generator") {
            if let Some((_, value)) = evidence.split_once(": ") {
                records.push(technology_evidence::observation("Generator metadata", value));
            }
        } else {
            let markers: &[&str] = match source {
                "body:spring-marker" => &["whitelabel error page"],
                "body:tomcat-marker" => &["apache tomcat", "apache-tomcat"],
                "django:csrf-form" => &["csrfmiddlewaretoken"],
                "django:csrf-error" => &["csrf verification failed"],
                "fastapi:branded-api-document" => &["fastapi", "openapi"],
                "moodle:page-config" => &["m.cfg"],
                "moodle:php-assets" => &["/theme/styles.php", "/lib/javascript.php", "/theme/javascript.php"],
                "moodle:powered-by" | "moodle:generic-prose" => &["moodle"],
                "totara:tui-assets" => &["/totara/tui/", "tui"],
                "totara:core-resource" => &["totara_core", "totara/core"],
                "totara:page-config" => &["totara"],
                "totara:powered-by" | "totara:generic-prose" => &["totara"],
                "wordpress:content-path" => &["wp-content/"],
                "wordpress:includes-path" => &["wp-includes/"],
                "wordpress:api-link" => &["api.w.org"],
                "wordpress:validated-login" => &["user_login", "wp-submit", "wp-login.php"],
                "wordpress:validated-api" => &["\"namespaces\"", "wp/v2"],
                "woocommerce:assets" => &["woocommerce"],
                "woocommerce:class" => &["woocommerce"],
                "woocommerce:cart-script" => &["wc-cart-fragments"],
                "woocommerce:global" => &["wc_add_to_cart_params", "woocommerce_params"],
                "woocommerce:validated-api" => &["wc/v3", "wc/v2", "woocommerce"],
                "magento:module" => &["magento_"],
                "magento:mage-asset" => &["/mage/"],
                "magento:versioned-asset" => &["/static/version"],
                "magento:javascript" => &["mage/cookies", "mage/translate"],
                "magento:validated-api" => &["\"base_currency_code\"", "\"website_id\""],
                "shopify:cdn" => &["cdn.shopify.com"],
                "shopify:asset-path" => &["/cdn/shop/"],
                "shopify:global-theme" => &["shopify.theme"],
                "shopify:global-routes" => &["shopify.routes"],
                "shopify:section-markup" => &["shopify-section"],
                "shopify:data-markup" => &["data-shopify"],
                "shopify:validated-cart-api" => &["\"item_count\"", "\"total_price\""],
                "silverstripe:resource" => &["/resources/vendor/silverstripe/"],
                "silverstripe:global" => &["silverstripe"],
                "silverstripe:validated-login" => &["memberloginform", "security/login"],
                "bigcommerce:stencil" => &["stencil"],
                "bigcommerce:cdn" => &["cdn.bigcommerce.com"],
                "bigcommerce:global" => &["bcdata"],
                "bigcommerce:validated-api" => &["\"cartamount\"", "\"lineitems\""],
                "prestashop:global" => &["prestashop"],
                "prestashop:module" => &["prestashop"],
                "prestashop:module-path" => &["/modules/"],
                "prestashop:theme-path" => &["/themes/"],
                "opencart:theme" => &["catalog/view/theme/"],
                "opencart:route" => &["route=common/home"],
                "opencart:validated-login" => &["route=account/login"],
                _ => &[],
            };
            for marker in markers {
                if let Some(start) = lower.find(marker) {
                    let (value, shortened) = technology_evidence::excerpt(&body, start..start + marker.len());
                    let mut record = technology_evidence::observation(&format!("Body signature: {source}"), &value);
                    record.excerpt_shortened = shortened;
                    records.push(record);
                }
            }
            if records.is_empty() && source.starts_with("behavior:") {
                records.push(technology_evidence::observation("Matched default / error response", &body));
            }
            if records.is_empty() && (evidence.contains("route:") || evidence.contains("reference:")) {
                if let Some((_, value)) = evidence.split_once(": ") {
                    records.push(technology_evidence::observation("Matched asset reference", value));
                }
            }
        }
    }
    if records.is_empty() {
        records.push(TechnologyEvidence {
            match_source: source.to_owned(),
            supporting_detection: Some(technology_evidence::safe_value(evidence)),
            ..Default::default()
        });
    }
    for record in &mut records {
        record.extracted_version = version.map(technology_evidence::safe_value);
        record.endpoint = Some(std::net::SocketAddr::new(endpoint.ip, endpoint.port).to_string());
        if let Some(response) = response {
            technology_evidence::locate(record, &response.url, record.endpoint.clone(), Some(&response.method), Some(response.status), response.body_truncated);
        }
    }
    records
}

fn product_html_tags(body: &str) -> Vec<Tag> {
    let input = BufferQueue::default();
    input.push_back(StrTendril::from(body));
    let tokenizer = Tokenizer::new(ProductHtmlSink::default(), Default::default());
    let _ = tokenizer.feed(&input);
    tokenizer.end();
    tokenizer.sink.0.into_inner()
}

pub(super) fn wordpress_login_response(response: &HttpObservation) -> bool {
    if !(200..300).contains(&response.status) {
        return false;
    }
    let Ok(base) = Url::parse(&response.url) else {
        return false;
    };
    let mut form = None;
    for tag in product_html_tags(&String::from_utf8_lossy(&response.body)) {
        match (tag.kind, tag.name.as_ref()) {
            (StartTag, "form") => {
                form = ({
                    let (tag, name): (&'_ Tag, &str) = (&tag, "action");
                    let inlined_result: Option<&'_ str> = {
                        tag.attrs
                            .iter()
                            .find(|attribute| attribute.name.local.as_ref() == name)
                            .map(|attribute| attribute.value.as_ref())
                    };
                    inlined_result
                })
                .and_then(|action| base.join(action.trim()).ok())
                .filter(|url| same_origin(&base, url) && url.path().ends_with("/wp-login.php"))
                .map(|_| (false, false));
            }
            (EndTag, "form") => form = None,
            (StartTag, "input") => {
                if let Some((log, pwd)) = &mut form {
                    match {
                        let (tag, name): (&'_ Tag, &str) = (&tag, "name");
                        let inlined_result: Option<&'_ str> = {
                            tag.attrs
                                .iter()
                                .find(|attribute| attribute.name.local.as_ref() == name)
                                .map(|attribute| attribute.value.as_ref())
                        };
                        inlined_result
                    } {
                        Some("log") => *log = true,
                        Some("pwd") => *pwd = true,
                        _ => {}
                    }
                    if *log && *pwd {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

pub(super) fn wordpress_api_response(response: &HttpObservation) -> bool {
    let Ok(url) = Url::parse(&response.url) else {
        return false;
    };
    if url.path().trim_end_matches('/') != "/wp-json"
        && !(url.path() == "/"
            && url
                .query_pairs()
                .any(|(name, value)| name == "rest_route" && value == "/"))
    {
        return false;
    }
    ({
        let (response,): (&HttpObservation,) = (response,);
        let inlined_result: Option<serde_json::Value> = {
            (200..300)
                .contains(&response.status)
                .then(|| serde_json::from_slice(&response.body).ok())
                .flatten()
        };
        inlined_result
    })
    .is_some_and(|json| {
        json.get("namespaces")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|namespaces| {
                namespaces
                    .iter()
                    .any(|namespace| namespace.as_str() == Some("wp/v2"))
            })
            && json.get("routes").is_some_and(serde_json::Value::is_object)
    })
}

fn woocommerce_api_response(response: &HttpObservation, path: &str) -> bool {
    path.starts_with("/wp-json/wc/store/v1")
        && ({
            let (response,): (&HttpObservation,) = (response,);
            let inlined_result: Option<serde_json::Value> = {
                (200..300)
                    .contains(&response.status)
                    .then(|| serde_json::from_slice(&response.body).ok())
                    .flatten()
            };
            inlined_result
        })
        .is_some_and(|json| {
            json.get("routes").is_some()
                || json.get("namespace").is_some()
                || json.to_string().to_ascii_lowercase().contains("wc/store")
        })
}

fn magento_api_response(response: &HttpObservation, path: &str) -> bool {
    path == "/rest/v1/store/storeconfigs"
        && ({
            let (response,): (&HttpObservation,) = (response,);
            let inlined_result: Option<serde_json::Value> = {
                (200..300)
                    .contains(&response.status)
                    .then(|| serde_json::from_slice(&response.body).ok())
                    .flatten()
            };
            inlined_result
        })
        .is_some_and(|json| {
            let text = json.to_string().to_ascii_lowercase();
            text.contains("base_url")
                && (text.contains("website_id") || text.contains("store_name"))
        })
}

fn shopify_cart_response(response: &HttpObservation, path: &str) -> bool {
    path == "/cart.js"
        && ({
            let (response,): (&HttpObservation,) = (response,);
            let inlined_result: Option<serde_json::Value> = {
                (200..300)
                    .contains(&response.status)
                    .then(|| serde_json::from_slice(&response.body).ok())
                    .flatten()
            };
            inlined_result
        })
        .is_some_and(|json| {
            json.get("items").is_some()
                && json.get("item_count").is_some()
                && json.get("token").is_some()
        })
}

fn bigcommerce_api_response(response: &HttpObservation, path: &str) -> bool {
    path == "/api/storefront/store-context"
        && ({
            let (response,): (&HttpObservation,) = (response,);
            let inlined_result: Option<serde_json::Value> = {
                (200..300)
                    .contains(&response.status)
                    .then(|| serde_json::from_slice(&response.body).ok())
                    .flatten()
            };
            inlined_result
        })
        .is_some_and(|json| {
            let text = json.to_string().to_ascii_lowercase();
            text.contains("storehash") || text.contains("store_hash") || text.contains("storeid")
        })
}

pub(super) fn record_observed_web_surfaces(endpoint: &mut EndpointScan) {
    let technologies = endpoint
        .products
        .iter()
        .filter(|product| matches!(product.layer, ProductLayer::Cms | ProductLayer::Ecommerce))
        .map(|product| product.name.as_str())
        .collect::<HashSet<_>>();
    if technologies.is_empty() {
        return;
    }
    let baselines = endpoint
        .http
        .iter()
        .filter(|response| response.url.contains("/nancy-exposure-not-found-"))
        .collect::<Vec<_>>();
    let mut surfaces = std::mem::take(&mut endpoint.observed_web_surfaces);
    for response in &endpoint.http {
        if !response.method.eq_ignore_ascii_case("GET")
            || !({
                let (response, endpoint_port): (&HttpObservation, u16) = (response, endpoint.port);
                {
                    Url::parse(&response.url)
                        .ok()
                        .and_then(|url| url.port_or_known_default())
                        == Some(endpoint_port)
                }
            })
            || (!((200..300).contains(&response.status)) && !matches!(response.status, 401 | 403))
        {
            continue;
        }
        if response_is_soft_404(response, &baselines) {
            continue;
        }
        let path = {
            let (response,): (&HttpObservation,) = (response,);
            {
                Url::parse(&response.url)
                    .ok()
                    .map(|url| url_path(&url))
                    .unwrap_or_default()
                    .to_ascii_lowercase()
            }
        };
        let mut candidates = Vec::new();
        if wordpress_login_response(response) && technologies.contains("WordPress") {
            candidates.push((
                "WordPress",
                WebSurfaceType::Login,
                Confidence::High,
                "WordPress login form targeting wp-login.php with log and pwd inputs".to_owned(),
            ));
        }
        if wordpress_api_response(response) && technologies.contains("WordPress") {
            candidates.push((
                "WordPress",
                WebSurfaceType::Api,
                Confidence::High,
                "Validated WordPress REST API response".to_owned(),
            ));
        }
        if woocommerce_api_response(response, &path) && technologies.contains("WooCommerce") {
            candidates.push((
                "WooCommerce",
                WebSurfaceType::Api,
                Confidence::High,
                "Validated WooCommerce Store API response".to_owned(),
            ));
        }
        if magento_api_response(response, &path)
            && (technologies.contains("Magento") || technologies.contains("Adobe Commerce"))
        {
            let technology = if technologies.contains("Adobe Commerce") {
                "Adobe Commerce"
            } else {
                "Magento"
            };
            candidates.push((
                technology,
                WebSurfaceType::Api,
                Confidence::High,
                "Validated Magento store configuration API response".to_owned(),
            ));
        }
        if shopify_cart_response(response, &path) && technologies.contains("Shopify") {
            candidates.push((
                "Shopify",
                WebSurfaceType::Cart,
                Confidence::High,
                "Validated Shopify cart API response".to_owned(),
            ));
        }
        if bigcommerce_api_response(response, &path) && technologies.contains("BigCommerce") {
            candidates.push((
                "BigCommerce",
                WebSurfaceType::Api,
                Confidence::High,
                "Validated BigCommerce Storefront API response".to_owned(),
            ));
        }

        for technology in &technologies {
            let classified = {
                let (technology, path): (&str, &str) = (technology, &path);
                {
                    let bare_path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
                    match technology {
                        "WordPress" if bare_path == "/wp-login.php" => Some(WebSurfaceType::Login),
                        "WordPress" if bare_path == "/wp-admin" => Some(WebSurfaceType::Admin),
                        "Moodle" | "Totara" if bare_path == "/login/index.php" => {
                            Some(WebSurfaceType::Login)
                        }
                        "WooCommerce" if matches!(bare_path, "/cart" | "/basket") => {
                            Some(WebSurfaceType::Cart)
                        }
                        "WooCommerce" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
                        "Magento" | "Adobe Commerce" if bare_path == "/customer/account/login" => {
                            Some(WebSurfaceType::Login)
                        }
                        "Magento" | "Adobe Commerce" if bare_path == "/admin" => {
                            Some(WebSurfaceType::Admin)
                        }
                        "Magento" | "Adobe Commerce" if bare_path == "/checkout/cart" => {
                            Some(WebSurfaceType::Cart)
                        }
                        "Magento" | "Adobe Commerce" if bare_path == "/checkout" => {
                            Some(WebSurfaceType::Checkout)
                        }
                        "Shopify" if bare_path == "/account/login" => Some(WebSurfaceType::Login),
                        "Shopify" if bare_path == "/cart" => Some(WebSurfaceType::Cart),
                        "Shopify" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
                        "Silverstripe" if bare_path.eq_ignore_ascii_case("/security/login") => {
                            Some(WebSurfaceType::Login)
                        }
                        "Silverstripe" if bare_path == "/admin" => Some(WebSurfaceType::Admin),
                        "BigCommerce" if bare_path == "/login.php" => Some(WebSurfaceType::Login),
                        "BigCommerce" if matches!(bare_path, "/cart" | "/cart.php") => {
                            Some(WebSurfaceType::Cart)
                        }
                        "BigCommerce" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
                        "PrestaShop" if bare_path == "/login" => Some(WebSurfaceType::Login),
                        "PrestaShop" if bare_path == "/cart" => Some(WebSurfaceType::Cart),
                        "PrestaShop" if matches!(bare_path, "/checkout" | "/order") => {
                            Some(WebSurfaceType::Checkout)
                        }
                        "OpenCart" if path.contains("route=account/login") => {
                            Some(WebSurfaceType::Login)
                        }
                        "OpenCart" if path.contains("route=checkout/cart") => {
                            Some(WebSurfaceType::Cart)
                        }
                        "OpenCart" if path.contains("route=checkout/checkout") => {
                            Some(WebSurfaceType::Checkout)
                        }
                        "Generic commerce" if matches!(bare_path, "/cart" | "/basket") => {
                            Some(WebSurfaceType::Cart)
                        }
                        "Generic commerce" if bare_path == "/checkout" => {
                            Some(WebSurfaceType::Checkout)
                        }
                        _ => None,
                    }
                }
            };
            let Some(surface_type) = classified else {
                continue;
            };
            if candidates.iter().any(|(candidate, kind, _, _)| {
                candidate.eq_ignore_ascii_case(technology) && *kind == surface_type
            }) {
                continue;
            }
            let evidence = match surface_type {
                WebSurfaceType::Login => login_page_evidence(response),
                WebSurfaceType::Admin => {
                    let (response,): (&HttpObservation,) = (response,);
                    {
                        'inlined_admin_page_evidence: {
                            if matches!(response.status, 401 | 403) {
                                break 'inlined_admin_page_evidence Some(
                                    "Access-controlled administration route".to_owned(),
                                );
                            }
                            let lower =
                                String::from_utf8_lossy(&response.body).to_ascii_lowercase();
                            ((lower.contains("admin")
                                || lower.contains("dashboard")
                                || lower.contains("control panel"))
                                && (lower.contains("<form")
                                    || lower.contains("navigation")
                                    || lower.contains("menu")))
                            .then(|| "Administration page markers".to_owned())
                        }
                    }
                }
                WebSurfaceType::Cart => {
                    let (response,): (&HttpObservation,) = (response,);
                    {
                        'inlined_cart_page_evidence: {
                            if matches!(response.status, 401 | 403) {
                                break 'inlined_cart_page_evidence Some(
                                    "Access-controlled cart route".to_owned(),
                                );
                            }
                            let lower =
                                String::from_utf8_lossy(&response.body).to_ascii_lowercase();
                            (lower.contains("cart")
                                && [
                                    "quantity",
                                    "subtotal",
                                    "checkout",
                                    "remove",
                                    "item_count",
                                    "line-item",
                                ]
                                .iter()
                                .any(|marker| lower.contains(marker)))
                            .then(|| {
                                "Cart page contains item-management or checkout markers".to_owned()
                            })
                        }
                    }
                }
                WebSurfaceType::Checkout => {
                    let (response,): (&HttpObservation,) = (response,);
                    {
                        'inlined_checkout_page_evidence: {
                            if matches!(response.status, 401 | 403) {
                                break 'inlined_checkout_page_evidence Some(
                                    "Access-controlled checkout route".to_owned(),
                                );
                            }
                            let lower =
                                String::from_utf8_lossy(&response.body).to_ascii_lowercase();
                            (lower.contains("checkout")
                                && [
                                    "payment",
                                    "billing",
                                    "shipping",
                                    "place order",
                                    "order summary",
                                ]
                                .iter()
                                .any(|marker| lower.contains(marker)))
                            .then(|| "Checkout page contains order or payment markers".to_owned())
                        }
                    }
                }
                WebSurfaceType::Api => None,
            };
            if let Some(evidence) = evidence {
                candidates.push((*technology, surface_type, Confidence::Medium, evidence));
            }
        }
        for (technology, surface_type, confidence, evidence) in candidates {
            ({
                let (surfaces, technology, response, surface_type, confidence, evidence): (
                    &mut Vec<ObservedWebSurface>,
                    &str,
                    &HttpObservation,
                    WebSurfaceType,
                    Confidence,
                    Vec<String>,
                ) = (
                    &mut surfaces,
                    technology,
                    response,
                    surface_type,
                    confidence,
                    vec![
                        format!("GET {} returned {}", response.url, response.status),
                        evidence,
                    ],
                );
                'inlined_add_web_surface: {
                    if let Some(existing) = surfaces.iter_mut().find(|surface| {
                        surface.technology.eq_ignore_ascii_case(technology)
                            && surface.url == response.url
                            && surface.surface_type == surface_type
                    }) {
                        existing.confidence = existing.confidence.max(confidence);
                        existing.evidence.extend(evidence);
                        existing.evidence.sort();
                        existing.evidence.dedup();
                        break 'inlined_add_web_surface;
                    }
                    surfaces.push(ObservedWebSurface {
                        technology: technology.to_owned(),
                        url: response.url.clone(),
                        status: response.status,
                        surface_type,
                        confidence,
                        evidence,
                    });
                }
            });
        }
    }
    endpoint.observed_web_surfaces = surfaces;
}

pub(super) fn response_is_soft_404(
    response: &HttpObservation,
    baselines: &[&HttpObservation],
) -> bool {
    let Ok(candidate_url) = Url::parse(&response.url) else {
        return false;
    };
    baselines.iter().any(|baseline| {
        let Ok(baseline_url) = Url::parse(&baseline.url) else {
            return false;
        };
        same_origin(&candidate_url, &baseline_url)
            && looks_like_soft_404(
                baseline,
                response,
                baseline_url.path(),
                candidate_url.path(),
            )
    })
}

fn login_page_evidence(response: &HttpObservation) -> Option<String> {
    if matches!(response.status, 401 | 403) {
        return Some("Access-controlled login route".to_owned());
    }
    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    (lower.contains("<form")
        && (lower.contains("type=\"password\"") || lower.contains("type='password'"))
        && (lower.contains("login") || lower.contains("log in") || lower.contains("sign in")))
    .then(|| "Login form with a password control".to_owned())
}
