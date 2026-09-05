use super::*;

#[derive(Clone)]
struct ProductSignal {
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

pub(super) fn apply_product_rules(endpoint: &mut EndpointScan) {
    let mut signals: HashMap<(&'static str, ProductLayer), Vec<ProductSignal>> = HashMap::new();
    for response in &endpoint.http {
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
                record_product_signal(
                    &mut signals,
                    detection.product,
                    layer,
                    format!("web-server:{}", detection.identifier),
                    evidence,
                    kind,
                    detection.version.clone(),
                );
            }
        }
    }
    for response in &endpoint.http {
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
                        record_product_signal(
                            &mut signals,
                            product,
                            layer,
                            "header:server".to_owned(),
                            format!("Server: {value}"),
                            ProductSignalKind::StrongExplicit,
                            extract_version(value, needle),
                        );
                    }
                }
                if lower.contains("amazons3") || lower.contains("amazon") {
                    record_product_signal(
                        &mut signals,
                        "AWS",
                        ProductLayer::Cloud,
                        "header:server".to_owned(),
                        format!("Server: {value}"),
                        ProductSignalKind::StrongExplicit,
                        extract_version(value, "amazon"),
                    );
                }
            }
            if header == "x-powered-by" {
                for (needle, product, layer) in [
                    ("express", "Express", ProductLayer::Framework),
                    ("asp.net", "ASP.NET", ProductLayer::Framework),
                    ("php", "PHP", ProductLayer::Runtime),
                ] {
                    if contains_identity_token(&lower, needle) {
                        record_product_signal(
                            &mut signals,
                            product,
                            layer,
                            "header:x-powered-by".to_owned(),
                            format!("X-Powered-By: {value}"),
                            ProductSignalKind::StrongExplicit,
                            extract_version(value, needle),
                        );
                    }
                }
            }
            if matches!(header.as_str(), "server" | "x-powered-by" | "x-runtime")
                && lower
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .any(|token| token == "rust")
            {
                record_product_signal(
                    &mut signals,
                    "Rust",
                    ProductLayer::Runtime,
                    format!("header:{header}"),
                    format!("{name}: {value}"),
                    ProductSignalKind::StrongExplicit,
                    extract_version(value, "rust"),
                );
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
                    record_product_signal(
                        &mut signals,
                        product,
                        layer,
                        format!("header:{header}"),
                        format!("{name}: {value}"),
                        ProductSignalKind::Strong,
                        None,
                    );
                }
            }
            if header == "set-cookie" && lower.contains("jsessionid") {
                record_product_signal(
                    &mut signals,
                    "Apache Tomcat",
                    ProductLayer::Server,
                    "cookie:jsessionid".to_owned(),
                    "JSESSIONID cookie".to_owned(),
                    ProductSignalKind::Indirect,
                    None,
                );
                record_product_signal(
                    &mut signals,
                    "Spring",
                    ProductLayer::Framework,
                    "cookie:jsessionid".to_owned(),
                    "JSESSIONID cookie".to_owned(),
                    ProductSignalKind::Indirect,
                    None,
                );
            }
        }
        let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
        if body.contains("whitelabel error page") || body.contains("spring boot") {
            record_product_signal(
                &mut signals,
                "Spring",
                ProductLayer::Framework,
                "body:spring-marker".to_owned(),
                "Spring page marker".to_owned(),
                ProductSignalKind::Indirect,
                None,
            );
        }
        if body.contains("apache tomcat") {
            record_product_signal(
                &mut signals,
                "Apache Tomcat",
                ProductLayer::Server,
                "body:tomcat-marker".to_owned(),
                "Apache Tomcat page marker".to_owned(),
                ProductSignalKind::Indirect,
                None,
            );
        }
        record_framework_response_signals(response, &body, &mut signals);
    }
    record_active_backend_signals(endpoint, &mut signals);
    for tls in &endpoint.tls {
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
                    record_product_signal(
                        &mut signals,
                        product,
                        layer,
                        "tls:certificate-identity".to_owned(),
                        format!("TLS certificate subject/issuer contains {needle}"),
                        ProductSignalKind::Indirect,
                        None,
                    );
                }
            }
        }
    }
    record_web_product_signals(endpoint, &mut signals);
    record_totara_moodle_ancestry(&mut signals);
    for ((name, layer), mut product_signals) in signals {
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
            .find_map(|signal| signal.version.clone());
        let evidence = product_signals
            .into_iter()
            .map(|signal| signal.evidence)
            .collect::<Vec<_>>();
        for item in evidence {
            add_product(endpoint, name, layer, version.clone(), confidence, item);
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

fn record_framework_response_signals(
    response: &HttpObservation,
    lower: &str,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    for (cookie, product, source) in [
        ("REVEL_SESSION", "Revel", "revel:session-cookie"),
        ("REVEL_FLASH", "Revel", "revel:flash-cookie"),
        ("beegosessionID", "Beego", "beego:session-cookie"),
        ("csrftoken", "Django", "django:csrf-cookie"),
    ] {
        if set_cookie_name(response, cookie).is_some() {
            record_product_signal(
                signals,
                product,
                ProductLayer::Framework,
                source.to_owned(),
                format!("Framework-specific {cookie} cookie"),
                ProductSignalKind::StrongExplicit,
                None,
            );
        }
    }
    if lower.contains("name=\"csrfmiddlewaretoken\"")
        || lower.contains("name='csrfmiddlewaretoken'")
    {
        record_product_signal(
            signals,
            "Django",
            ProductLayer::Framework,
            "django:csrf-form".to_owned(),
            "Django csrfmiddlewaretoken form control".to_owned(),
            ProductSignalKind::StrongExplicit,
            None,
        );
    }
    if lower.contains("csrf verification failed. request aborted") {
        record_product_signal(
            signals,
            "Django",
            ProductLayer::Framework,
            "django:csrf-error".to_owned(),
            "Distinctive Django CSRF failure page".to_owned(),
            ProductSignalKind::CatalogHigh,
            None,
        );
    }
    if fastapi_branded_document(response) {
        record_product_signal(
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
    }
}

fn fastapi_branded_document(response: &HttpObservation) -> bool {
    crate::web_server::is_fastapi_branded_document(&response.url, &response.body)
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

fn record_active_backend_signals(
    endpoint: &EndpointScan,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    for baseline in endpoint.http.iter().filter(|response| {
        response.method.eq_ignore_ascii_case("GET") && is_random_not_found_path(response)
    }) {
        if baseline.status != 404 || baseline.body_truncated {
            continue;
        }
        let root_options = endpoint.http.iter().filter(|response| {
            response.method.eq_ignore_ascii_case("OPTIONS")
                && response_path(response).as_deref() == Some("/")
                && same_observation_origin(baseline, response)
        });

        if baseline.body.is_empty() {
            for options in root_options {
                if options.status != 405 || options.body_truncated || !options.body.is_empty() {
                    continue;
                }
                if has_single_exact_header(options, "allow", "GET,HEAD") {
                    record_backend_pair(
                        signals,
                        "Axum",
                        ProductLayer::Server,
                        "Rust",
                        "behavior:axum-default-routing",
                        "Random-path GET returned Axum-style empty 404 and OPTIONS / returned empty 405 with Allow: GET,HEAD",
                        ProductSignalKind::StrongExplicit,
                    );
                } else if has_actix_allow_header(options) {
                    record_backend_pair(
                        signals,
                        "Actix Web",
                        ProductLayer::Server,
                        "Rust",
                        "behavior:actix-default-routing",
                        "Random-path GET returned empty 404 and OPTIONS / returned an Actix-style empty 405 with a spaced Allow header",
                        ProductSignalKind::StrongExplicit,
                    );
                }
            }
        } else if rocket_not_found(baseline) {
            record_backend_pair(
                signals,
                "Rocket",
                ProductLayer::Server,
                "Rust",
                "behavior:rocket-default-catcher",
                "Random-path GET returned Rocket's complete default 404 catcher document",
                ProductSignalKind::StrongExplicit,
            );
        } else if go_net_http_not_found(baseline) {
            record_product_signal(
                signals,
                "Go",
                ProductLayer::Runtime,
                "behavior:go-net-http-not-found".to_owned(),
                "Random-path GET returned the canonical Go net/http 404 response".to_owned(),
                ProductSignalKind::StrongExplicit,
                None,
            );
        } else if gin_not_found(baseline)
            && endpoint.http.iter().any(|response| {
                response.method.eq_ignore_ascii_case("OPTIONS")
                    && response_path(response).as_deref() == Some("/")
                    && same_observation_origin(baseline, response)
                    && gin_not_found(response)
            })
        {
            record_backend_pair(
                signals,
                "Gin",
                ProductLayer::Framework,
                "Go",
                "behavior:gin-default-routing",
                "Random-path GET and OPTIONS / returned Gin's exact default no-route response",
                ProductSignalKind::StrongExplicit,
            );
        } else if fiber_not_found(baseline)
            && endpoint.http.iter().any(|response| {
                same_observation_origin(baseline, response)
                    && header_values(response, "server").any(|value| {
                        contains_identity_token(&value.to_ascii_lowercase(), "fasthttp")
                    })
            })
        {
            record_backend_pair(
                signals,
                "Fiber",
                ProductLayer::Framework,
                "Go",
                "behavior:fiber-fasthttp-routing",
                "Random-path GET returned Fiber's dynamic Cannot GET response and the origin exposed fasthttp",
                ProductSignalKind::StrongExplicit,
            );
        } else if echo_not_found(baseline) {
            record_product_signal(
                signals,
                "Go",
                ProductLayer::Runtime,
                "behavior:echo-default-error-envelope".to_owned(),
                "Random-path GET returned Echo's default JSON error envelope".to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        } else if starlette_not_found(baseline) {
            record_product_signal(
                signals,
                "Python",
                ProductLayer::Runtime,
                "behavior:starlette-default-error-envelope".to_owned(),
                "Random-path GET returned the generic FastAPI/Starlette JSON error envelope"
                    .to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        } else if werkzeug_not_found(baseline) {
            record_backend_pair(
                signals,
                "Werkzeug",
                ProductLayer::Server,
                "Python",
                "behavior:werkzeug-default-not-found",
                "Random-path GET returned Werkzeug's complete default 404 exception page",
                ProductSignalKind::StrongExplicit,
            );
        } else if django_not_found(baseline) {
            record_backend_pair(
                signals,
                "Django",
                ProductLayer::Framework,
                "Python",
                "behavior:django-production-not-found",
                "Random-path GET returned Django's complete production 404 page",
                ProductSignalKind::StrongExplicit,
            );
        }
    }

    record_aspnet_core_signals(endpoint, signals);
}

fn record_backend_pair(
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
    backend: &'static str,
    backend_layer: ProductLayer,
    runtime: &'static str,
    source: &'static str,
    evidence: &str,
    kind: ProductSignalKind,
) {
    for (name, layer) in [(backend, backend_layer), (runtime, ProductLayer::Runtime)] {
        record_product_signal(
            signals,
            name,
            layer,
            source.to_owned(),
            evidence.to_owned(),
            kind,
            None,
        );
    }
}

fn is_random_not_found_path(response: &HttpObservation) -> bool {
    response_path(response).is_some_and(|path| {
        path.strip_prefix("/nancy-exposure-not-found-")
            .is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    })
}

fn response_path(response: &HttpObservation) -> Option<String> {
    Url::parse(&response.url)
        .ok()
        .map(|url| url.path().to_owned())
}

fn same_observation_origin(left: &HttpObservation, right: &HttpObservation) -> bool {
    Url::parse(&left.url)
        .ok()
        .zip(Url::parse(&right.url).ok())
        .is_some_and(|(left, right)| same_origin(&left, &right))
}

fn has_single_exact_header(response: &HttpObservation, name: &str, expected: &str) -> bool {
    let mut values = header_values(response, name);
    values.next() == Some(expected) && values.next().is_none()
}

fn has_actix_allow_header(response: &HttpObservation) -> bool {
    let mut values = header_values(response, "allow");
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() || !value.contains(", ") {
        return false;
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

fn has_exact_content_type(response: &HttpObservation, expected: &str) -> bool {
    has_single_header_ignoring_ascii_case(response, "content-type", expected)
}

fn has_single_header_ignoring_ascii_case(
    response: &HttpObservation,
    name: &str,
    expected: &str,
) -> bool {
    let mut values = header_values(response, name);
    values
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
        && values.next().is_none()
}

fn rocket_not_found(response: &HttpObservation) -> bool {
    response.body == ROCKET_NOT_FOUND
        && has_exact_content_type(response, "text/html; charset=utf-8")
}

fn go_net_http_not_found(response: &HttpObservation) -> bool {
    response.body == b"404 page not found\n"
        && has_exact_content_type(response, "text/plain; charset=utf-8")
        && has_single_header_ignoring_ascii_case(response, "x-content-type-options", "nosniff")
}

fn gin_not_found(response: &HttpObservation) -> bool {
    response.status == 404
        && !response.body_truncated
        && response.body == b"404 page not found"
        && has_exact_content_type(response, "text/plain")
}

fn fiber_not_found(response: &HttpObservation) -> bool {
    let Some(path) = response_path(response) else {
        return false;
    };
    response.body == format!("Cannot GET {path}").as_bytes()
        && has_exact_content_type(response, "text/plain; charset=utf-8")
}

fn echo_not_found(response: &HttpObservation) -> bool {
    response.body == b"{\"message\":\"Not Found\"}\n"
        && has_exact_content_type(response, "application/json; charset=UTF-8")
}

fn starlette_not_found(response: &HttpObservation) -> bool {
    response.body == b"{\"detail\":\"Not Found\"}"
        && has_exact_content_type(response, "application/json")
}

fn werkzeug_not_found(response: &HttpObservation) -> bool {
    response.body == WERKZEUG_NOT_FOUND
        && has_exact_content_type(response, "text/html; charset=utf-8")
}

fn django_not_found(response: &HttpObservation) -> bool {
    response.body == DJANGO_NOT_FOUND
        && has_exact_content_type(response, "text/html; charset=utf-8")
}

fn record_aspnet_core_signals(
    endpoint: &EndpointScan,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    let mut cookie_names = endpoint
        .http
        .iter()
        .flat_map(|response| header_values(response, "set-cookie"))
        .filter_map(|value| value.split(';').next())
        .filter_map(|pair| pair.split_once('=').map(|(name, _)| name.trim()))
        .filter(|name| aspnet_core_cookie(name))
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
        record_backend_pair(
            signals,
            "ASP.NET Core",
            ProductLayer::Framework,
            ".NET",
            "behavior:aspnet-core-cookies",
            &evidence,
            ProductSignalKind::StrongExplicit,
        );
    }

    if endpoint.http.iter().any(aspnet_core_branded_page) {
        record_backend_pair(
            signals,
            "ASP.NET Core",
            ProductLayer::Framework,
            ".NET",
            "behavior:aspnet-core-branded-page",
            "ASP.NET Core branded hosting or developer error page",
            ProductSignalKind::StrongExplicit,
        );
    }
}

fn aspnet_core_cookie(name: &str) -> bool {
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

fn aspnet_core_branded_page(response: &HttpObservation) -> bool {
    if response.status < 500 {
        return false;
    }
    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    let hosting_error = lower.contains("http error 500.")
        && lower.contains("asp.net core")
        && lower.contains("common solutions to this issue");
    let startup_error = lower.contains("an error occurred while starting the application.")
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
}

fn contains_identity_token(value: &str, needle: &str) -> bool {
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

pub(super) fn reconcile_web_server_products(endpoints: &mut [EndpointScan]) {
    for endpoint in endpoints {
        for response in &endpoint.http {
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
                    if detection.version.is_some() {
                        product.version = detection.version;
                    }
                    product.confidence = product.confidence.max(match detection.confidence {
                        FingerprintConfidence::High => Confidence::High,
                        FingerprintConfidence::Medium => Confidence::Medium,
                    });
                    product.evidence.extend(detection.evidence);
                    product.evidence.sort();
                    product.evidence.dedup();
                }
            }
        }
    }
}

fn record_web_product_signals(
    endpoint: &EndpointScan,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    let mut generic = HashMap::<&'static str, String>::new();
    let baselines = endpoint
        .http
        .iter()
        .filter(|response| response.url.contains("/nancy-exposure-not-found-"))
        .collect::<Vec<_>>();
    for response in &endpoint.http {
        if !response_on_endpoint_port(response, endpoint.port)
            || (!((200..300).contains(&response.status)) && !matches!(response.status, 401 | 403))
            || response.url.contains("/nancy-exposure-not-found-")
            || response_is_soft_404(response, &baselines)
        {
            continue;
        }
        let body = String::from_utf8_lossy(&response.body);
        let lower = body.to_ascii_lowercase();
        let generator = html_generator(&body);
        let generator_lower = generator
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let path = response_path_query(response);
        for generator in html_generators(&body) {
            record_known_generator_signal(&generator, signals);
        }
        record_vendor_header_signals(response, signals);
        record_moodle_totara_signals(response, &body, &lower, &path, signals);

        if generator_lower.contains("wordpress") {
            record_product_signal(
                signals,
                "WordPress",
                ProductLayer::Cms,
                "wordpress:generator".to_owned(),
                format!(
                    "Generator metadata: {}",
                    generator.as_deref().unwrap_or_default()
                ),
                ProductSignalKind::StrongExplicit,
                generator
                    .as_deref()
                    .and_then(|value| extract_version(value, "WordPress")),
            );
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
                record_product_signal(
                    signals,
                    "WordPress",
                    ProductLayer::Cms,
                    source.to_owned(),
                    evidence.to_owned(),
                    ProductSignalKind::Strong,
                    None,
                );
            }
        }
        if response.headers.iter().any(|(name, value)| {
            (name.eq_ignore_ascii_case("link") && value.to_ascii_lowercase().contains("wp-json"))
                || (name.eq_ignore_ascii_case("x-pingback")
                    && value.to_ascii_lowercase().contains("xmlrpc.php"))
        }) {
            record_product_signal(
                signals,
                "WordPress",
                ProductLayer::Cms,
                "wordpress:header".to_owned(),
                "WordPress REST or XML-RPC response header".to_owned(),
                ProductSignalKind::StrongExplicit,
                None,
            );
        }
        if cookie_contains(response, "wordpress_") || cookie_contains(response, "wp-settings-") {
            record_product_signal(
                signals,
                "WordPress",
                ProductLayer::Cms,
                "wordpress:cookie".to_owned(),
                "WordPress cookie name".to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        }
        if wordpress_api_response(response, &path) {
            record_product_signal(
                signals,
                "WordPress",
                ProductLayer::Cms,
                "wordpress:validated-api".to_owned(),
                format!("Validated WordPress REST API response at {}", response.url),
                ProductSignalKind::Validated,
                None,
            );
        }

        if generator_lower.contains("woocommerce") {
            record_product_signal(
                signals,
                "WooCommerce",
                ProductLayer::Ecommerce,
                "woocommerce:generator".to_owned(),
                format!(
                    "Generator metadata: {}",
                    generator.as_deref().unwrap_or_default()
                ),
                ProductSignalKind::StrongExplicit,
                generator
                    .as_deref()
                    .and_then(|value| extract_version(value, "WooCommerce")),
            );
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
                record_product_signal(
                    signals,
                    "WooCommerce",
                    ProductLayer::Ecommerce,
                    source.to_owned(),
                    evidence.to_owned(),
                    ProductSignalKind::Strong,
                    None,
                );
            }
        }
        if cookie_contains(response, "woocommerce_")
            || cookie_contains(response, "woocommerce_cart_hash")
            || cookie_contains(response, "wp_woocommerce_session_")
        {
            record_product_signal(
                signals,
                "WooCommerce",
                ProductLayer::Ecommerce,
                "woocommerce:cookie".to_owned(),
                "WooCommerce cart or session cookie".to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        }
        if woocommerce_api_response(response, &path) {
            record_product_signal(
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
        }

        record_magento_signals(
            response,
            &lower,
            generator.as_deref(),
            &generator_lower,
            &path,
            signals,
        );
        record_shopify_signals(
            response,
            &lower,
            generator.as_deref(),
            &generator_lower,
            &path,
            signals,
        );
        record_other_store_signals(
            response,
            &lower,
            generator.as_deref(),
            &generator_lower,
            &path,
            signals,
        );

        if is_storefront_document(response) {
            collect_generic_commerce_signals(&lower, &mut generic);
        }
    }
    let has_product = generic.contains_key("product") || generic.contains_key("offer");
    let has_transaction = generic.contains_key("checkout") || generic.contains_key("payment");
    if generic.len() >= 3 && has_product && generic.contains_key("cart") && has_transaction {
        let mut evidence = generic.into_iter().collect::<Vec<_>>();
        evidence.sort_by_key(|(category, _)| *category);
        for (category, item) in evidence {
            record_product_signal(
                signals,
                "Generic commerce",
                ProductLayer::Ecommerce,
                format!("commerce:{category}"),
                item,
                ProductSignalKind::Indirect,
                None,
            );
        }
    }
}

fn record_moodle_totara_signals(
    response: &HttpObservation,
    body: &str,
    lower: &str,
    path: &str,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    if let Some(name) = set_cookie_name_with_prefix(response, "MoodleSession") {
        record_product_signal(
            signals,
            "Moodle",
            ProductLayer::Cms,
            "moodle:session-cookie".to_owned(),
            format!("Moodle session cookie: {name}"),
            ProductSignalKind::StrongExplicit,
            None,
        );
    }
    if structured_javascript_config(
        lower,
        "m.cfg",
        &["wwwroot", "sesskey", "theme", "contextid"],
    ) {
        record_product_signal(
            signals,
            "Moodle",
            ProductLayer::Cms,
            "moodle:page-config".to_owned(),
            "Structured Moodle M.cfg page configuration".to_owned(),
            ProductSignalKind::Strong,
            None,
        );
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
            record_product_signal(
                signals,
                "Moodle",
                ProductLayer::Cms,
                "moodle:php-assets".to_owned(),
                format!("Moodle PHP asset route: {route}"),
                ProductSignalKind::Strong,
                None,
            );
        }
    }
    if canonical_powered_by_link(body, "Moodle", &["moodle.com", "moodle.org"]) {
        record_product_signal(
            signals,
            "Moodle",
            ProductLayer::Cms,
            "moodle:powered-by".to_owned(),
            "Canonical Powered by Moodle attribution".to_owned(),
            ProductSignalKind::StrongExplicit,
            None,
        );
    }
    if generic_product_prose(lower, "moodle") {
        record_product_signal(
            signals,
            "Moodle",
            ProductLayer::Cms,
            "moodle:generic-prose".to_owned(),
            "Generic Moodle copyright, licence, or powered-by prose".to_owned(),
            ProductSignalKind::Indirect,
            None,
        );
    }

    if let Some(name) = set_cookie_name_with_prefix(response, "TotaraSession") {
        record_product_signal(
            signals,
            "Totara",
            ProductLayer::Cms,
            "totara:session-cookie".to_owned(),
            format!("Totara session cookie: {name}"),
            ProductSignalKind::StrongExplicit,
            None,
        );
    }
    if lower.contains("/totara/tui/") || path.starts_with("/totara/tui/") {
        record_product_signal(
            signals,
            "Totara",
            ProductLayer::Cms,
            "totara:tui-assets".to_owned(),
            "Totara Tui asset route".to_owned(),
            ProductSignalKind::Strong,
            None,
        );
    }
    if lower.contains("totara_core") || path.contains("/totara_core/") {
        record_product_signal(
            signals,
            "Totara",
            ProductLayer::Cms,
            "totara:core-resource".to_owned(),
            "Totara core resource or module".to_owned(),
            ProductSignalKind::Strong,
            None,
        );
    }
    if structured_javascript_config(
        lower,
        "_pageconfig",
        &["wwwroot", "sesskey", "rev", "theme", "context", "locale"],
    ) {
        record_product_signal(
            signals,
            "Totara",
            ProductLayer::Cms,
            "totara:page-config".to_owned(),
            "Structured Totara page configuration".to_owned(),
            ProductSignalKind::Strong,
            None,
        );
    }
    if canonical_powered_by_link(body, "Totara", &["totara.com"]) {
        record_product_signal(
            signals,
            "Totara",
            ProductLayer::Cms,
            "totara:powered-by".to_owned(),
            "Canonical Powered by Totara attribution".to_owned(),
            ProductSignalKind::StrongExplicit,
            None,
        );
    }
    if generic_product_prose(lower, "totara") {
        record_product_signal(
            signals,
            "Totara",
            ProductLayer::Cms,
            "totara:generic-prose".to_owned(),
            "Generic Totara copyright, licence, or powered-by prose".to_owned(),
            ProductSignalKind::Indirect,
            None,
        );
    }
}

fn record_totara_moodle_ancestry(
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    let Some(totara) = signals.get(&("Totara", ProductLayer::Cms)).cloned() else {
        return;
    };
    for signal in totara {
        record_product_signal(
            signals,
            "Moodle",
            ProductLayer::Cms,
            format!("moodle:totara-ancestry:{}", signal.source),
            format!("Moodle-derived Totara platform: {}", signal.evidence),
            signal.kind,
            None,
        );
    }
}

fn record_magento_signals(
    response: &HttpObservation,
    lower: &str,
    generator: Option<&str>,
    generator_lower: &str,
    path: &str,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    if generator_lower.contains("magento") || generator_lower.contains("adobe commerce") {
        let product = if generator_lower.contains("adobe commerce") {
            "Adobe Commerce"
        } else {
            "Magento"
        };
        record_product_signal(
            signals,
            product,
            ProductLayer::Ecommerce,
            "magento:generator".to_owned(),
            format!("Generator metadata: {}", generator.unwrap_or_default()),
            ProductSignalKind::StrongExplicit,
            generator.and_then(|value| {
                extract_version(value, "Magento")
                    .or_else(|| extract_version(value, "Adobe Commerce"))
            }),
        );
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
            record_product_signal(
                signals,
                "Magento",
                ProductLayer::Ecommerce,
                source.to_owned(),
                evidence.to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        }
    }
    if response
        .headers
        .iter()
        .any(|(name, _)| name.to_ascii_lowercase().starts_with("x-magento-"))
    {
        record_product_signal(
            signals,
            "Magento",
            ProductLayer::Ecommerce,
            "magento:header".to_owned(),
            "Magento-specific response header".to_owned(),
            ProductSignalKind::StrongExplicit,
            None,
        );
    }
    if cookie_contains(response, "private_content_version")
        || cookie_contains(response, "mage-cache-")
        || cookie_contains(response, "form_key")
    {
        record_product_signal(
            signals,
            "Magento",
            ProductLayer::Ecommerce,
            "magento:cookie".to_owned(),
            "Magento storefront cookie".to_owned(),
            ProductSignalKind::Strong,
            None,
        );
    }
    if magento_api_response(response, path) {
        record_product_signal(
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
    }
}

fn record_shopify_signals(
    response: &HttpObservation,
    lower: &str,
    generator: Option<&str>,
    generator_lower: &str,
    path: &str,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    if generator_lower.contains("shopify") {
        record_product_signal(
            signals,
            "Shopify",
            ProductLayer::Ecommerce,
            "shopify:generator".to_owned(),
            format!("Generator metadata: {}", generator.unwrap_or_default()),
            ProductSignalKind::StrongExplicit,
            generator.and_then(|value| extract_version(value, "Shopify")),
        );
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
            record_product_signal(
                signals,
                "Shopify",
                ProductLayer::Ecommerce,
                source.to_owned(),
                evidence.to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        }
    }
    if response.headers.iter().any(|(name, _)| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "x-shopid" | "x-shopify-stage" | "x-shopify-shop-api-call-limit"
        )
    }) {
        record_product_signal(
            signals,
            "Shopify",
            ProductLayer::Ecommerce,
            "shopify:header".to_owned(),
            "Shopify-specific response header".to_owned(),
            ProductSignalKind::StrongExplicit,
            None,
        );
    }
    if cookie_contains(response, "_shopify_") || cookie_contains(response, "_shopify_y") {
        record_product_signal(
            signals,
            "Shopify",
            ProductLayer::Ecommerce,
            "shopify:cookie".to_owned(),
            "Shopify storefront cookie".to_owned(),
            ProductSignalKind::Strong,
            None,
        );
    }
    if shopify_cart_response(response, path) {
        record_product_signal(
            signals,
            "Shopify",
            ProductLayer::Ecommerce,
            "shopify:validated-cart-api".to_owned(),
            format!("Validated Shopify cart API response at {}", response.url),
            ProductSignalKind::Validated,
            None,
        );
    }
}

fn record_other_store_signals(
    response: &HttpObservation,
    lower: &str,
    generator: Option<&str>,
    generator_lower: &str,
    path: &str,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    for (needle, product, layer) in [
        ("sulu", "Sulu", ProductLayer::Cms),
        ("silverstripe", "Silverstripe", ProductLayer::Cms),
        ("bigcommerce", "BigCommerce", ProductLayer::Ecommerce),
        ("prestashop", "PrestaShop", ProductLayer::Ecommerce),
        ("opencart", "OpenCart", ProductLayer::Ecommerce),
    ] {
        if generator_lower.contains(needle) {
            record_product_signal(
                signals,
                product,
                layer,
                format!("{needle}:generator"),
                format!("Generator metadata: {}", generator.unwrap_or_default()),
                ProductSignalKind::StrongExplicit,
                generator.and_then(|value| extract_version(value, product)),
            );
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
            record_product_signal(
                signals,
                product,
                layer,
                source.to_owned(),
                evidence.to_owned(),
                ProductSignalKind::Strong,
                None,
            );
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
            record_product_signal(
                signals,
                product,
                layer,
                format!("header:{header}"),
                format!("{header} response header"),
                ProductSignalKind::StrongExplicit,
                None,
            );
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
        if cookie_contains(response, needle) {
            record_product_signal(
                signals,
                product,
                ProductLayer::Ecommerce,
                source.to_owned(),
                evidence.to_owned(),
                ProductSignalKind::Strong,
                None,
            );
        }
    }
    if silverstripe_login_response(response, path) {
        record_product_signal(
            signals,
            "Silverstripe",
            ProductLayer::Cms,
            "silverstripe:validated-login".to_owned(),
            format!("Validated Silverstripe login response at {}", response.url),
            ProductSignalKind::Validated,
            None,
        );
    }
    if bigcommerce_api_response(response, path) {
        record_product_signal(
            signals,
            "BigCommerce",
            ProductLayer::Ecommerce,
            "bigcommerce:validated-api".to_owned(),
            format!("Validated BigCommerce Storefront API at {}", response.url),
            ProductSignalKind::Validated,
            None,
        );
    }
    if opencart_login_response(response, path) {
        record_product_signal(
            signals,
            "OpenCart",
            ProductLayer::Ecommerce,
            "opencart:validated-login".to_owned(),
            format!("Validated OpenCart account login page at {}", response.url),
            ProductSignalKind::Validated,
            None,
        );
    }
}

fn record_known_generator_signal(
    generator: &str,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
    let lower = generator.to_ascii_lowercase();
    let (needle, product, layer) = if lower.contains("totara") {
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
        return;
    };
    record_product_signal(
        signals,
        product,
        layer,
        format!("{needle}:generator"),
        format!("Generator metadata: {generator}"),
        ProductSignalKind::StrongExplicit,
        extract_version(generator, product),
    );
}

fn record_vendor_header_signals(
    response: &HttpObservation,
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
) {
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
                record_product_signal(
                    signals,
                    product,
                    layer,
                    format!("{needle}:vendor-header"),
                    format!("Vendor-specific {name} response header"),
                    ProductSignalKind::StrongExplicit,
                    valued.then(|| extract_version(&value, needle)).flatten(),
                );
            }
        }
    }
}

fn html_generator(body: &str) -> Option<String> {
    html_generators(body).into_iter().next()
}

fn html_generators(body: &str) -> Vec<String> {
    let lower = body.to_ascii_lowercase();
    let mut position = 0usize;
    let mut generators = Vec::new();
    while let Some(relative) = lower[position..].find("<meta") {
        let start = position + relative;
        let Some(relative_end) = lower[start..].find('>') else {
            break;
        };
        let end = relative_end + start + 1;
        let tag = &body[start..end];
        if html_attribute(tag, "name").is_some_and(|value| value.eq_ignore_ascii_case("generator"))
            && let Some(content) = html_attribute(tag, "content")
        {
            generators.push(content);
        }
        position = end;
    }
    generators
}

fn cookie_contains(response: &HttpObservation, needle: &str) -> bool {
    header_values(response, "set-cookie").any(|value| {
        value
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    })
}

fn set_cookie_name(response: &HttpObservation, expected: &str) -> Option<String> {
    header_values(response, "set-cookie").find_map(|value| {
        let pair = value.split(';').next()?.trim();
        let (name, _) = pair.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case(expected)
            .then(|| name.trim().to_owned())
    })
}

fn set_cookie_name_with_prefix(response: &HttpObservation, prefix: &str) -> Option<String> {
    header_values(response, "set-cookie").find_map(|value| {
        let pair = value.split(';').next()?.trim();
        let (name, _) = pair.split_once('=')?;
        name.trim()
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase())
            .then(|| name.trim().to_owned())
    })
}

fn structured_javascript_config(body: &str, variable: &str, keys: &[&str]) -> bool {
    let mut position = 0usize;
    while let Some(relative) = body[position..].find(variable) {
        let start = position + relative + variable.len();
        let remainder = body[start..].trim_start();
        let Some(object) = remainder.strip_prefix('=').map(str::trim_start) else {
            position = start;
            continue;
        };
        if !object.starts_with('{') {
            position = start;
            continue;
        }
        let Some(end) = javascript_object_end(object) else {
            position = start;
            continue;
        };
        let object = &object[..end];
        let matched = keys
            .iter()
            .filter(|key| {
                object.contains(&format!("\"{key}\"")) || object.contains(&format!("'{key}'"))
            })
            .count();
        if matched >= 2 {
            return true;
        }
        position = start;
    }
    false
}

fn javascript_object_end(value: &str) -> Option<usize> {
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
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index + 1);
            }
        }
    }
    None
}

fn canonical_powered_by_link(body: &str, product: &str, domains: &[&str]) -> bool {
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
                    domains
                        .iter()
                        .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
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
                && (inner.contains("powered by") || before.trim_end().ends_with("powered by"))
            {
                return true;
            }
        }
        position = close + 4;
    }
    false
}

fn generic_product_prose(body: &str, product: &str) -> bool {
    body.contains(product)
        && ["copyright", "licence", "license", "licensed", "powered by"]
            .iter()
            .any(|marker| body.contains(marker))
}

fn response_path_query(response: &HttpObservation) -> String {
    Url::parse(&response.url)
        .ok()
        .map(|url| url_path(&url))
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn response_on_endpoint_port(response: &HttpObservation, endpoint_port: u16) -> bool {
    Url::parse(&response.url)
        .ok()
        .and_then(|url| url.port_or_known_default())
        == Some(endpoint_port)
}

fn successful_json(response: &HttpObservation) -> Option<serde_json::Value> {
    (200..300)
        .contains(&response.status)
        .then(|| serde_json::from_slice(&response.body).ok())
        .flatten()
}

fn wordpress_api_response(response: &HttpObservation, path: &str) -> bool {
    if path.trim_end_matches('/') != "/wp-json" {
        return false;
    }
    successful_json(response).is_some_and(|json| {
        json.get("namespaces").is_some()
            || json.get("routes").is_some()
            || json.to_string().to_ascii_lowercase().contains("wp/v2")
    })
}

fn woocommerce_api_response(response: &HttpObservation, path: &str) -> bool {
    path.starts_with("/wp-json/wc/store/v1")
        && successful_json(response).is_some_and(|json| {
            json.get("routes").is_some()
                || json.get("namespace").is_some()
                || json.to_string().to_ascii_lowercase().contains("wc/store")
        })
}

fn magento_api_response(response: &HttpObservation, path: &str) -> bool {
    path == "/rest/v1/store/storeconfigs"
        && successful_json(response).is_some_and(|json| {
            let text = json.to_string().to_ascii_lowercase();
            text.contains("base_url")
                && (text.contains("website_id") || text.contains("store_name"))
        })
}

fn shopify_cart_response(response: &HttpObservation, path: &str) -> bool {
    path == "/cart.js"
        && successful_json(response).is_some_and(|json| {
            json.get("items").is_some()
                && json.get("item_count").is_some()
                && json.get("token").is_some()
        })
}

fn bigcommerce_api_response(response: &HttpObservation, path: &str) -> bool {
    path == "/api/storefront/store-context"
        && successful_json(response).is_some_and(|json| {
            let text = json.to_string().to_ascii_lowercase();
            text.contains("storehash") || text.contains("store_hash") || text.contains("storeid")
        })
}

fn silverstripe_login_response(response: &HttpObservation, path: &str) -> bool {
    path.trim_end_matches('/') == "/security/login"
        && (200..300).contains(&response.status)
        && login_page_evidence(response).is_some()
        && String::from_utf8_lossy(&response.body)
            .to_ascii_lowercase()
            .contains("silverstripe")
}

fn opencart_login_response(response: &HttpObservation, path: &str) -> bool {
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

fn is_storefront_document(response: &HttpObservation) -> bool {
    if !(200..300).contains(&response.status) || response.body.is_empty() {
        return false;
    }
    let path = response_path_query(response);
    matches!(path.as_str(), "/" | "/products" | "/products/")
        && header_values(response, "content-type")
            .any(|value| value.to_ascii_lowercase().contains("html"))
}

fn collect_generic_commerce_signals(lower: &str, signals: &mut HashMap<&'static str, String>) {
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
            || !response_on_endpoint_port(response, endpoint.port)
            || (!((200..300).contains(&response.status)) && !matches!(response.status, 401 | 403))
        {
            continue;
        }
        if response_is_soft_404(response, &baselines) {
            continue;
        }
        let path = response_path_query(response);
        let mut candidates = Vec::new();
        if wordpress_api_response(response, &path) && technologies.contains("WordPress") {
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
            let classified = classify_platform_surface(technology, &path);
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
                WebSurfaceType::Admin => admin_page_evidence(response),
                WebSurfaceType::Cart => cart_page_evidence(response),
                WebSurfaceType::Checkout => checkout_page_evidence(response),
                WebSurfaceType::Api => None,
            };
            if let Some(evidence) = evidence {
                candidates.push((*technology, surface_type, Confidence::Medium, evidence));
            }
        }
        for (technology, surface_type, confidence, evidence) in candidates {
            add_web_surface(
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
        }
    }
    endpoint.observed_web_surfaces = surfaces;
}

fn classify_platform_surface(technology: &str, path: &str) -> Option<WebSurfaceType> {
    let bare_path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    match technology {
        "WordPress" if bare_path == "/wp-login.php" => Some(WebSurfaceType::Login),
        "WordPress" if bare_path == "/wp-admin" => Some(WebSurfaceType::Admin),
        "Moodle" | "Totara" if bare_path == "/login/index.php" => Some(WebSurfaceType::Login),
        "WooCommerce" if matches!(bare_path, "/cart" | "/basket") => Some(WebSurfaceType::Cart),
        "WooCommerce" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
        "Magento" | "Adobe Commerce" if bare_path == "/customer/account/login" => {
            Some(WebSurfaceType::Login)
        }
        "Magento" | "Adobe Commerce" if bare_path == "/admin" => Some(WebSurfaceType::Admin),
        "Magento" | "Adobe Commerce" if bare_path == "/checkout/cart" => Some(WebSurfaceType::Cart),
        "Magento" | "Adobe Commerce" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
        "Shopify" if bare_path == "/account/login" => Some(WebSurfaceType::Login),
        "Shopify" if bare_path == "/cart" => Some(WebSurfaceType::Cart),
        "Shopify" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
        "Silverstripe" if bare_path.eq_ignore_ascii_case("/security/login") => {
            Some(WebSurfaceType::Login)
        }
        "Silverstripe" if bare_path == "/admin" => Some(WebSurfaceType::Admin),
        "BigCommerce" if bare_path == "/login.php" => Some(WebSurfaceType::Login),
        "BigCommerce" if matches!(bare_path, "/cart" | "/cart.php") => Some(WebSurfaceType::Cart),
        "BigCommerce" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
        "PrestaShop" if bare_path == "/login" => Some(WebSurfaceType::Login),
        "PrestaShop" if bare_path == "/cart" => Some(WebSurfaceType::Cart),
        "PrestaShop" if matches!(bare_path, "/checkout" | "/order") => {
            Some(WebSurfaceType::Checkout)
        }
        "OpenCart" if path.contains("route=account/login") => Some(WebSurfaceType::Login),
        "OpenCart" if path.contains("route=checkout/cart") => Some(WebSurfaceType::Cart),
        "OpenCart" if path.contains("route=checkout/checkout") => Some(WebSurfaceType::Checkout),
        "Generic commerce" if matches!(bare_path, "/cart" | "/basket") => {
            Some(WebSurfaceType::Cart)
        }
        "Generic commerce" if bare_path == "/checkout" => Some(WebSurfaceType::Checkout),
        _ => None,
    }
}

fn response_is_soft_404(response: &HttpObservation, baselines: &[&HttpObservation]) -> bool {
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

fn admin_page_evidence(response: &HttpObservation) -> Option<String> {
    if matches!(response.status, 401 | 403) {
        return Some("Access-controlled administration route".to_owned());
    }
    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    ((lower.contains("admin") || lower.contains("dashboard") || lower.contains("control panel"))
        && (lower.contains("<form") || lower.contains("navigation") || lower.contains("menu")))
    .then(|| "Administration page markers".to_owned())
}

fn cart_page_evidence(response: &HttpObservation) -> Option<String> {
    if matches!(response.status, 401 | 403) {
        return Some("Access-controlled cart route".to_owned());
    }
    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
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
    .then(|| "Cart page contains item-management or checkout markers".to_owned())
}

fn checkout_page_evidence(response: &HttpObservation) -> Option<String> {
    if matches!(response.status, 401 | 403) {
        return Some("Access-controlled checkout route".to_owned());
    }
    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
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

fn add_web_surface(
    surfaces: &mut Vec<ObservedWebSurface>,
    technology: &str,
    response: &HttpObservation,
    surface_type: WebSurfaceType,
    confidence: Confidence,
    evidence: Vec<String>,
) {
    if let Some(existing) = surfaces.iter_mut().find(|surface| {
        surface.technology.eq_ignore_ascii_case(technology)
            && surface.url == response.url
            && surface.surface_type == surface_type
    }) {
        existing.confidence = existing.confidence.max(confidence);
        existing.evidence.extend(evidence);
        existing.evidence.sort();
        existing.evidence.dedup();
        return;
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

fn record_product_signal(
    signals: &mut HashMap<(&'static str, ProductLayer), Vec<ProductSignal>>,
    name: &'static str,
    layer: ProductLayer,
    source: String,
    evidence: String,
    kind: ProductSignalKind,
    version: Option<String>,
) {
    signals
        .entry((name, layer))
        .or_default()
        .push(ProductSignal {
            source,
            evidence,
            kind,
            version,
        });
}

fn extract_version(value: &str, product: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let index = lower.find(&product.to_ascii_lowercase())? + product.len();
    let remainder = value[index..].trim_start_matches(['/', ' ', '-', '_']);
    let version = remainder
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
        .collect::<String>();
    if version.chars().any(|character| character.is_ascii_digit()) {
        Some(version)
    } else {
        None
    }
}
