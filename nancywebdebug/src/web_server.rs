use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebProductRole {
    Server,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FingerprintConfidence {
    Medium,
    High,
}

impl fmt::Display for FingerprintConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Medium => "Medium",
            Self::High => "High",
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WebServerDetection {
    pub product: &'static str,
    pub identifier: &'static str,
    pub role: WebProductRole,
    pub version: Option<String>,
    pub confidence: FingerprintConfidence,
    pub evidence: Vec<String>,
}

impl WebServerDetection {
    pub fn display_identity(&self) -> String {
        self.version
            .as_ref()
            .map(|version| format!("{}/{}", self.product, version))
            .unwrap_or_else(|| self.product.to_owned())
    }
}

#[derive(Clone, Copy)]
enum VersionStyle {
    Adjacent,
    Parenthesized,
    None,
}

#[derive(Clone, Copy)]
struct CatalogEntry {
    product: &'static str,
    identifier: &'static str,
    role: WebProductRole,
    aliases: &'static [(&'static str, VersionStyle)],
}

const CATALOG: &[CatalogEntry] = &[
    CatalogEntry {
        product: "Apache Tomcat",
        identifier: "tomcat",
        role: WebProductRole::Server,
        aliases: &[
            ("apache-coyote", VersionStyle::None),
            ("apache tomcat", VersionStyle::Adjacent),
            ("tomcat", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Microsoft IIS",
        identifier: "iis",
        role: WebProductRole::Server,
        aliases: &[
            ("microsoft-iis", VersionStyle::Adjacent),
            ("microsoft iis", VersionStyle::Adjacent),
            ("iis", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Apache HTTP Server",
        identifier: "apache-httpd",
        role: WebProductRole::Server,
        aliases: &[
            ("apache http server", VersionStyle::Adjacent),
            ("apache httpd", VersionStyle::Adjacent),
            ("apache", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "OpenLiteSpeed",
        identifier: "openlitespeed",
        role: WebProductRole::Server,
        aliases: &[("openlitespeed", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "LiteSpeed",
        identifier: "litespeed",
        role: WebProductRole::Server,
        aliases: &[
            ("litespeed web server", VersionStyle::Adjacent),
            ("litespeed", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "OpenResty",
        identifier: "openresty",
        role: WebProductRole::Server,
        aliases: &[("openresty", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "lighttpd",
        identifier: "lighttpd",
        role: WebProductRole::Server,
        aliases: &[("lighttpd", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "nginx",
        identifier: "nginx",
        role: WebProductRole::Server,
        aliases: &[("nginx", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Caddy",
        identifier: "caddy",
        role: WebProductRole::Server,
        aliases: &[("caddy", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Jetty",
        identifier: "jetty",
        role: WebProductRole::Server,
        aliases: &[("jetty", VersionStyle::Parenthesized)],
    },
    CatalogEntry {
        product: "Kestrel",
        identifier: "kestrel",
        role: WebProductRole::Server,
        aliases: &[("kestrel", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "gunicorn",
        identifier: "gunicorn",
        role: WebProductRole::Server,
        aliases: &[("gunicorn", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Uvicorn",
        identifier: "uvicorn",
        role: WebProductRole::Server,
        aliases: &[("uvicorn", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Puma",
        identifier: "puma",
        role: WebProductRole::Server,
        aliases: &[("puma", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Passenger",
        identifier: "passenger",
        role: WebProductRole::Server,
        aliases: &[
            ("phusion passenger", VersionStyle::Adjacent),
            ("passenger", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Cowboy",
        identifier: "cowboy",
        role: WebProductRole::Server,
        aliases: &[("cowboy", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Werkzeug",
        identifier: "werkzeug",
        role: WebProductRole::Server,
        aliases: &[("werkzeug", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "HAProxy",
        identifier: "haproxy",
        role: WebProductRole::Proxy,
        aliases: &[("haproxy", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Envoy",
        identifier: "envoy",
        role: WebProductRole::Proxy,
        aliases: &[("envoy", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Traefik",
        identifier: "traefik",
        role: WebProductRole::Proxy,
        aliases: &[("traefik", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Varnish",
        identifier: "varnish",
        role: WebProductRole::Proxy,
        aliases: &[("varnish", VersionStyle::Adjacent)],
    },
];

#[derive(Clone, Copy)]
struct Match {
    entry: &'static CatalogEntry,
    alias: &'static str,
    style: VersionStyle,
    start: usize,
    end: usize,
}

pub(crate) fn detect_web_servers<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    body: &[u8],
) -> Vec<WebServerDetection> {
    let mut detections = BTreeMap::<&'static str, WebServerDetection>::new();
    for (name, value) in headers {
        let header = name.to_ascii_lowercase();
        if matches!(
            header.as_str(),
            "server" | "via" | "x-powered-by" | "x-turbo-charged-by"
        ) {
            for matched in catalog_matches(value) {
                let confidence = if header == "server" {
                    FingerprintConfidence::High
                } else {
                    FingerprintConfidence::Medium
                };
                record(
                    &mut detections,
                    matched.entry,
                    version_after(value, matched),
                    confidence,
                    format!("{name}: {value}"),
                );
            }
        }
        let product = match header.as_str() {
            "x-litespeed-cache"
            | "x-litespeed-cache-control"
            | "x-litespeed-purge"
            | "x-litespeed-tag"
            | "x-litespeed-vary" => Some("litespeed"),
            "x-varnish" => Some("varnish"),
            "x-envoy-upstream-service-time" | "x-envoy-decorator-operation" => Some("envoy"),
            "x-traefik-router" => Some("traefik"),
            _ => None,
        };
        if let Some(identifier) = product
            && let Some(entry) = entry(identifier)
        {
            record(
                &mut detections,
                entry,
                None,
                FingerprintConfidence::Medium,
                format!("{name}: {value}"),
            );
        }
    }
    detect_body(body, &mut detections);
    let mut output = detections.into_values().collect::<Vec<_>>();
    output.sort_by(|left, right| {
        role_rank(left.role)
            .cmp(&role_rank(right.role))
            .then(right.confidence.cmp(&left.confidence))
            .then(left.product.cmp(right.product))
    });
    output
}

pub(crate) fn canonical_product_name(value: &str) -> Option<&'static str> {
    let value = value.trim();
    catalog_matches(value)
        .into_iter()
        .find(|matched| matched.start == 0 && matched.end == value.len())
        .map(|matched| matched.entry.product)
}

fn catalog_matches(value: &str) -> Vec<Match> {
    let lower = value.to_ascii_lowercase();
    let mut matches = Vec::new();
    for entry in CATALOG {
        for &(alias, style) in entry.aliases {
            for (start, _) in lower.match_indices(alias) {
                let end = start + alias.len();
                if token_boundary(&lower, start, end) {
                    matches.push(Match {
                        entry,
                        alias,
                        style,
                        start,
                        end,
                    });
                }
            }
        }
    }
    matches.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then(right.alias.len().cmp(&left.alias.len()))
    });
    let mut selected = Vec::<Match>::new();
    for candidate in matches {
        if selected
            .iter()
            .any(|existing| candidate.start < existing.end && candidate.end > existing.start)
        {
            continue;
        }
        selected.push(candidate);
    }
    selected
}

fn token_boundary(value: &str, start: usize, end: usize) -> bool {
    let before = value[..start].chars().next_back();
    let after = value[end..].chars().next();
    !before.is_some_and(|character| character.is_ascii_alphanumeric())
        && !after.is_some_and(|character| character.is_ascii_alphanumeric())
}

fn version_after(value: &str, matched: Match) -> Option<String> {
    if matches!(matched.style, VersionStyle::None) {
        return None;
    }
    let remainder = &value[matched.end..];
    let remainder = match matched.style {
        VersionStyle::Adjacent => remainder.trim_start_matches(['/', ' ', '-', '_']),
        VersionStyle::Parenthesized => remainder
            .strip_prefix('(')
            .unwrap_or_else(|| remainder.trim_start_matches(['/', ' ', '-', '_', ':'])),
        VersionStyle::None => return None,
    };
    let version = remainder
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '+')
        })
        .collect::<String>();
    exact_exposed_version(&version).then_some(version)
}

fn exact_exposed_version(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    let (version_without_jetty_build, jetty_build) = lower
        .find(".v")
        .map(|index| (&lower[..index], Some(&lower[index + 2..])))
        .unwrap_or((&lower, None));
    if jetty_build.is_some_and(|build| {
        build.is_empty() || !build.chars().all(|character| character.is_ascii_digit())
    }) {
        return false;
    }
    let (core, suffix) = version_without_jetty_build
        .find(['-', '_', '+'])
        .map(|index| {
            (
                &version_without_jetty_build[..index],
                Some(&version_without_jetty_build[index + 1..]),
            )
        })
        .unwrap_or((version_without_jetty_build, None));
    if suffix.is_some_and(|suffix| {
        !["alpha", "beta", "preview", "pre", "rc"]
            .iter()
            .any(|marker| {
                suffix.strip_prefix(marker).is_some_and(|remainder| {
                    remainder
                        .chars()
                        .all(|character| character.is_ascii_digit() || character == '.')
                })
            })
    }) {
        return false;
    }
    let mut parts = core.split('.');
    let count = parts.clone().count();
    (2..=4).contains(&count)
        && parts.all(|part| !part.is_empty() && part.chars().all(|value| value.is_ascii_digit()))
}

pub(crate) fn is_exact_web_server_version(version: &str) -> bool {
    exact_exposed_version(version)
}

fn detect_body(body: &[u8], detections: &mut BTreeMap<&'static str, WebServerDetection>) {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();
    for (identifier, markers) in [
        (
            "openresty",
            &[
                "<title>welcome to openresty!</title>",
                "welcome to openresty!",
            ][..],
        ),
        (
            "nginx",
            &[
                "<title>welcome to nginx!</title>",
                "welcome to nginx!",
                "<hr><center>nginx",
                "<center>nginx/",
            ][..],
        ),
        (
            "apache-httpd",
            &[
                "test page for the apache http server",
                "<address>apache/",
                "<address>apache server at ",
            ][..],
        ),
        (
            "iis",
            &[
                "<title>iis windows server</title>",
                "iis windows server",
                "<title>welcome to iis",
                "welcome to iis",
                "iisstart.png",
            ][..],
        ),
        (
            "tomcat",
            &[
                "<title>apache tomcat",
                "<h1>apache tomcat",
                "apache tomcat/",
                "powered by apache tomcat",
            ][..],
        ),
        (
            "jetty",
            &["powered by jetty://", "<a href=\"https://jetty.org/\">"][..],
        ),
        (
            "caddy",
            &[
                "<title>caddy works!</title>",
                "your caddy web server is working!",
            ][..],
        ),
        (
            "litespeed",
            &[
                "proudly powered by litespeed web server",
                "<title>litespeed web server",
            ][..],
        ),
        (
            "openlitespeed",
            &["<title>openlitespeed", "powered by openlitespeed"][..],
        ),
        (
            "lighttpd",
            &["powered by lighttpd", "<address>lighttpd/"][..],
        ),
    ] {
        if !markers.iter().any(|marker| lower.contains(marker)) {
            continue;
        }
        let Some(entry) = entry(identifier) else {
            continue;
        };
        let version = catalog_matches(&text)
            .into_iter()
            .find(|matched| matched.entry.identifier == identifier)
            .and_then(|matched| version_after(&text, matched));
        record(
            detections,
            entry,
            version,
            FingerprintConfidence::High,
            format!(
                "Response body contains a distinctive {} default/error-page marker",
                entry.product
            ),
        );
    }
}

fn entry(identifier: &str) -> Option<&'static CatalogEntry> {
    CATALOG.iter().find(|entry| entry.identifier == identifier)
}

fn record(
    detections: &mut BTreeMap<&'static str, WebServerDetection>,
    entry: &'static CatalogEntry,
    version: Option<String>,
    confidence: FingerprintConfidence,
    evidence: String,
) {
    let detection = detections
        .entry(entry.identifier)
        .or_insert_with(|| WebServerDetection {
            product: entry.product,
            identifier: entry.identifier,
            role: entry.role,
            version: None,
            confidence,
            evidence: Vec::new(),
        });
    if detection.version.is_none() {
        detection.version = version;
    }
    detection.confidence = detection.confidence.max(confidence);
    if !detection.evidence.contains(&evidence) {
        detection.evidence.push(evidence);
    }
}

fn role_rank(role: WebProductRole) -> u8 {
    match role {
        WebProductRole::Server => 0,
        WebProductRole::Proxy => 1,
    }
}
