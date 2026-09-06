use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebProductRole {
    Server,
    Proxy,
    Framework,
    Runtime,
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
        product: "Undertow",
        identifier: "undertow",
        role: WebProductRole::Server,
        aliases: &[("undertow", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "WildFly",
        identifier: "wildfly",
        role: WebProductRole::Server,
        aliases: &[("wildfly", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "JBoss EAP",
        identifier: "jboss-eap",
        role: WebProductRole::Server,
        aliases: &[
            ("jboss application server", VersionStyle::Adjacent),
            ("jboss-eap", VersionStyle::Adjacent),
            ("jboss eap", VersionStyle::Adjacent),
            ("jboss", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "GlassFish",
        identifier: "glassfish",
        role: WebProductRole::Server,
        aliases: &[
            ("oracle glassfish server", VersionStyle::Adjacent),
            ("eclipse glassfish", VersionStyle::Adjacent),
            (
                "glassfish server open source edition",
                VersionStyle::Adjacent,
            ),
            ("glassfish server", VersionStyle::Adjacent),
            ("glassfish", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Payara Server",
        identifier: "payara",
        role: WebProductRole::Server,
        aliases: &[
            ("payara server", VersionStyle::Adjacent),
            ("payara", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Oracle WebLogic Server",
        identifier: "weblogic",
        role: WebProductRole::Server,
        aliases: &[
            ("oracle weblogic server", VersionStyle::Adjacent),
            ("weblogic server", VersionStyle::Adjacent),
            ("weblogic", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "IBM WebSphere Application Server",
        identifier: "websphere",
        role: WebProductRole::Server,
        aliases: &[
            ("ibm websphere application server", VersionStyle::Adjacent),
            ("websphere application server", VersionStyle::Adjacent),
            ("websphere", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Netty",
        identifier: "netty",
        role: WebProductRole::Server,
        aliases: &[("netty", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Grizzly",
        identifier: "grizzly",
        role: WebProductRole::Server,
        aliases: &[("grizzly", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Resin",
        identifier: "resin",
        role: WebProductRole::Server,
        aliases: &[
            ("resin web server", VersionStyle::Adjacent),
            ("resin", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Winstone",
        identifier: "winstone",
        role: WebProductRole::Server,
        aliases: &[
            ("winstone servlet engine", VersionStyle::Adjacent),
            ("winstone", VersionStyle::Adjacent),
        ],
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
        product: "Hypercorn",
        identifier: "hypercorn",
        role: WebProductRole::Server,
        aliases: &[("hypercorn", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Waitress",
        identifier: "waitress",
        role: WebProductRole::Server,
        aliases: &[("waitress", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "CherryPy",
        identifier: "cherrypy",
        role: WebProductRole::Server,
        aliases: &[("cherrypy", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "TornadoServer",
        identifier: "tornado",
        role: WebProductRole::Server,
        aliases: &[
            ("tornadoserver", VersionStyle::Adjacent),
            ("tornado server", VersionStyle::Adjacent),
            ("tornado", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "TwistedWeb",
        identifier: "twisted",
        role: WebProductRole::Server,
        aliases: &[
            ("twistedweb", VersionStyle::Adjacent),
            ("twisted web", VersionStyle::Adjacent),
            ("twisted", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "aiohttp",
        identifier: "aiohttp",
        role: WebProductRole::Server,
        aliases: &[("aiohttp", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Daphne",
        identifier: "daphne",
        role: WebProductRole::Server,
        aliases: &[("daphne", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Granian",
        identifier: "granian",
        role: WebProductRole::Server,
        aliases: &[("granian", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "gevent",
        identifier: "gevent",
        role: WebProductRole::Server,
        aliases: &[("gevent", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "mod_wsgi",
        identifier: "mod-wsgi",
        role: WebProductRole::Server,
        aliases: &[
            ("mod_wsgi-express", VersionStyle::Adjacent),
            ("mod_wsgi", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Sanic",
        identifier: "sanic",
        role: WebProductRole::Framework,
        aliases: &[("sanic", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Flask",
        identifier: "flask",
        role: WebProductRole::Framework,
        aliases: &[("flask", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Django",
        identifier: "django",
        role: WebProductRole::Framework,
        aliases: &[("django", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "FastAPI",
        identifier: "fastapi",
        role: WebProductRole::Framework,
        aliases: &[("fastapi", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Starlette",
        identifier: "starlette",
        role: WebProductRole::Framework,
        aliases: &[("starlette", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Bottle",
        identifier: "bottle",
        role: WebProductRole::Framework,
        aliases: &[("bottle", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Pyramid",
        identifier: "pyramid",
        role: WebProductRole::Framework,
        aliases: &[("pyramid", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Falcon",
        identifier: "falcon-python",
        role: WebProductRole::Framework,
        aliases: &[
            ("falcon-python", VersionStyle::Adjacent),
            ("python falcon", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Quart",
        identifier: "quart",
        role: WebProductRole::Framework,
        aliases: &[("quart", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Litestar",
        identifier: "litestar",
        role: WebProductRole::Framework,
        aliases: &[("litestar", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "fasthttp",
        identifier: "fasthttp",
        role: WebProductRole::Server,
        aliases: &[("fasthttp", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Fiber",
        identifier: "fiber",
        role: WebProductRole::Framework,
        aliases: &[("fiber", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Beego",
        identifier: "beego",
        role: WebProductRole::Framework,
        aliases: &[
            ("beegoserver:beego", VersionStyle::Adjacent),
            ("beego server", VersionStyle::Adjacent),
            ("beego", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Gin",
        identifier: "gin",
        role: WebProductRole::Framework,
        aliases: &[
            ("gin-gonic", VersionStyle::Adjacent),
            ("gin", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Echo",
        identifier: "echo-go",
        role: WebProductRole::Framework,
        aliases: &[
            ("labstack echo", VersionStyle::Adjacent),
            ("echo", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Revel",
        identifier: "revel",
        role: WebProductRole::Framework,
        aliases: &[("revel", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Hertz",
        identifier: "hertz",
        role: WebProductRole::Framework,
        aliases: &[
            ("cloudwego hertz", VersionStyle::Adjacent),
            ("hertz", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "GoFrame",
        identifier: "goframe",
        role: WebProductRole::Framework,
        aliases: &[
            ("goframe http server", VersionStyle::Adjacent),
            ("goframe", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Buffalo",
        identifier: "buffalo",
        role: WebProductRole::Framework,
        aliases: &[
            ("gobuffalo", VersionStyle::Adjacent),
            ("buffalo", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Chi",
        identifier: "chi-go",
        role: WebProductRole::Framework,
        aliases: &[
            ("go-chi", VersionStyle::Adjacent),
            ("chi", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Rocket",
        identifier: "rocket",
        role: WebProductRole::Server,
        aliases: &[("rocket", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Actix Web",
        identifier: "actix-web",
        role: WebProductRole::Server,
        aliases: &[
            ("actix-web", VersionStyle::Adjacent),
            ("actix web", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Axum",
        identifier: "axum",
        role: WebProductRole::Server,
        aliases: &[("axum", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Salvo",
        identifier: "salvo",
        role: WebProductRole::Server,
        aliases: &[("salvo", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Poem",
        identifier: "poem",
        role: WebProductRole::Server,
        aliases: &[("poem", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Fastify",
        identifier: "fastify",
        role: WebProductRole::Framework,
        aliases: &[("fastify", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Koa",
        identifier: "koa",
        role: WebProductRole::Framework,
        aliases: &[
            ("koa.js", VersionStyle::Adjacent),
            ("koa", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Hapi",
        identifier: "hapi",
        role: WebProductRole::Framework,
        aliases: &[
            ("@hapi/hapi", VersionStyle::Adjacent),
            ("hapi.js", VersionStyle::Adjacent),
            ("hapijs", VersionStyle::Adjacent),
            ("hapi", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "NestJS",
        identifier: "nestjs",
        role: WebProductRole::Framework,
        aliases: &[
            ("nestjs", VersionStyle::Adjacent),
            ("nest.js", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Deno",
        identifier: "deno",
        role: WebProductRole::Runtime,
        aliases: &[("deno", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Bun",
        identifier: "bun",
        role: WebProductRole::Runtime,
        aliases: &[("bun", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Go",
        identifier: "go-runtime",
        role: WebProductRole::Runtime,
        aliases: &[
            ("golang", VersionStyle::Adjacent),
            ("go", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Python",
        identifier: "python-runtime",
        role: WebProductRole::Runtime,
        aliases: &[("python", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Ruby",
        identifier: "ruby-runtime",
        role: WebProductRole::Runtime,
        aliases: &[("ruby", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Node.js",
        identifier: "node-runtime",
        role: WebProductRole::Runtime,
        aliases: &[
            ("node.js", VersionStyle::Adjacent),
            ("nodejs", VersionStyle::Adjacent),
            ("node", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "PHP",
        identifier: "php-runtime",
        role: WebProductRole::Runtime,
        aliases: &[("php", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Java",
        identifier: "java-runtime",
        role: WebProductRole::Runtime,
        aliases: &[
            ("openjdk", VersionStyle::Adjacent),
            ("java", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: ".NET",
        identifier: "dotnet-runtime",
        role: WebProductRole::Runtime,
        aliases: &[
            ("dotnet", VersionStyle::Adjacent),
            (".net", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "uWebSockets.js",
        identifier: "uwebsockets-js",
        role: WebProductRole::Server,
        aliases: &[
            ("uwebsockets.js server", VersionStyle::Adjacent),
            ("uwebsockets.js", VersionStyle::Adjacent),
            ("uwebsockets", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "Unicorn",
        identifier: "unicorn",
        role: WebProductRole::Server,
        aliases: &[("unicorn", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Thin",
        identifier: "thin-ruby",
        role: WebProductRole::Server,
        aliases: &[("thin", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "WEBrick",
        identifier: "webrick",
        role: WebProductRole::Server,
        aliases: &[("webrick", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Falcon",
        identifier: "falcon-ruby",
        role: WebProductRole::Server,
        aliases: &[("falcon", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Mongrel",
        identifier: "mongrel",
        role: WebProductRole::Server,
        aliases: &[("mongrel", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Roda",
        identifier: "roda",
        role: WebProductRole::Framework,
        aliases: &[("roda", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Sinatra",
        identifier: "sinatra",
        role: WebProductRole::Framework,
        aliases: &[("sinatra", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "PHP development server",
        identifier: "php-development-server",
        role: WebProductRole::Server,
        aliases: &[
            ("php development server", VersionStyle::Adjacent),
            ("php cli server", VersionStyle::Adjacent),
            ("php built-in web server", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "FrankenPHP",
        identifier: "frankenphp",
        role: WebProductRole::Server,
        aliases: &[("frankenphp", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "RoadRunner",
        identifier: "roadrunner",
        role: WebProductRole::Server,
        aliases: &[("roadrunner", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "OpenSwoole",
        identifier: "openswoole",
        role: WebProductRole::Server,
        aliases: &[("openswoole", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Swoole",
        identifier: "swoole",
        role: WebProductRole::Server,
        aliases: &[("swoole", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Bandit",
        identifier: "bandit",
        role: WebProductRole::Server,
        aliases: &[("bandit", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "MochiWeb",
        identifier: "mochiweb",
        role: WebProductRole::Server,
        aliases: &[("mochiweb", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Yaws",
        identifier: "yaws",
        role: WebProductRole::Server,
        aliases: &[("yaws", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Phoenix",
        identifier: "phoenix",
        role: WebProductRole::Framework,
        aliases: &[("phoenix", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Warp",
        identifier: "warp-haskell",
        role: WebProductRole::Server,
        aliases: &[("warp", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Snap",
        identifier: "snap",
        role: WebProductRole::Framework,
        aliases: &[("snap", VersionStyle::Adjacent)],
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
    CatalogEntry {
        product: "Squid",
        identifier: "squid",
        role: WebProductRole::Proxy,
        aliases: &[("squid", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Apache Traffic Server",
        identifier: "apache-traffic-server",
        role: WebProductRole::Proxy,
        aliases: &[
            ("apache traffic server", VersionStyle::Adjacent),
            ("apachetrafficserver", VersionStyle::Adjacent),
            ("trafficserver", VersionStyle::Adjacent),
            ("ats", VersionStyle::Adjacent),
        ],
    },
    CatalogEntry {
        product: "H2O",
        identifier: "h2o",
        role: WebProductRole::Server,
        aliases: &[("h2o", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Tengine",
        identifier: "tengine",
        role: WebProductRole::Server,
        aliases: &[("tengine", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Angie",
        identifier: "angie",
        role: WebProductRole::Server,
        aliases: &[("angie", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "OpenBSD httpd",
        identifier: "openbsd-httpd",
        role: WebProductRole::Server,
        aliases: &[("openbsd httpd", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Cherokee",
        identifier: "cherokee",
        role: WebProductRole::Server,
        aliases: &[("cherokee", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "Hiawatha",
        identifier: "hiawatha",
        role: WebProductRole::Server,
        aliases: &[("hiawatha", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "thttpd",
        identifier: "thttpd",
        role: WebProductRole::Server,
        aliases: &[("thttpd", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "mini_httpd",
        identifier: "mini-httpd",
        role: WebProductRole::Server,
        aliases: &[("mini_httpd", VersionStyle::Adjacent)],
    },
    CatalogEntry {
        product: "GoAhead",
        identifier: "goahead",
        role: WebProductRole::Server,
        aliases: &[
            ("goahead-webs", VersionStyle::Adjacent),
            ("goahead webserver", VersionStyle::Adjacent),
            ("goahead", VersionStyle::Adjacent),
        ],
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
    status: Option<u16>,
    response_url: Option<&str>,
) -> Vec<WebServerDetection> {
    detect_web_servers_inner(headers, body, status, response_url, true)
}

pub(crate) fn detect_primary_web_server<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    body: &[u8],
    status: Option<u16>,
) -> Option<WebServerDetection> {
    detect_web_servers_inner(headers, body, status, None, false)
        .into_iter()
        .next()
}

fn detect_web_servers_inner<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    body: &[u8],
    status: Option<u16>,
    response_url: Option<&str>,
    include_evidence: bool,
) -> Vec<WebServerDetection> {
    let mut detections = BTreeMap::<&'static str, WebServerDetection>::new();
    for (name, value) in headers {
        let header = name.to_ascii_lowercase();
        if matches!(
            header.as_str(),
            "server" | "via" | "x-powered-by" | "x-runtime" | "x-generator" | "x-turbo-charged-by"
        ) {
            for matched in catalog_matches(value) {
                let matched = if matched.entry.identifier == "falcon-ruby" && header != "server" {
                    Match {
                        entry: ({
                            let (identifier,): (&str,) = ("falcon-python",);
                            let inlined_result: Option<&'static CatalogEntry> =
                                { CATALOG.iter().find(|entry| entry.identifier == identifier) };
                            inlined_result
                        })
                        .unwrap_or(matched.entry),
                        ..matched
                    }
                } else {
                    matched
                };
                let confidence = if header == "server" {
                    FingerprintConfidence::High
                } else {
                    FingerprintConfidence::Medium
                };
                ({
                    let (detections, entry, version, confidence, evidence): (
                        &mut BTreeMap<&'static str, WebServerDetection>,
                        &'static CatalogEntry,
                        Option<String>,
                        FingerprintConfidence,
                        Option<String>,
                    ) = (
                        &mut detections,
                        matched.entry,
                        ({
                            let (value, matched): (&str, Match) = (value, matched);
                            let inlined_result: Option<String> = {
                                'inlined_version_after: {
                                    if matches!(matched.style, VersionStyle::None) {
                                        break 'inlined_version_after None;
                                    }
                                    let remainder = &value[matched.end..];
                                    let remainder = match matched.style {
                                        VersionStyle::Adjacent | VersionStyle::Parenthesized => {
                                            let remainder = remainder
                                                .trim_start_matches(['/', ' ', '-', '_', ':']);
                                            remainder.strip_prefix('(').unwrap_or(remainder)
                                        }
                                        VersionStyle::None => break 'inlined_version_after None,
                                    };
                                    let remainder = remainder
                                        .strip_prefix('v')
                                        .filter(|remainder| {
                                            remainder.starts_with(|character: char| {
                                                character.is_ascii_digit()
                                            })
                                        })
                                        .unwrap_or(remainder);
                                    let version = remainder
                                        .chars()
                                        .take_while(|character| {
                                            character.is_ascii_alphanumeric()
                                                || matches!(character, '.' | '-' | '_' | '+')
                                        })
                                        .collect::<String>();
                                    exact_exposed_version(&version).then_some(version)
                                }
                            };
                            inlined_result
                        }),
                        confidence,
                        include_evidence.then(|| {
                            let (status, response_url, detail): (Option<u16>, Option<&str>, &str) =
                                (status, response_url, &format!("{name}: {value}"));
                            let inlined_result: String = {
                                let url = response_url.filter(|url| !url.is_empty()).map(
                                    |value: &str| {
                                        let Ok(mut url) = url::Url::parse(value) else {
                                            return value
                                                .split(['?', '#'])
                                                .next()
                                                .unwrap_or_default()
                                                .chars()
                                                .take(512)
                                                .collect();
                                        };
                                        let _ = url.set_username("");
                                        let _ = url.set_password(None);
                                        url.set_query(None);
                                        url.set_fragment(None);
                                        url.to_string()
                                    },
                                );
                                match (status, url) {
                                    (Some(status), Some(url)) => {
                                        format!("HTTP {status} response at {url}: {detail}")
                                    }
                                    (Some(status), None) => {
                                        format!("HTTP {status} response: {detail}")
                                    }
                                    (None, Some(url)) => format!("Response at {url}: {detail}"),
                                    (None, None) => detail.to_owned(),
                                }
                            };
                            inlined_result
                        }),
                    );

                    let detection =
                        detections
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
                    if let Some(evidence) = evidence
                        && !detection.evidence.contains(&evidence)
                    {
                        detection.evidence.push(evidence);
                    }
                });
            }
            if header == "server"
                && let Some(version) = ({
                    let (value,): (&str,) = (value,);
                    let inlined_result: Option<String> = {
                        'inlined_php_development_server_version: {
                            let lower = value.to_ascii_lowercase();
                            let remainder = match lower
                                .strip_prefix("php/")
                                .or_else(|| lower.strip_prefix("php "))
                            {
                                Some(value) => value,
                                None => break 'inlined_php_development_server_version None,
                            };
                            let version = remainder
                                .chars()
                                .take_while(|character| {
                                    character.is_ascii_alphanumeric()
                                        || matches!(character, '.' | '-' | '_' | '+')
                                })
                                .collect::<String>();
                            let suffix = remainder[version.len()..].trim_start();
                            (suffix.starts_with("development server")
                                && exact_exposed_version(&version))
                            .then_some(version)
                        }
                    };
                    inlined_result
                })
                && let Some(entry) = ({
                    let (identifier,): (&str,) = ("php-development-server",);
                    let inlined_result: Option<&'static CatalogEntry> =
                        { CATALOG.iter().find(|entry| entry.identifier == identifier) };
                    inlined_result
                })
            {
                ({
                    let (detections, entry, version, confidence, evidence): (
                        &mut BTreeMap<&'static str, WebServerDetection>,
                        &'static CatalogEntry,
                        Option<String>,
                        FingerprintConfidence,
                        Option<String>,
                    ) = (
                        &mut detections,
                        entry,
                        Some(version),
                        FingerprintConfidence::High,
                        include_evidence.then(|| {
                            let (status, response_url, detail): (Option<u16>, Option<&str>, &str) =
                                (status, response_url, &format!("{name}: {value}"));
                            let inlined_result: String = {
                                let url = response_url.filter(|url| !url.is_empty()).map(
                                    |value: &str| {
                                        let Ok(mut url) = url::Url::parse(value) else {
                                            return value
                                                .split(['?', '#'])
                                                .next()
                                                .unwrap_or_default()
                                                .chars()
                                                .take(512)
                                                .collect();
                                        };
                                        let _ = url.set_username("");
                                        let _ = url.set_password(None);
                                        url.set_query(None);
                                        url.set_fragment(None);
                                        url.to_string()
                                    },
                                );
                                match (status, url) {
                                    (Some(status), Some(url)) => {
                                        format!("HTTP {status} response at {url}: {detail}")
                                    }
                                    (Some(status), None) => {
                                        format!("HTTP {status} response: {detail}")
                                    }
                                    (None, Some(url)) => format!("Response at {url}: {detail}"),
                                    (None, None) => detail.to_owned(),
                                }
                            };
                            inlined_result
                        }),
                    );

                    let detection =
                        detections
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
                    if let Some(evidence) = evidence
                        && !detection.evidence.contains(&evidence)
                    {
                        detection.evidence.push(evidence);
                    }
                });
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
            _ => [
                ("x-revel-", "revel"),
                ("x-beego-", "beego"),
                ("x-django-", "django"),
                ("x-fastapi-", "fastapi"),
                ("x-sanic-", "sanic"),
                ("x-litestar-", "litestar"),
                ("x-phoenix-", "phoenix"),
                ("x-fastify-", "fastify"),
            ]
            .into_iter()
            .find_map(|(prefix, identifier)| header.starts_with(prefix).then_some(identifier)),
        };
        if let Some(identifier) = product
            && let Some(entry) = ({
                let (identifier,): (&str,) = (identifier,);
                let inlined_result: Option<&'static CatalogEntry> =
                    { CATALOG.iter().find(|entry| entry.identifier == identifier) };
                inlined_result
            })
        {
            ({
                let (detections, entry, version, confidence, evidence): (
                    &mut BTreeMap<&'static str, WebServerDetection>,
                    &'static CatalogEntry,
                    Option<String>,
                    FingerprintConfidence,
                    Option<String>,
                ) = (
                    &mut detections,
                    entry,
                    None,
                    FingerprintConfidence::Medium,
                    include_evidence.then(|| {
                        let (status, response_url, detail): (Option<u16>, Option<&str>, &str) =
                            (status, response_url, &format!("{name}: {value}"));
                        let inlined_result: String = {
                            let url =
                                response_url
                                    .filter(|url| !url.is_empty())
                                    .map(|value: &str| {
                                        let Ok(mut url) = url::Url::parse(value) else {
                                            return value
                                                .split(['?', '#'])
                                                .next()
                                                .unwrap_or_default()
                                                .chars()
                                                .take(512)
                                                .collect();
                                        };
                                        let _ = url.set_username("");
                                        let _ = url.set_password(None);
                                        url.set_query(None);
                                        url.set_fragment(None);
                                        url.to_string()
                                    });
                            match (status, url) {
                                (Some(status), Some(url)) => {
                                    format!("HTTP {status} response at {url}: {detail}")
                                }
                                (Some(status), None) => format!("HTTP {status} response: {detail}"),
                                (None, Some(url)) => format!("Response at {url}: {detail}"),
                                (None, None) => detail.to_owned(),
                            }
                        };
                        inlined_result
                    }),
                );

                let detection =
                    detections
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
                if let Some(evidence) = evidence
                    && !detection.evidence.contains(&evidence)
                {
                    detection.evidence.push(evidence);
                }
            });
        }
        if header == "set-cookie"
            && let Some(cookie_name) = value
                .split(';')
                .next()
                .and_then(|pair| pair.split_once('='))
                .map(|(name, _)| name.trim())
        {
            let product = if cookie_name.eq_ignore_ascii_case("REVEL_SESSION")
                || cookie_name.eq_ignore_ascii_case("REVEL_FLASH")
            {
                Some("revel")
            } else if cookie_name.eq_ignore_ascii_case("beegosessionID") {
                Some("beego")
            } else if cookie_name.eq_ignore_ascii_case("csrftoken") {
                Some("django")
            } else {
                None
            };
            if let Some(entry) = product
                .and_then(|identifier| CATALOG.iter().find(|entry| entry.identifier == identifier))
            {
                ({
                    let (detections, entry, version, confidence, evidence): (
                        &mut BTreeMap<&'static str, WebServerDetection>,
                        &'static CatalogEntry,
                        Option<String>,
                        FingerprintConfidence,
                        Option<String>,
                    ) =
                        (
                            &mut detections,
                            entry,
                            None,
                            FingerprintConfidence::Medium,
                            include_evidence.then(|| {
                                let (status, response_url, detail): (
                                    Option<u16>,
                                    Option<&str>,
                                    &str,
                                ) = (
                                    status,
                                    response_url,
                                    &format!("Framework-specific {cookie_name} cookie"),
                                );
                                let inlined_result: String = {
                                    let url = response_url.filter(|url| !url.is_empty()).map(
                                        |value: &str| {
                                            let Ok(mut url) = url::Url::parse(value) else {
                                                return value
                                                    .split(['?', '#'])
                                                    .next()
                                                    .unwrap_or_default()
                                                    .chars()
                                                    .take(512)
                                                    .collect();
                                            };
                                            let _ = url.set_username("");
                                            let _ = url.set_password(None);
                                            url.set_query(None);
                                            url.set_fragment(None);
                                            url.to_string()
                                        },
                                    );
                                    match (status, url) {
                                        (Some(status), Some(url)) => {
                                            format!("HTTP {status} response at {url}: {detail}")
                                        }
                                        (Some(status), None) => {
                                            format!("HTTP {status} response: {detail}")
                                        }
                                        (None, Some(url)) => format!("Response at {url}: {detail}"),
                                        (None, None) => detail.to_owned(),
                                    }
                                };
                                inlined_result
                            }),
                        );

                    let detection =
                        detections
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
                    if let Some(evidence) = evidence
                        && !detection.evidence.contains(&evidence)
                    {
                        detection.evidence.push(evidence);
                    }
                });
            }
        }
    }
    ({
        let (body, status, response_url, detections, include_evidence): (
            &[u8],
            Option<u16>,
            Option<&str>,
            &mut BTreeMap<&'static str, WebServerDetection>,
            bool,
        ) = (
            body,
            status,
            response_url,
            &mut detections,
            include_evidence,
        );

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
            (
                "bottle",
                &[
                    "powered by <a href=\"http://bottlepy.org/",
                    "powered by <a href=\"https://bottlepy.org/",
                ][..],
            ),
            (
                "cherrypy",
                &[
                    "powered by <a href=\"http://www.cherrypy.org\">cherrypy",
                    "powered by <a href=\"https://cherrypy.org\">cherrypy",
                ][..],
            ),
            ("twisted", &["<address>twistedweb/"][..]),
            ("werkzeug", &["<title>werkzeug debugger</title>"][..]),
        ] {
            if !markers.iter().any(|marker| lower.contains(marker)) {
                continue;
            }
            let Some(entry) = ({
                let (identifier,): (&str,) = (identifier,);
                let inlined_result: Option<&'static CatalogEntry> =
                    { CATALOG.iter().find(|entry| entry.identifier == identifier) };
                inlined_result
            }) else {
                continue;
            };
            let version = catalog_matches(&text)
                .into_iter()
                .find(|matched| matched.entry.identifier == identifier)
                .and_then(|matched| {
                    let (value, matched): (&str, Match) = (&text, matched);
                    let inlined_result: Option<String> = {
                        'inlined_version_after: {
                            if matches!(matched.style, VersionStyle::None) {
                                break 'inlined_version_after None;
                            }
                            let remainder = &value[matched.end..];
                            let remainder = match matched.style {
                                VersionStyle::Adjacent | VersionStyle::Parenthesized => {
                                    let remainder =
                                        remainder.trim_start_matches(['/', ' ', '-', '_', ':']);
                                    remainder.strip_prefix('(').unwrap_or(remainder)
                                }
                                VersionStyle::None => break 'inlined_version_after None,
                            };
                            let remainder = remainder
                                .strip_prefix('v')
                                .filter(|remainder| {
                                    remainder
                                        .starts_with(|character: char| character.is_ascii_digit())
                                })
                                .unwrap_or(remainder);
                            let version = remainder
                                .chars()
                                .take_while(|character| {
                                    character.is_ascii_alphanumeric()
                                        || matches!(character, '.' | '-' | '_' | '+')
                                })
                                .collect::<String>();
                            exact_exposed_version(&version).then_some(version)
                        }
                    };
                    inlined_result
                });
            ({
                let (detections, entry, version, confidence, evidence): (
                    &mut BTreeMap<&'static str, WebServerDetection>,
                    &'static CatalogEntry,
                    Option<String>,
                    FingerprintConfidence,
                    Option<String>,
                ) = (
                    detections,
                    entry,
                    version,
                    FingerprintConfidence::High,
                    include_evidence.then(|| {
                        let (status, response_url, detail): (Option<u16>, Option<&str>, &str) = (
                            status,
                            response_url,
                            &format!(
                                "Response body contains a distinctive {} default/error-page marker",
                                entry.product
                            ),
                        );
                        let inlined_result: String = {
                            let url =
                                response_url
                                    .filter(|url| !url.is_empty())
                                    .map(|value: &str| {
                                        let Ok(mut url) = url::Url::parse(value) else {
                                            return value
                                                .split(['?', '#'])
                                                .next()
                                                .unwrap_or_default()
                                                .chars()
                                                .take(512)
                                                .collect();
                                        };
                                        let _ = url.set_username("");
                                        let _ = url.set_password(None);
                                        url.set_query(None);
                                        url.set_fragment(None);
                                        url.to_string()
                                    });
                            match (status, url) {
                                (Some(status), Some(url)) => {
                                    format!("HTTP {status} response at {url}: {detail}")
                                }
                                (Some(status), None) => format!("HTTP {status} response: {detail}"),
                                (None, Some(url)) => format!("Response at {url}: {detail}"),
                                (None, None) => detail.to_owned(),
                            }
                        };
                        inlined_result
                    }),
                );

                let detection =
                    detections
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
                if let Some(evidence) = evidence
                    && !detection.evidence.contains(&evidence)
                {
                    detection.evidence.push(evidence);
                }
            });
        }
        if status.is_some_and(|status| {
let (status, body,): (u16, & str,) = (status, &lower,);
{
'inlined_apache_fallback_error_document: {

    if !(400..600).contains(&status) {
        break 'inlined_apache_fallback_error_document false;
    }
    let normalized = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if !normalized.contains(
        "error was encountered while trying to use an errordocument to handle the request",
    ) {
        break 'inlined_apache_fallback_error_document false;
    }
    match status {
        400 => normalized.contains("your browser sent a request that this server could not understand"),
        401 => normalized.contains(
            "this server could not verify that you are authorized to access the document requested",
        ),
        403 => normalized.contains("you don't have permission to access this resource"),
        404 => normalized.contains("the requested url was not found on this server"),
        405 => normalized.contains("is not allowed for this url"),
        406 => normalized.contains(
            "an appropriate representation of the requested resource could not be found on this server",
        ),
        408 => normalized.contains("server timeout waiting for the http request from the client"),
        410 => normalized.contains("the requested resource is no longer available on this server"),
        413 => normalized.contains("the requested resource does not allow request data"),
        414 => normalized.contains("the requested url's length exceeds the capacity limit for this server"),
        415 => normalized.contains(
            "the supplied request data is not in a format acceptable for processing by this resource",
        ),
        500 => normalized.contains(
            "the server encountered an internal error or misconfiguration and was unable to complete your request",
        ),
        501 => normalized.contains("to url not supported"),
        502 => normalized.contains(
            "the proxy server received an invalid response from an upstream server",
        ),
        503 => normalized.contains("the server is temporarily unable to service your request"),
        504 => normalized.contains(
            "the gateway did not receive a timely response from the upstream server or application",
        ),
        _ => false,
    }

}
}

})
        && let Some(entry) = ({
let (identifier,): (& str,) = ("apache-httpd",);
let inlined_result: Option < & 'static CatalogEntry > = {

    CATALOG.iter().find(|entry| entry.identifier == identifier)

};
inlined_result
})
    {
        ({
let (detections, entry, version, confidence, evidence,): (& mut BTreeMap < & 'static str , WebServerDetection >, & 'static CatalogEntry, Option < String >, FingerprintConfidence, Option < String >,) = (detections, entry, None, FingerprintConfidence::High, include_evidence.then(|| {
                {
let (status, response_url, detail,): (Option < u16 >, Option < & str >, & str,) = (status, response_url, "Response body matches Apache's fallback ErrorDocument page",);
let inlined_result: String = {

    let url = response_url
        .filter(|url| !url.is_empty())
        .map(|value: & str| {
    let Ok(mut url) = url::Url::parse(value) else {
        return value
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .chars()
            .take(512)
            .collect();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
});
    match (status, url) {
        (Some(status), Some(url)) => format!("HTTP {status} response at {url}: {detail}"),
        (Some(status), None) => format!("HTTP {status} response: {detail}"),
        (None, Some(url)) => format!("Response at {url}: {detail}"),
        (None, None) => detail.to_owned(),
    }

};
inlined_result
}
            }),);

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
    if let Some(evidence) = evidence
        && !detection.evidence.contains(&evidence)
    {
        detection.evidence.push(evidence);
    }

});
    }
    });
    let mut output = detections.into_values().collect::<Vec<_>>();
    output.sort_by(|left, right| {
        ({
            let (role,): (WebProductRole,) = (left.role,);
            let inlined_result: u8 = {
                match role {
                    WebProductRole::Server => 0,
                    WebProductRole::Proxy => 1,
                    WebProductRole::Framework => 2,
                    WebProductRole::Runtime => 3,
                }
            };
            inlined_result
        })
        .cmp(
            &({
                let (role,): (WebProductRole,) = (right.role,);
                let inlined_result: u8 = {
                    match role {
                        WebProductRole::Server => 0,
                        WebProductRole::Proxy => 1,
                        WebProductRole::Framework => 2,
                        WebProductRole::Runtime => 3,
                    }
                };
                inlined_result
            }),
        )
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
                if {
                    let (value, start, end): (&str, usize, usize) = (&lower, start, end);
                    {
                        let before = value[..start].chars().next_back();
                        let after = value[end..].chars().next();
                        !before.is_some_and(|character| character.is_ascii_alphanumeric())
                            && !after.is_some_and(|character| character.is_ascii_alphanumeric())
                    }
                } {
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

pub(crate) fn exact_exposed_version(version: &str) -> bool {
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
    let (mut core, suffix) = version_without_jetty_build
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
    if let Some((numeric, qualifier)) = core.rsplit_once('.')
        && ["final", "ga", "release"].contains(&qualifier)
    {
        core = numeric;
    }
    let mut parts = core.split('.');
    let count = parts.clone().count();
    (2..=4).contains(&count)
        && parts.all(|part| !part.is_empty() && part.chars().all(|value| value.is_ascii_digit()))
}

pub(crate) use exact_exposed_version as is_exact_web_server_version;

pub(crate) fn is_fastapi_branded_document(url: &str, body: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(body).to_ascii_lowercase();
    if lower.contains("fastapi.tiangolo.com/img/favicon.png")
        && (lower.contains("swaggeruibundle") || lower.contains("redoc"))
    {
        return true;
    }
    let path = url::Url::parse(url)
        .ok()
        .map(|url| url.path().trim_end_matches('/').to_ascii_lowercase())
        .unwrap_or_default();
    if !path.ends_with("/openapi.json") && path != "/api-docs" {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .is_some_and(|document| {
            (document.get("openapi").is_some() || document.get("swagger").is_some())
                && (document
                    .pointer("/info/title")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|title| {
                        catalog_matches(title)
                            .iter()
                            .any(|matched| matched.entry.identifier == "fastapi")
                    })
                    || document.get("x-fastapi").is_some())
        })
}
