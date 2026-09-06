use base64::Engine;
use serde::{Deserialize, Serialize};
use std::io::Write;
use winit::application::ApplicationHandler;
use winit::dpi::LogicalSize;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, EventLoop};
use winit::window::{Window, WindowId};
use wry::{WebView, WebViewBuilder};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
pub struct CookieRecord {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub expires_at: Option<i64>,
}

impl Drop for CookieRecord {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

struct CookieBrowser {
    login_url: String,
    target_url: String,
    window: Option<Window>,
    webview: Option<WebView>,
    error: Option<String>,
    result: Option<Zeroizing<String>>,
}

impl ApplicationHandler for CookieBrowser {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let attributes = Window::default_attributes()
            .with_title("Sign in, then close this window to capture cookies")
            .with_inner_size(LogicalSize::new(1100.0, 800.0));
        let window = match event_loop.create_window(attributes) {
            Ok(window) => window,
            Err(error) => {
                self.error = Some(format!("Unable to create browser window: {error}"));
                event_loop.exit();
                return;
            }
        };
        let webview = match WebViewBuilder::new()
            .with_url(&self.login_url)
            .with_incognito(true)
            .build(&window)
        {
            Ok(webview) => webview,
            Err(error) => {
                self.error = Some(format!("Unable to initialise WebView2: {error}"));
                event_loop.exit();
                return;
            }
        };
        self.window = Some(window);
        self.webview = Some(webview);
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        event: WindowEvent,
    ) {
        if event != WindowEvent::CloseRequested {
            return;
        }
        let result = self
            .webview
            .as_ref()
            .ok_or_else(|| "WebView2 was not ready".to_owned())
            .and_then(|webview| {
                webview
                    .cookies()
                    .map_err(|error| format!("Unable to read WebView2 cookies: {error}"))
            })
            .and_then(|cookies| {
                let target = url::Url::parse(&self.target_url)
                    .map_err(|error| format!("Invalid target URL: {error}"))?;
                let target_host = target.host_str().unwrap_or_default().to_ascii_lowercase();
                let records = cookies
                    .into_iter()
                    .filter(|cookie| {
                        let (domain, target_host): (Option<&str>, &str) =
                            (cookie.domain(), &target_host);
                        'inlined_cookie_domain_matches: {
                            let Some(domain) = domain else {
                                break 'inlined_cookie_domain_matches false;
                            };
                            let domain = domain.trim_start_matches('.').to_ascii_lowercase();
                            target_host == domain || target_host.ends_with(&format!(".{domain}"))
                        }
                    })
                    .map(|cookie| CookieRecord {
                        name: cookie.name().to_owned(),
                        value: cookie.value().to_owned(),
                        domain: cookie.domain().unwrap_or(&target_host).to_ascii_lowercase(),
                        path: cookie.path().unwrap_or("/").to_owned(),
                        secure: cookie.secure().unwrap_or(false),
                        expires_at: cookie
                            .expires_datetime()
                            .map(|value| value.unix_timestamp()),
                    })
                    .collect::<Vec<_>>();
                if records.is_empty() {
                    Err("No cookies apply to the request URL".to_owned())
                } else {
                    serde_json::to_string(&records)
                        .map(Zeroizing::new)
                        .map_err(|error| format!("Unable to encode captured cookies: {error}"))
                }
            });
        match result {
            Ok(result) => self.result = Some(result),
            Err(error) => self.error = Some(error),
        }
        event_loop.exit();
    }
}

pub fn run(login_url: String, target_url: String) -> Result<Zeroizing<String>, String> {
    let event_loop = EventLoop::new().map_err(|error| error.to_string())?;
    let mut app = CookieBrowser {
        login_url,
        target_url,
        window: None,
        webview: None,
        error: None,
        result: None,
    };
    event_loop
        .run_app(&mut app)
        .map_err(|error| error.to_string())?;
    if let Some(error) = app.error {
        Err(error)
    } else {
        app.result
            .ok_or_else(|| "The browser closed without capturing cookies".to_owned())
    }
}

pub fn write_protocol_result(result: &Result<Zeroizing<String>, String>) -> std::io::Result<()> {
    let (kind, payload) = match result {
        Ok(payload) => ("NANCY_COOKIE_OK:", payload.as_bytes()),
        Err(error) => ("NANCY_COOKIE_ERROR:", error.as_bytes()),
    };
    let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(payload));
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(kind.as_bytes())?;
    stdout.write_all(encoded.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}
