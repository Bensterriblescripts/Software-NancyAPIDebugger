use http::HeaderValue;
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use super::browser::CookieRecord;
use super::profiles::{BrowserCookie, SharedAuthStore, StoredProfileKind};

pub fn capture_browser_cookies(
    store: SharedAuthStore,
    id: u64,
    target_url: &str,
    cancel: CancellationToken,
) -> Result<String, String> {
    let target_url = parse_http_url(target_url)
        .map_err(|error| format!("Request URL: {error}"))?
        .to_string();
    let profile = store
        .lock()
        .map_err(|_| "Authentication profile store is unavailable".to_owned())?
        .profile(id)
        .ok_or_else(|| "Authentication profile no longer exists".to_owned())?;
    let StoredProfileKind::BrowserCookies(config) = profile.kind else {
        return Err("Profile does not use browser cookies".to_owned());
    };
    validate_host(&target_url, &config.host_scope)?;
    #[cfg(target_os = "linux")]
    if std::env::var_os("DISPLAY").is_none_or(|display| display.is_empty()) {
        return Err(
            "Browser cookie capture requires X11 or XWayland (DISPLAY is unavailable)".to_owned(),
        );
    }
    let executable = std::env::current_exe()
        .map_err(|error| format!("Unable to locate the application executable: {error}"))?;
    let mut command = Command::new(executable);
    command
        .arg("--cookie-browser")
        .arg(config.login_url)
        .arg(&target_url)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(target_os = "linux")]
    command
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("WAYLAND_SOCKET")
        .env("GDK_BACKEND", "x11");
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("Unable to open the WebView2 login window: {error}"))?;
    let status = loop {
        if cancel.is_cancelled() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Authentication cancelled".to_owned());
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "Unable to monitor the WebView2 login window: {error}"
                ));
            }
        }
    };
    let mut output = Zeroizing::new(Vec::new());
    if let Some(mut stdout) = child.stdout.take() {
        stdout
            .read_to_end(&mut output)
            .map_err(|error| format!("Unable to read the WebView2 cookie result: {error}"))?;
    }
    let output_text = String::from_utf8_lossy(&output);
    if let Some(encoded) = output_text
        .lines()
        .find_map(|line| line.strip_prefix("NANCY_COOKIE_ERROR:"))
    {
        return Err({
            let (encoded,): (&str,) = (encoded,);
            let inlined_result: Result<String, String> = 'inlined_decode_protocol_text: {
                use base64::Engine;
                let decoded = match base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| "The WebView2 error result was invalid".to_owned())
                {
                    Ok(value) => value,
                    Err(error) => {
                        break 'inlined_decode_protocol_text Err(::core::convert::From::from(
                            error,
                        ));
                    }
                };
                String::from_utf8(decoded)
                    .map_err(|_| "The WebView2 error result was not valid text".to_owned())
            };
            inlined_result
        }?);
    }
    let encoded = output_text
        .lines()
        .find_map(|line| line.strip_prefix("NANCY_COOKIE_OK:"))
        .ok_or_else(|| "No cookies were returned by the WebView2 login window".to_owned())?;
    if !status.success() {
        return Err("The WebView2 login window closed without capturing cookies".to_owned());
    }
    use base64::Engine;
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| "The WebView2 cookie result was invalid".to_owned())?,
    );
    let records: Vec<CookieRecord> = serde_json::from_slice(&decoded)
        .map_err(|error| format!("The WebView2 cookie result was invalid: {error}"))?;
    let cookies = records
        .into_iter()
        .map(BrowserCookie::from_record)
        .collect::<Result<Vec<_>, _>>()?;
    store
        .lock()
        .map_err(|_| "Authentication profile store is unavailable".to_owned())?
        .set_browser_cookies(id, &target_url, cookies)?;
    Ok(format!("Captured browser cookies for '{}'", profile.name))
}

pub(super) fn normalize_cookie(input: &str) -> Result<String, String> {
    if input.contains(['\r', '\n']) {
        return Err("Cookie value cannot contain line breaks".to_owned());
    }
    let trimmed = input.trim();
    let value = trimmed
        .strip_prefix("Cookie:")
        .or_else(|| trimmed.strip_prefix("cookie:"))
        .unwrap_or(trimmed)
        .trim();
    if value.is_empty() {
        return Err("Cookie value is required".to_owned());
    }
    for pair in value.split(';') {
        let (name, _) = pair.trim().split_once('=').ok_or_else(|| {
            "Cookies must use name=value pairs separated by semicolons".to_owned()
        })?;
        if name.trim().is_empty() {
            return Err("Cookie name cannot be empty".to_owned());
        }
    }
    HeaderValue::from_str(value).map_err(|error| format!("Invalid cookie value: {error}"))?;
    Ok(value.to_owned())
}

pub(super) fn cookie_path_matches(cookie_path: &str, request_path: &str) -> bool {
    request_path == cookie_path
        || (request_path.starts_with(cookie_path)
            && (cookie_path.ends_with('/')
                || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')))
}

pub(super) fn parse_http_url(input: &str) -> Result<Url, String> {
    let normalized = if input.contains("://") {
        input.trim().to_owned()
    } else {
        format!("https://{}", input.trim())
    };
    let url = Url::parse(&normalized).map_err(|error| error.to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("an HTTP or HTTPS URL with a host is required".to_owned());
    }
    Ok(url)
}

pub(super) fn require_host_scope(input: &str) -> Result<String, String> {
    let scope = {
        let (input,): (&str,) = (input,);
        {
            input
                .trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or_default()
                .split(':')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        }
    };
    if scope.is_empty() {
        Err("Host scope is required".to_owned())
    } else {
        Ok(scope)
    }
}

pub(super) fn validate_host(target_url: &str, host_scope: &str) -> Result<(), String> {
    let scope = require_host_scope(host_scope)?;
    let target = parse_http_url(target_url)?;
    let host = target.host_str().unwrap_or_default().to_ascii_lowercase();
    let domain = scope.trim_start_matches('.');
    if host == domain || (scope.starts_with('.') && host.ends_with(&format!(".{domain}"))) {
        Ok(())
    } else {
        Err(format!("Authentication profile is restricted to {scope}"))
    }
}
