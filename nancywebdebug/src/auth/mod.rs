mod browser;
mod cookies;
mod http;
mod oauth;
mod profiles;

pub(crate) use browser::{run as run_cookie_browser, write_protocol_result};
pub use cookies::capture_browser_cookies;
pub use oauth::sign_in_interactive;
pub use profiles::{AuthStore, ProfileInput, ProfileSummary, ProfileType, SharedAuthStore};

use cookies::{parse_http_url, validate_host};
use oauth::{acquire_client_credentials, refresh_interactive};
use profiles::{CachedToken, StoredProfileKind};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct ResolvedAuth {
    pub header_name: &'static str,
    pub header_value: Zeroizing<String>,
    pub detail: String,
}

pub async fn resolve(
    store: SharedAuthStore,
    id: u64,
    target_url: &str,
    timeout: Duration,
    cancel: CancellationToken,
) -> Result<ResolvedAuth, String> {
    let profile = store
        .lock()
        .map_err(|_| "Authentication profile store is unavailable".to_owned())?
        .profile(id)
        .ok_or_else(|| "Authentication profile no longer exists".to_owned())?;
    match profile.kind {
        StoredProfileKind::AzureInteractive(config) => {
            let token = if let Some(token) = config.token.clone().filter(CachedToken::is_valid) {
                token
            } else if let Some(refresh_token) = config
                .token
                .as_ref()
                .and_then(|token| token.refresh_token.clone())
            {
                let token = refresh_interactive(&config, refresh_token, timeout, &cancel).await?;
                store
                    .lock()
                    .map_err(|_| "Authentication profile store is unavailable".to_owned())?
                    .set_token(id, token.clone())?;
                token
            } else {
                return Err(format!(
                    "Profile '{}' requires interactive sign-in",
                    profile.name
                ));
            };
            Ok(ResolvedAuth {
                header_name: "authorization",
                header_value: Zeroizing::new(format!("Bearer {}", token.access_token.as_str())),
                detail: format!("Azure bearer token from '{}'", profile.name),
            })
        }
        StoredProfileKind::AzureClientCredentials(config) => {
            let token = if let Some(token) = config.token.clone().filter(CachedToken::is_valid) {
                token
            } else {
                let token = acquire_client_credentials(&config, timeout, &cancel).await?;
                store
                    .lock()
                    .map_err(|_| "Authentication profile store is unavailable".to_owned())?
                    .set_token(id, token.clone())?;
                token
            };
            Ok(ResolvedAuth {
                header_name: "authorization",
                header_value: Zeroizing::new(format!("Bearer {}", token.access_token.as_str())),
                detail: format!("Azure app token from '{}'", profile.name),
            })
        }
        StoredProfileKind::BrowserCookies(config) => {
            validate_host(target_url, &config.host_scope)?;
            let url = parse_http_url(target_url)?;
            let mut cookies = config
                .cookies
                .iter()
                .filter(|cookie| cookie.applies_to(&url))
                .collect::<Vec<_>>();
            cookies.sort_by_key(|cookie| std::cmp::Reverse(cookie.path.len()));
            if cookies.is_empty() {
                return Err(format!(
                    "Profile '{}' has no captured cookies applicable to this URL",
                    profile.name
                ));
            }
            let mut header = Zeroizing::new(String::new());
            for cookie in cookies {
                if !header.is_empty() {
                    header.push_str("; ");
                }
                header.push_str(&cookie.name);
                header.push('=');
                header.push_str(cookie.value.as_str());
            }
            Ok(ResolvedAuth {
                header_name: "cookie",
                header_value: header,
                detail: format!("Browser cookies from '{}'", profile.name),
            })
        }
        StoredProfileKind::ManualCookie(config) => {
            validate_host(target_url, &config.host_scope)?;
            Ok(ResolvedAuth {
                header_name: "cookie",
                header_value: config.cookie,
                detail: format!("Manual cookie from '{}'", profile.name),
            })
        }
    }
}
