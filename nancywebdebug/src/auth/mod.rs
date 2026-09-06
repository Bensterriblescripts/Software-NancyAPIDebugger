mod browser;
mod cookies;
mod oauth;
mod profiles;

pub(crate) use browser::{run as run_cookie_browser, write_protocol_result};
pub use cookies::capture_browser_cookies;
pub use oauth::sign_in_interactive;
pub use profiles::{
    AuthStore, ClientCertificateProfile, ProfileInput, ProfileSummary, ProfileType, SharedAuthStore,
};

use cookies::{parse_http_url, validate_host};
use oauth::{acquire_client_credentials, refresh_interactive};
use profiles::StoredProfileKind;
use rustls::pki_types::CertificateDer;
use rustls::sign::CertifiedKey;
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct ResolvedAuth {
    pub header_name: &'static str,
    pub header_value: Zeroizing<String>,
    pub detail: String,
}

#[derive(Clone)]
pub(crate) struct LoadedClientCertificate {
    pub(crate) profile_name: String,
    pub(crate) host_scope: String,
    pub(crate) certified_key: Arc<CertifiedKey>,
}

impl fmt::Debug for LoadedClientCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedClientCertificate")
            .field("profile_name", &self.profile_name)
            .field("host_scope", &self.host_scope)
            .finish_non_exhaustive()
    }
}

impl LoadedClientCertificate {
    pub(crate) fn applies_to(&self, host: &str) -> bool {
        host.trim_matches(['[', ']'])
            .trim_end_matches('.')
            .eq_ignore_ascii_case(&self.host_scope)
    }
}

pub(crate) fn certificate_file_metadata(
    path: &str,
) -> Result<crate::diagnostics::CertificateTrace, String> {
    let certificates = read_certificates(path)?;
    let certificate = crate::request::parse_certificate(certificates[0].as_ref());
    if certificate
        .subject
        .starts_with("Unable to parse certificate:")
    {
        return Err(certificate.subject);
    }
    Ok(certificate)
}

fn read_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file =
        File::open(path).map_err(|error| format!("Unable to open certificate chain: {error}"))?;
    let mut reader = BufReader::new(file);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Invalid PEM certificate chain: {error}"))?;
    if certificates.is_empty() {
        return Err("Certificate chain contains no PEM certificates".to_owned());
    }
    Ok(certificates)
}

pub(crate) fn resolve_client_certificate(
    store: SharedAuthStore,
    id: u64,
    target_url: &str,
) -> Result<LoadedClientCertificate, String> {
    let profile = store
        .lock()
        .map_err(|_| "Authentication profile store is unavailable".to_owned())?
        .profile(id)
        .ok_or_else(|| "Client-certificate profile no longer exists".to_owned())?;
    let StoredProfileKind::ClientCertificate(config) = profile.kind else {
        return Err("Selected profile is not a client-certificate profile".to_owned());
    };
    validate_host(target_url, &config.host_scope)?;
    let certificates = read_certificates(&config.certificate_chain_path)?;
    let file = File::open(&config.private_key_path)
        .map_err(|error| format!("Unable to open private-key file: {error}"))?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|error| format!("Invalid PEM private key: {error}"))?
        .ok_or_else(|| "Private-key file contains no supported unencrypted PEM key".to_owned())?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let certified_key = CertifiedKey::from_der(certificates, key, &provider)
        .map_err(|error| format!("Invalid client certificate or private key: {error}"))?;
    certified_key
        .keys_match()
        .map_err(|error| format!("Client certificate and private key do not match: {error}"))?;
    Ok(LoadedClientCertificate {
        profile_name: profile.name,
        host_scope: config.host_scope,
        certified_key: Arc::new(certified_key),
    })
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
            let token = if let Some(token) = config.token.clone().filter(|token| {
                token.expires_at > std::time::Instant::now() + std::time::Duration::from_secs(60)
            }) {
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
            let token = if let Some(token) = config.token.clone().filter(|token| {
                token.expires_at > std::time::Instant::now() + std::time::Duration::from_secs(60)
            }) {
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
        StoredProfileKind::ClientCertificate(_) => {
            Err("Client-certificate profiles must be selected separately".to_owned())
        }
    }
}
