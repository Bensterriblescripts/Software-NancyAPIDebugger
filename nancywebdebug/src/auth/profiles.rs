use crate::diagnostics::RequestAuth;
use http::HeaderValue;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use super::browser::CookieRecord;
use super::cookies::{
    cookie_path_matches, normalize_cookie, normalize_cookie_path, parse_http_url,
    require_host_scope, unix_timestamp_now, validate_host,
};
use super::oauth::{normalize_scopes, validate_azure};

pub type SharedAuthStore = Arc<Mutex<AuthStore>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileType {
    AzureInteractive,
    AzureClientCredentials,
    BrowserCookies,
    ManualCookie,
}

impl ProfileType {
    pub const ALL: [Self; 4] = [
        Self::AzureInteractive,
        Self::AzureClientCredentials,
        Self::BrowserCookies,
        Self::ManualCookie,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::AzureInteractive => "Azure interactive (PKCE)",
            Self::AzureClientCredentials => "Azure client credentials",
            Self::BrowserCookies => "Browser session cookies",
            Self::ManualCookie => "Manual session cookie",
        }
    }
}

#[derive(Clone)]
pub struct ProfileInput {
    pub name: String,
    pub profile_type: ProfileType,
    pub tenant: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: String,
    pub login_url: String,
    pub host_scope: String,
    pub cookie: String,
}

impl Default for ProfileInput {
    fn default() -> Self {
        Self {
            name: String::new(),
            profile_type: ProfileType::AzureInteractive,
            tenant: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: String::new(),
            login_url: String::new(),
            host_scope: String::new(),
            cookie: String::new(),
        }
    }
}

impl ProfileInput {
    pub fn clear_sensitive(&mut self) {
        self.client_secret.zeroize();
        self.cookie.zeroize();
    }
}

impl Drop for ProfileInput {
    fn drop(&mut self) {
        self.clear_sensitive();
    }
}

#[derive(Clone)]
pub struct ProfileSummary {
    pub id: u64,
    pub name: String,
    pub profile_type: ProfileType,
    pub status: String,
}

#[derive(Clone)]
pub(super) struct CachedToken {
    pub(super) access_token: Zeroizing<String>,
    pub(super) refresh_token: Option<Zeroizing<String>>,
    pub(super) expires_at: Instant,
}

impl CachedToken {
    pub(super) fn is_valid(&self) -> bool {
        self.expires_at > Instant::now() + Duration::from_secs(60)
    }
}

#[derive(Clone)]
pub(super) struct AzureInteractiveProfile {
    pub(super) tenant: String,
    pub(super) client_id: String,
    pub(super) scopes: String,
    pub(super) token: Option<CachedToken>,
}

#[derive(Clone)]
pub(super) struct AzureClientCredentialsProfile {
    pub(super) tenant: String,
    pub(super) client_id: String,
    pub(super) client_secret: Zeroizing<String>,
    pub(super) scope: String,
    pub(super) token: Option<CachedToken>,
}

#[derive(Clone)]
pub(super) struct BrowserCookieProfile {
    pub(super) login_url: String,
    pub(super) host_scope: String,
    pub(super) cookies: Vec<BrowserCookie>,
    pub(super) captured_for: Option<String>,
}

#[derive(Clone)]
pub struct BrowserCookie {
    pub(super) domain: String,
    pub(super) path: String,
    pub(super) secure: bool,
    pub(super) expires_at: Option<i64>,
    pub(super) name: String,
    pub(super) value: Zeroizing<String>,
}

impl BrowserCookie {
    pub(super) fn from_record(mut record: CookieRecord) -> Result<Self, String> {
        if record.name.is_empty() || record.name.contains([';', '=']) {
            return Err("Captured cookie has an invalid name".to_owned());
        }
        HeaderValue::from_str(&record.value)
            .map_err(|error| format!("Captured cookie has an invalid value: {error}"))?;
        let value = Zeroizing::new(std::mem::take(&mut record.value));
        Ok(Self {
            domain: record.domain.trim().to_ascii_lowercase(),
            path: normalize_cookie_path(&record.path),
            secure: record.secure,
            expires_at: record.expires_at,
            name: record.name.trim().to_owned(),
            value,
        })
    }

    pub fn applies_to(&self, url: &Url) -> bool {
        if self.secure && url.scheme() != "https" {
            return false;
        }
        if self
            .expires_at
            .is_some_and(|expiry| expiry <= unix_timestamp_now())
        {
            return false;
        }
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let domain = self.domain.trim_start_matches('.');
        let domain_matches = if self.domain.starts_with('.') {
            host == domain || host.ends_with(&format!(".{domain}"))
        } else {
            host == domain
        };
        domain_matches && cookie_path_matches(&self.path, url.path())
    }
}

#[derive(Clone)]
pub(super) struct ManualCookieProfile {
    pub(super) host_scope: String,
    pub(super) cookie: Zeroizing<String>,
}

#[derive(Clone)]
pub(super) enum StoredProfileKind {
    AzureInteractive(AzureInteractiveProfile),
    AzureClientCredentials(AzureClientCredentialsProfile),
    BrowserCookies(BrowserCookieProfile),
    ManualCookie(ManualCookieProfile),
}

impl StoredProfileKind {
    fn profile_type(&self) -> ProfileType {
        match self {
            Self::AzureInteractive(_) => ProfileType::AzureInteractive,
            Self::AzureClientCredentials(_) => ProfileType::AzureClientCredentials,
            Self::BrowserCookies(_) => ProfileType::BrowserCookies,
            Self::ManualCookie(_) => ProfileType::ManualCookie,
        }
    }

    fn status(&self) -> String {
        match self {
            Self::AzureInteractive(profile) => match &profile.token {
                Some(token) if token.is_valid() => "Signed in".to_owned(),
                Some(_) => "Token expired; refresh available".to_owned(),
                None => "Sign-in required".to_owned(),
            },
            Self::AzureClientCredentials(profile) => match &profile.token {
                Some(token) if token.is_valid() => "Token cached".to_owned(),
                _ => "Token acquired when sent".to_owned(),
            },
            Self::BrowserCookies(profile) => match &profile.captured_for {
                Some(target) => format!("{} cookies captured for {target}", profile.cookies.len()),
                None => "Cookie capture required".to_owned(),
            },
            Self::ManualCookie(_) => "Ready".to_owned(),
        }
    }
}

#[derive(Clone)]
pub(super) struct AuthProfile {
    pub(super) id: u64,
    pub(super) name: String,
    pub(super) kind: StoredProfileKind,
}

pub struct AuthStore {
    profiles: Vec<AuthProfile>,
    next_id: u64,
}

impl Default for AuthStore {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            next_id: 1,
        }
    }
}

impl AuthStore {
    pub fn shared() -> SharedAuthStore {
        Arc::new(Mutex::new(Self::default()))
    }

    pub fn summaries(&self) -> Vec<ProfileSummary> {
        self.profiles
            .iter()
            .map(|profile| ProfileSummary {
                id: profile.id,
                name: profile.name.clone(),
                profile_type: profile.kind.profile_type(),
                status: profile.kind.status(),
            })
            .collect()
    }

    pub fn metadata(&self, id: u64) -> Option<RequestAuth> {
        self.profiles
            .iter()
            .find(|profile| profile.id == id)
            .map(|profile| RequestAuth {
                profile_id: profile.id,
                profile_name: profile.name.clone(),
                profile_kind: profile.kind.profile_type().label().to_owned(),
            })
    }

    pub fn profile_input(&self, id: u64) -> Option<ProfileInput> {
        let profile = self.profiles.iter().find(|profile| profile.id == id)?;
        let mut input = ProfileInput::default();
        input.name = profile.name.clone();
        input.profile_type = profile.kind.profile_type();
        match &profile.kind {
            StoredProfileKind::AzureInteractive(config) => {
                input.tenant = config.tenant.clone();
                input.client_id = config.client_id.clone();
                input.scopes = config.scopes.clone();
            }
            StoredProfileKind::AzureClientCredentials(config) => {
                input.tenant = config.tenant.clone();
                input.client_id = config.client_id.clone();
                input.client_secret = config.client_secret.to_string();
                input.scopes = config.scope.clone();
            }
            StoredProfileKind::BrowserCookies(config) => {
                input.login_url = config.login_url.clone();
                input.host_scope = config.host_scope.clone();
            }
            StoredProfileKind::ManualCookie(config) => {
                input.host_scope = config.host_scope.clone();
                input.cookie = config.cookie.to_string();
            }
        }
        Some(input)
    }

    pub fn save(&mut self, editing: Option<u64>, input: &ProfileInput) -> Result<u64, String> {
        let name = input.name.trim().to_owned();
        if name.is_empty() {
            return Err("Profile name is required".to_owned());
        }
        if self
            .profiles
            .iter()
            .any(|profile| Some(profile.id) != editing && profile.name.eq_ignore_ascii_case(&name))
        {
            return Err("Profile names must be unique".to_owned());
        }
        let kind = match input.profile_type {
            ProfileType::AzureInteractive => {
                validate_azure(&input.tenant, &input.client_id, &input.scopes)?;
                StoredProfileKind::AzureInteractive(AzureInteractiveProfile {
                    tenant: input.tenant.trim().to_owned(),
                    client_id: input.client_id.trim().to_owned(),
                    scopes: normalize_scopes(&input.scopes),
                    token: None,
                })
            }
            ProfileType::AzureClientCredentials => {
                validate_azure(&input.tenant, &input.client_id, &input.scopes)?;
                if input.client_secret.is_empty() {
                    return Err("Client secret is required".to_owned());
                }
                let scope = normalize_scopes(&input.scopes);
                if scope.split_whitespace().count() != 1 || !scope.ends_with("/.default") {
                    return Err(
                        "Client credentials require one scope ending in /.default".to_owned()
                    );
                }
                StoredProfileKind::AzureClientCredentials(AzureClientCredentialsProfile {
                    tenant: input.tenant.trim().to_owned(),
                    client_id: input.client_id.trim().to_owned(),
                    client_secret: Zeroizing::new(input.client_secret.clone()),
                    scope,
                    token: None,
                })
            }
            ProfileType::BrowserCookies => {
                let login_url = parse_http_url(&input.login_url)
                    .map_err(|error| format!("Login URL: {error}"))?
                    .to_string();
                let host_scope = require_host_scope(&input.host_scope)?;
                StoredProfileKind::BrowserCookies(BrowserCookieProfile {
                    login_url,
                    host_scope,
                    cookies: Vec::new(),
                    captured_for: None,
                })
            }
            ProfileType::ManualCookie => {
                let host_scope = require_host_scope(&input.host_scope)?;
                let cookie = normalize_cookie(&input.cookie)?;
                StoredProfileKind::ManualCookie(ManualCookieProfile {
                    host_scope,
                    cookie: Zeroizing::new(cookie),
                })
            }
        };
        if let Some(id) = editing {
            let profile = self
                .profiles
                .iter_mut()
                .find(|profile| profile.id == id)
                .ok_or_else(|| "Authentication profile no longer exists".to_owned())?;
            profile.name = name;
            if same_configuration(&profile.kind, &kind) {
                return Ok(id);
            }
            profile.kind = kind;
            Ok(id)
        } else {
            let id = self.next_id;
            self.next_id += 1;
            self.profiles.push(AuthProfile { id, name, kind });
            Ok(id)
        }
    }

    pub fn delete(&mut self, id: u64) -> bool {
        let before = self.profiles.len();
        self.profiles.retain(|profile| profile.id != id);
        self.profiles.len() != before
    }

    pub(super) fn profile(&self, id: u64) -> Option<AuthProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.id == id)
            .cloned()
    }

    pub(super) fn set_token(&mut self, id: u64, token: CachedToken) -> Result<(), String> {
        let profile = self
            .profiles
            .iter_mut()
            .find(|profile| profile.id == id)
            .ok_or_else(|| "Authentication profile was deleted".to_owned())?;
        match &mut profile.kind {
            StoredProfileKind::AzureInteractive(config) => config.token = Some(token),
            StoredProfileKind::AzureClientCredentials(config) => config.token = Some(token),
            _ => return Err("Profile is not an Azure OAuth2 profile".to_owned()),
        }
        Ok(())
    }

    pub(super) fn set_browser_cookies(
        &mut self,
        id: u64,
        target: &str,
        cookies: Vec<BrowserCookie>,
    ) -> Result<(), String> {
        let profile = self
            .profiles
            .iter_mut()
            .find(|profile| profile.id == id)
            .ok_or_else(|| "Authentication profile was deleted".to_owned())?;
        let StoredProfileKind::BrowserCookies(config) = &mut profile.kind else {
            return Err("Profile does not use browser cookies".to_owned());
        };
        let url = parse_http_url(target)?;
        let host = url
            .host_str()
            .ok_or_else(|| "Request URL has no host".to_owned())?
            .to_ascii_lowercase();
        validate_host(target, &config.host_scope)?;
        if cookies.is_empty() {
            return Err("No captured cookies apply to the request URL".to_owned());
        }
        config.cookies = cookies;
        config.captured_for = Some(host);
        Ok(())
    }
}

fn same_configuration(current: &StoredProfileKind, replacement: &StoredProfileKind) -> bool {
    match (current, replacement) {
        (StoredProfileKind::AzureInteractive(a), StoredProfileKind::AzureInteractive(b)) => {
            a.tenant == b.tenant && a.client_id == b.client_id && a.scopes == b.scopes
        }
        (
            StoredProfileKind::AzureClientCredentials(a),
            StoredProfileKind::AzureClientCredentials(b),
        ) => {
            a.tenant == b.tenant
                && a.client_id == b.client_id
                && a.client_secret.as_str() == b.client_secret.as_str()
                && a.scope == b.scope
        }
        (StoredProfileKind::BrowserCookies(a), StoredProfileKind::BrowserCookies(b)) => {
            a.login_url == b.login_url && a.host_scope == b.host_scope
        }
        (StoredProfileKind::ManualCookie(a), StoredProfileKind::ManualCookie(b)) => {
            a.host_scope == b.host_scope && a.cookie.as_str() == b.cookie.as_str()
        }
        _ => false,
    }
}
