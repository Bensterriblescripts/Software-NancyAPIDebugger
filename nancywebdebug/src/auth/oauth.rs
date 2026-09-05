use bytes::Bytes;
use http::header::HOST;
use http::{Request, Response, Uri, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use oauth2::basic::BasicClient;
use oauth2::{
    AsyncHttpClient, AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    HttpRequest, HttpResponse, PkceCodeChallenge, RedirectUrl, RefreshToken, Scope, TokenResponse,
    TokenUrl,
};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use rustls_platform_verifier::Verifier as PlatformVerifier;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use super::profiles::{
    AzureClientCredentialsProfile, AzureInteractiveProfile, CachedToken, SharedAuthStore,
    StoredProfileKind,
};

pub async fn sign_in_interactive(
    store: SharedAuthStore,
    id: u64,
    cancel: CancellationToken,
) -> Result<String, String> {
    let profile = store
        .lock()
        .map_err(|_| "Authentication profile store is unavailable".to_owned())?
        .profile(id)
        .ok_or_else(|| "Authentication profile no longer exists".to_owned())?;
    let StoredProfileKind::AzureInteractive(config) = profile.kind else {
        return Err("Profile does not use interactive Azure authentication".to_owned());
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| format!("Unable to start OAuth callback listener: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("Unable to read OAuth callback address: {error}"))?
        .port();
    let redirect = format!("http://127.0.0.1:{port}/callback");
    let (authorize, token) = azure_endpoints(&config.tenant)?;
    let client = BasicClient::new(ClientId::new(config.client_id.clone()))
        .set_auth_uri(AuthUrl::new(authorize).map_err(|error| error.to_string())?)
        .set_token_uri(TokenUrl::new(token).map_err(|error| error.to_string())?)
        .set_auth_type(AuthType::RequestBody)
        .set_redirect_uri(RedirectUrl::new(redirect.clone()).map_err(|error| error.to_string())?);
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut authorization = client.authorize_url(CsrfToken::new_random);
    for scope in interactive_scopes(&config.scopes) {
        authorization = authorization.add_scope(Scope::new(scope));
    }
    let (authorization_url, expected_state) = authorization.set_pkce_challenge(challenge).url();
    webbrowser::open(authorization_url.as_str())
        .map_err(|error| format!("Unable to open the system browser: {error}"))?;
    let (code, returned_state) = receive_oauth_callback(listener, &cancel).await?;
    if returned_state != *expected_state.secret() {
        return Err("OAuth state validation failed".to_owned());
    }
    let http_client = OAuthHttpClient;
    let request = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(verifier)
        .request_async(&http_client);
    let response = tokio::select! {
        _ = cancel.cancelled() => return Err("Authentication cancelled".to_owned()),
        response = tokio::time::timeout(Duration::from_secs(30), request) => response,
    }
    .map_err(|_| "Azure token exchange timed out".to_owned())?
    .map_err(|error| format!("Azure token exchange failed: {error}"))?;
    let token = cache_token(&response, None);
    store
        .lock()
        .map_err(|_| "Authentication profile store is unavailable".to_owned())?
        .set_token(id, token)?;
    Ok(format!("Signed in with '{}'", profile.name))
}

pub(super) async fn acquire_client_credentials(
    config: &AzureClientCredentialsProfile,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<CachedToken, String> {
    let (_, token) = azure_endpoints(&config.tenant)?;
    let client = BasicClient::new(ClientId::new(config.client_id.clone()))
        .set_client_secret(ClientSecret::new(config.client_secret.to_string()))
        .set_token_uri(TokenUrl::new(token).map_err(|error| error.to_string())?)
        .set_auth_type(AuthType::RequestBody);
    let http_client = OAuthHttpClient;
    let request = client
        .exchange_client_credentials()
        .add_scope(Scope::new(config.scope.clone()))
        .request_async(&http_client);
    let response = tokio::select! {
        _ = cancel.cancelled() => return Err("Authentication cancelled".to_owned()),
        response = tokio::time::timeout(timeout, request) => response,
    }
    .map_err(|_| "Azure token request timed out".to_owned())?
    .map_err(|error| format!("Azure token request failed: {error}"))?;
    Ok(cache_token(&response, None))
}

pub(super) async fn refresh_interactive(
    config: &AzureInteractiveProfile,
    refresh_token: Zeroizing<String>,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<CachedToken, String> {
    let (_, token) = azure_endpoints(&config.tenant)?;
    let client = BasicClient::new(ClientId::new(config.client_id.clone()))
        .set_token_uri(TokenUrl::new(token).map_err(|error| error.to_string())?)
        .set_auth_type(AuthType::RequestBody);
    let http_client = OAuthHttpClient;
    let refresh = RefreshToken::new(refresh_token.to_string());
    let request = client
        .exchange_refresh_token(&refresh)
        .request_async(&http_client);
    let response = tokio::select! {
        _ = cancel.cancelled() => return Err("Authentication cancelled".to_owned()),
        response = tokio::time::timeout(timeout, request) => response,
    }
    .map_err(|_| "Azure token refresh timed out".to_owned())?
    .map_err(|_| "Azure token refresh failed; sign in again".to_owned())?;
    Ok(cache_token(&response, Some(refresh_token)))
}

fn cache_token(
    response: &impl TokenResponse,
    previous_refresh: Option<Zeroizing<String>>,
) -> CachedToken {
    CachedToken {
        access_token: Zeroizing::new(response.access_token().secret().to_owned()),
        refresh_token: response
            .refresh_token()
            .map(|token| Zeroizing::new(token.secret().to_owned()))
            .or(previous_refresh),
        expires_at: Instant::now()
            + response
                .expires_in()
                .unwrap_or_else(|| Duration::from_secs(3600)),
    }
}

async fn receive_oauth_callback(
    listener: TcpListener,
    cancel: &CancellationToken,
) -> Result<(String, String), String> {
    let accepted = tokio::select! {
        _ = cancel.cancelled() => return Err("Authentication cancelled".to_owned()),
        accepted = tokio::time::timeout(Duration::from_secs(300), listener.accept()) => accepted,
    };
    let (mut stream, _) = accepted
        .map_err(|_| "Azure sign-in timed out".to_owned())?
        .map_err(|error| format!("OAuth callback failed: {error}"))?;
    let mut request = vec![0_u8; 16 * 1024];
    let length = stream
        .read(&mut request)
        .await
        .map_err(|error| format!("Unable to read OAuth callback: {error}"))?;
    let request = String::from_utf8_lossy(&request[..length]);
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| "OAuth callback request was invalid".to_owned())?;
    let callback = Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|error| format!("OAuth callback URL was invalid: {error}"))?;
    let parameters = callback.query_pairs().collect::<Vec<_>>();
    let error = parameters
        .iter()
        .find(|(key, _)| key == "error_description")
        .map(|(_, value)| value.to_string());
    let result = if let Some(error) = error {
        Err(error)
    } else {
        let code = parameters
            .iter()
            .find(|(key, _)| key == "code")
            .map(|(_, value)| value.to_string())
            .ok_or_else(|| "OAuth callback did not contain an authorization code".to_owned());
        let state = parameters
            .iter()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string())
            .ok_or_else(|| "OAuth callback did not contain state".to_owned());
        code.and_then(|code| state.map(|state| (code, state)))
    };
    let successful = result.is_ok();
    let body = if successful {
        "Sign-in completed. You can close this tab."
    } else {
        "Sign-in failed. Return to Nancy API Debugger for details."
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
    result
}

fn azure_endpoints(tenant: &str) -> Result<(String, String), String> {
    let tenant = tenant.trim();
    if tenant.is_empty()
        || !tenant
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '.'))
    {
        return Err(
            "Tenant must be a tenant ID, verified domain, or Azure tenant alias".to_owned(),
        );
    }
    let base = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0");
    Ok((format!("{base}/authorize"), format!("{base}/token")))
}

fn interactive_scopes(scopes: &str) -> Vec<String> {
    let mut scopes = normalize_scopes(scopes)
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !scopes.iter().any(|scope| scope == "offline_access") {
        scopes.push("offline_access".to_owned());
    }
    scopes
}

pub(super) fn normalize_scopes(scopes: &str) -> String {
    scopes.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn validate_azure(tenant: &str, client_id: &str, scopes: &str) -> Result<(), String> {
    azure_endpoints(tenant)?;
    if client_id.trim().is_empty() {
        return Err("Client ID is required".to_owned());
    }
    if normalize_scopes(scopes).is_empty() {
        return Err("At least one scope is required".to_owned());
    }
    Ok(())
}

struct OAuthHttpClient;

impl<'c> AsyncHttpClient<'c> for OAuthHttpClient {
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(send_oauth_request(request))
    }
}

async fn send_oauth_request(request: HttpRequest) -> Result<HttpResponse, io::Error> {
    let authority = request
        .uri()
        .authority()
        .cloned()
        .ok_or_else(|| oauth_io_error("OAuth request URL has no authority"))?;
    if request.uri().scheme_str() != Some("https") {
        return Err(oauth_io_error("OAuth token requests require HTTPS"));
    }
    let host = authority.host().to_owned();
    let tcp = TcpStream::connect((host.as_str(), authority.port_u16().unwrap_or(443))).await?;
    let server_name = ServerName::try_from(host).map_err(oauth_io_error)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = PlatformVerifier::new(provider.clone()).map_err(oauth_io_error)?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(oauth_io_error)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls = TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .map_err(oauth_io_error)?;
    let version = match tls.get_ref().1.alpn_protocol() {
        Some(b"h2") => Version::HTTP_2,
        _ => Version::HTTP_11,
    };
    let request = oauth_origin_form_request(request, authority, version)?;
    let response = match version {
        Version::HTTP_2 => send_oauth_http2(tls, request).await?,
        _ => send_oauth_http1(tls, request).await?,
    };
    let (parts, body) = response.into_parts();
    let body = body
        .collect()
        .await
        .map_err(oauth_io_error)?
        .to_bytes()
        .to_vec();
    Ok(Response::from_parts(parts, body))
}

fn oauth_origin_form_request(
    request: HttpRequest,
    authority: http::uri::Authority,
    version: Version,
) -> Result<Request<Full<Bytes>>, io::Error> {
    let (mut parts, body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    parts.uri = path.parse::<Uri>().map_err(oauth_io_error)?;
    parts.version = version;
    if !parts.headers.contains_key(HOST) {
        parts
            .headers
            .insert(HOST, authority.as_str().parse().map_err(oauth_io_error)?);
    }
    Ok(Request::from_parts(parts, Full::new(Bytes::from(body))))
}

async fn send_oauth_http1(
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    request: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, io::Error> {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(oauth_io_error)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender.send_request(request).await.map_err(oauth_io_error)
}

async fn send_oauth_http2(
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    request: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, io::Error> {
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .map_err(oauth_io_error)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender.send_request(request).await.map_err(oauth_io_error)
}

fn oauth_io_error(value: impl ToString) -> io::Error {
    io::Error::other(value.to_string())
}
