use bytes::Bytes;
use http::header::HOST;
use http::{Request, Response, Uri, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use oauth2::{AsyncHttpClient, HttpRequest, HttpResponse};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use rustls_platform_verifier::Verifier as PlatformVerifier;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub(super) struct OAuthHttpClient;

impl<'c> AsyncHttpClient<'c> for OAuthHttpClient {
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(send(request))
    }
}

async fn send(request: HttpRequest) -> Result<HttpResponse, io::Error> {
    let authority = request
        .uri()
        .authority()
        .cloned()
        .ok_or_else(|| error("OAuth request URL has no authority"))?;
    if request.uri().scheme_str() != Some("https") {
        return Err(error("OAuth token requests require HTTPS"));
    }
    let host = authority.host().to_owned();
    let port = authority.port_u16().unwrap_or(443);
    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    let server_name = ServerName::try_from(host).map_err(error)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = PlatformVerifier::new(provider.clone()).map_err(error)?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(error)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls = TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .map_err(error)?;
    let version = match tls.get_ref().1.alpn_protocol() {
        Some(b"h2") => Version::HTTP_2,
        _ => Version::HTTP_11,
    };
    let request = origin_form_request(request, authority, version)?;
    let response = match version {
        Version::HTTP_2 => send_http2(tls, request).await?,
        _ => send_http1(tls, request).await?,
    };
    let (parts, body) = response.into_parts();
    let body = body.collect().await.map_err(error)?.to_bytes().to_vec();
    Ok(Response::from_parts(parts, body))
}

fn origin_form_request(
    request: HttpRequest,
    authority: http::uri::Authority,
    version: Version,
) -> Result<Request<Full<Bytes>>, io::Error> {
    let (mut parts, body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    parts.uri = path.parse::<Uri>().map_err(error)?;
    parts.version = version;
    if !parts.headers.contains_key(HOST) {
        parts
            .headers
            .insert(HOST, authority.as_str().parse().map_err(error)?);
    }
    Ok(Request::from_parts(parts, Full::new(Bytes::from(body))))
}

async fn send_http1(
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    request: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, io::Error> {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(error)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender.send_request(request).await.map_err(error)
}

async fn send_http2(
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    request: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, io::Error> {
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .map_err(error)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender.send_request(request).await.map_err(error)
}

fn error(value: impl ToString) -> io::Error {
    io::Error::other(value.to_string())
}
