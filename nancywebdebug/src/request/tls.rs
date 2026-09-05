use crate::auth::LoadedClientCertificate;
use crate::diagnostics::{
    CertificateTrace, ClientAuthObservation, ClientAuthStatus, ProtocolPreference, TlsTrace,
};
use rustls::client::ResolvesClientCert;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::Verifier as PlatformVerifier;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

#[derive(Debug, Default)]
pub(crate) struct CertificateCapture {
    pub(super) certificates: Vec<Vec<u8>>,
    pub(super) ocsp_response: Vec<u8>,
    validation_error: Option<String>,
    client_certificate_requested: bool,
    client_certificate_profile: Option<String>,
}

#[derive(Debug)]
struct TrackingClientCertResolver {
    capture: Arc<Mutex<CertificateCapture>>,
    certified_key: Option<Arc<CertifiedKey>>,
}

impl ResolvesClientCert for TrackingClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.capture.lock().unwrap().client_certificate_requested = true;
        self.certified_key.clone()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct CapturingVerifier {
    inner: PlatformVerifier,
    capture: Arc<Mutex<CertificateCapture>>,
}

#[derive(Debug)]
struct PermissiveCapturingVerifier {
    capture: Arc<Mutex<CertificateCapture>>,
}

impl ServerCertVerifier for PermissiveCapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut capture = self.capture.lock().unwrap();
        capture.certificates.clear();
        capture.certificates.push(end_entity.as_ref().to_vec());
        capture
            .certificates
            .extend(intermediates.iter().map(|cert| cert.as_ref().to_vec()));
        capture.ocsp_response = ocsp_response.to_vec();
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        {
            let mut capture = self.capture.lock().unwrap();
            capture.certificates.clear();
            capture.certificates.push(end_entity.as_ref().to_vec());
            capture
                .certificates
                .extend(intermediates.iter().map(|cert| cert.as_ref().to_vec()));
            capture.ocsp_response = ocsp_response.to_vec();
            capture.validation_error = None;
        }
        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        if let Err(error) = &result {
            self.capture.lock().unwrap().validation_error = Some(error.to_string());
        }
        result
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub(super) fn make_tls_config(
    protocol: ProtocolPreference,
    capture: Arc<Mutex<CertificateCapture>>,
    http3: bool,
    client_certificate: Option<&LoadedClientCertificate>,
) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = PlatformVerifier::new(provider.clone()).map_err(|error| error.to_string())?;
    let verifier = CapturingVerifier {
        inner: verifier,
        capture: capture.clone(),
    };
    if let Some(client_certificate) = client_certificate {
        capture.lock().unwrap().client_certificate_profile =
            Some(client_certificate.profile_name.clone());
    }
    let resolver = TrackingClientCertResolver {
        capture: capture.clone(),
        certified_key: client_certificate.map(|certificate| certificate.certified_key.clone()),
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = if http3 {
        vec![b"h3".to_vec()]
    } else {
        match protocol {
            ProtocolPreference::Auto => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            ProtocolPreference::Http11 => vec![b"http/1.1".to_vec()],
            ProtocolPreference::Http2 => vec![b"h2".to_vec()],
            ProtocolPreference::Http3 => vec![b"h3".to_vec()],
        }
    };
    Ok(Arc::new(config))
}

pub(crate) fn make_exposure_tls_config(
    tls13: Option<bool>,
    permissive: bool,
    offer_http2: bool,
    capture: Arc<Mutex<CertificateCapture>>,
    client_certificate: Option<&LoadedClientCertificate>,
) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone());
    let builder = match tls13 {
        Some(true) => builder.with_protocol_versions(&[&rustls::version::TLS13]),
        Some(false) => builder.with_protocol_versions(&[&rustls::version::TLS12]),
        None => builder.with_safe_default_protocol_versions(),
    }
    .map_err(|error| error.to_string())?;
    let verifier: Arc<dyn ServerCertVerifier> = if permissive {
        Arc::new(PermissiveCapturingVerifier {
            capture: capture.clone(),
        })
    } else {
        let inner = PlatformVerifier::new(provider).map_err(|error| error.to_string())?;
        Arc::new(CapturingVerifier {
            inner,
            capture: capture.clone(),
        })
    };
    if let Some(client_certificate) = client_certificate {
        capture.lock().unwrap().client_certificate_profile =
            Some(client_certificate.profile_name.clone());
    }
    let resolver = TrackingClientCertResolver {
        capture: capture.clone(),
        certified_key: client_certificate.map(|certificate| certificate.certified_key.clone()),
    };
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = if offer_http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    Ok(Arc::new(config))
}

pub(crate) fn tls_trace_from_stream(
    host: &str,
    stream: &TlsStream<TcpStream>,
    capture: &Arc<Mutex<CertificateCapture>>,
) -> TlsTrace {
    let (_, connection) = stream.get_ref();
    let mut trace = tls_trace_from_capture(host, capture);
    trace.version = connection
        .protocol_version()
        .map(|version| format!("{version:?}"))
        .or_else(|| Some("Unavailable (not exposed by TLS library)".to_owned()));
    trace.cipher_suite = connection
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()))
        .or_else(|| Some("Unavailable (not exposed by TLS library)".to_owned()));
    trace.alpn = connection
        .alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
        .or_else(|| Some("Unavailable (server did not negotiate ALPN)".to_owned()));
    trace.validation = Some("Valid".to_owned());
    trace.client_auth = client_auth_observation(capture, true);
    trace
}

pub(super) fn tls_trace_from_quic(
    host: &str,
    connection: &quinn::Connection,
    capture: &Arc<Mutex<CertificateCapture>>,
) -> TlsTrace {
    let mut trace = tls_trace_from_capture(host, capture);
    trace.version = Some("TLS 1.3 (QUIC)".to_owned());
    trace.cipher_suite = Some("Unavailable (QUIC library does not expose it)".to_owned());
    trace.validation = Some("Valid".to_owned());
    if let Some(data) = connection.handshake_data()
        && let Ok(data) = data.downcast::<quinn::crypto::rustls::HandshakeData>()
    {
        trace.alpn = data
            .protocol
            .as_ref()
            .map(|protocol| String::from_utf8_lossy(protocol).into_owned());
    }
    trace.alpn.get_or_insert_with(|| {
        "Unavailable (QUIC library did not expose negotiated ALPN)".to_owned()
    });
    trace.client_auth = client_auth_observation(capture, true);
    trace
}

pub(crate) fn tls_trace_from_capture(
    host: &str,
    capture: &Arc<Mutex<CertificateCapture>>,
) -> TlsTrace {
    let client_auth = client_auth_observation(capture, false);
    let capture = capture.lock().unwrap();
    TlsTrace {
        server_name: host.to_owned(),
        version: Some("Unavailable (TLS handshake did not complete)".to_owned()),
        cipher_suite: Some("Unavailable (TLS handshake did not complete)".to_owned()),
        alpn: Some("Unavailable (TLS handshake did not complete)".to_owned()),
        validation: Some(
            if capture.validation_error.is_some() {
                "Invalid"
            } else {
                "Unavailable (validation did not complete)"
            }
            .to_owned(),
        ),
        validation_error: capture.validation_error.clone(),
        ocsp_response: capture.ocsp_response.clone(),
        certificates: capture
            .certificates
            .iter()
            .map(|der| parse_certificate(der))
            .collect(),
        client_auth,
    }
}

fn client_auth_observation(
    capture: &Arc<Mutex<CertificateCapture>>,
    handshake_succeeded: bool,
) -> ClientAuthObservation {
    let capture = capture.lock().unwrap();
    let requested = capture.client_certificate_requested;
    let profile_name = capture.client_certificate_profile.clone();
    let status = match (requested, profile_name.is_some(), handshake_succeeded) {
        (false, _, true) => ClientAuthStatus::Absent,
        (false, _, false) => ClientAuthStatus::Inconclusive,
        (true, false, true) => ClientAuthStatus::Optional,
        (true, false, false) => ClientAuthStatus::Required,
        (true, true, true) => ClientAuthStatus::Accepted,
        (true, true, false) => ClientAuthStatus::Rejected,
    };
    let evidence = if requested {
        vec!["The server sent a TLS CertificateRequest".to_owned()]
    } else if handshake_succeeded {
        vec!["The server did not send a TLS CertificateRequest".to_owned()]
    } else {
        vec!["The handshake ended before client-auth requirements could be established".to_owned()]
    };
    ClientAuthObservation {
        certificate_requested: requested,
        status,
        profile_name,
        evidence,
    }
}

pub(crate) fn parse_certificate(der: &[u8]) -> CertificateTrace {
    let fingerprint = Sha256::digest(der);
    let sha256 = fingerprint
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    match parse_x509_certificate(der) {
        Ok((_, certificate)) => {
            let subject_alt_names = certificate
                .subject_alternative_name()
                .ok()
                .flatten()
                .map(|extension| {
                    extension
                        .value
                        .general_names
                        .iter()
                        .map(|name| match name {
                            GeneralName::DNSName(name) => format!("DNS: {name}"),
                            GeneralName::IPAddress(bytes) => {
                                format!("IP: {}", format_ip_bytes(bytes))
                            }
                            other => format!("{other:?}"),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let public_key_bits = certificate
                .public_key()
                .parsed()
                .ok()
                .map(|key| key.key_size())
                .filter(|bits| *bits > 0);
            let basic_constraints = certificate.basic_constraints().ok().flatten();
            let is_ca = basic_constraints.as_ref().map(|value| value.value.ca);
            let basic_constraints_critical = basic_constraints.as_ref().map(|value| value.critical);
            let key_usage = certificate
                .key_usage()
                .ok()
                .flatten()
                .map(|value| {
                    value
                        .value
                        .to_string()
                        .split(", ")
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let extended_key_usage = certificate
                .extended_key_usage()
                .ok()
                .flatten()
                .map(|value| {
                    let value = value.value;
                    let mut usages = Vec::new();
                    for (present, name) in [
                        (value.any, "Any"),
                        (value.server_auth, "Server authentication"),
                        (value.client_auth, "Client authentication"),
                        (value.code_signing, "Code signing"),
                        (value.email_protection, "Email protection"),
                        (value.time_stamping, "Time stamping"),
                        (value.ocsp_signing, "OCSP signing"),
                    ] {
                        if present {
                            usages.push(name.to_owned());
                        }
                    }
                    usages.extend(value.other.iter().map(ToString::to_string));
                    usages
                })
                .unwrap_or_default();
            CertificateTrace {
                subject: certificate.subject().to_string(),
                issuer: certificate.issuer().to_string(),
                serial: certificate.raw_serial_as_string(),
                not_before: certificate.validity().not_before.to_string(),
                not_after: certificate.validity().not_after.to_string(),
                not_before_unix: Some(certificate.validity().not_before.timestamp()),
                not_after_unix: Some(certificate.validity().not_after.timestamp()),
                subject_alt_names,
                public_key_algorithm: certificate.public_key().algorithm.algorithm.to_id_string(),
                public_key_bits,
                signature_algorithm: certificate.signature_algorithm.algorithm.to_id_string(),
                is_ca,
                basic_constraints_critical,
                key_usage,
                extended_key_usage,
                sha256,
            }
        }
        Err(error) => CertificateTrace {
            subject: format!("Unable to parse certificate: {error}"),
            issuer: String::new(),
            serial: String::new(),
            not_before: String::new(),
            not_after: String::new(),
            not_before_unix: None,
            not_after_unix: None,
            subject_alt_names: Vec::new(),
            public_key_algorithm: String::new(),
            public_key_bits: None,
            signature_algorithm: String::new(),
            is_ca: None,
            basic_constraints_critical: None,
            key_usage: Vec::new(),
            extended_key_usage: Vec::new(),
            sha256,
        },
    }
}

fn format_ip_bytes(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])).to_string(),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            IpAddr::V6(Ipv6Addr::from(octets)).to_string()
        }
        _ => bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}
