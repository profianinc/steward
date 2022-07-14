// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

#![warn(rust_2018_idioms, unused_lifetimes, unused_qualifications, clippy::all)]

#[macro_use]
extern crate anyhow;

mod crypto;
mod ext;

use crypto::*;
use ext::{kvm::Kvm, sgx::Sgx, snp::Snp, ExtVerifier};
use x509::ext::pkix::name::GeneralName;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::{Extension, TypedHeader};
use axum::headers::ContentType;
use axum::routing::{get, post};
use axum::Router;
use hyper::StatusCode;
use mime::Mime;

use const_oid::db::rfc5280::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_CE_SUBJECT_ALT_NAME,
    ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH,
};
use const_oid::db::rfc5912::ID_EXTENSION_REQ;
use der::asn1::{GeneralizedTime, Ia5String, UIntBytes};
use der::{Decodable, Encodable};
use pkcs8::PrivateKeyInfo;
use rustls_pemfile::Item;
use x509::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName};
use x509::name::RdnSequence;
use x509::request::{CertReq, ExtensionReq};
use x509::time::{Time, Validity};
use x509::{Certificate, PkiPath, TbsCertificate};

use clap::Parser;
use zeroize::Zeroizing;

#[cfg(not(target_arch = "wasm32"))]
use anyhow::Context;
#[cfg(not(target_arch = "wasm32"))]
use std::fs::read;
#[cfg(not(target_arch = "wasm32"))]
use std::net::SocketAddr;

#[cfg(target_arch = "wasm32")]
use pem;

const PKCS10: &str = "application/pkcs10";

/// Attestation server for use with Enarx.
///
/// Any command-line options listed here may be specified by one or
/// more configuration files, which can be used by passing the
/// name of the file on the command-line with the syntax `@config.toml`.
/// The configuration file must contain valid TOML table mapping argument
/// names to their values.
#[derive(Clone, Debug, Parser)]
#[clap(author, version, about)]
struct Args {
    #[clap(short, long, env = "STEWARD_KEY")]
    key: Option<PathBuf>,

    #[clap(short, long, env = "STEWARD_CRT")]
    crt: Option<PathBuf>,

    #[clap(short, long, env = "ROCKET_PORT", default_value = "3000")]
    port: u16,

    #[clap(short, long, env = "ROCKET_ADDRESS", default_value = "::")]
    addr: IpAddr,

    #[clap(short, long, env = "RENDER_EXTERNAL_HOSTNAME")]
    host: Option<String>,

    #[clap(long, env = "STEWARD_SAN")]
    san: Option<String>,
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
struct State {
    key: Zeroizing<Vec<u8>>,
    crt: Vec<u8>,
    san: Option<String>,
}

impl State {
    #[allow(unused_variables, dead_code)]
    pub fn load(
        san: Option<String>,
        key: impl AsRef<Path>,
        crt: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        // Load the key file.
        let mut key = std::io::BufReader::new(std::fs::File::open(key)?);
        let key = match rustls_pemfile::read_one(&mut key)? {
            Some(Item::PKCS8Key(buf)) => Zeroizing::new(buf),
            _ => return Err(anyhow!("invalid key file")),
        };

        // Load the crt file.
        let mut crt = std::io::BufReader::new(std::fs::File::open(crt)?);
        let crt = match rustls_pemfile::read_one(&mut crt)? {
            Some(Item::X509Certificate(buf)) => buf,
            _ => return Err(anyhow!("invalid key file")),
        };

        // Validate the syntax of the files.
        PrivateKeyInfo::from_der(key.as_ref())?;
        Certificate::from_der(crt.as_ref())?;

        Ok(Self { key, crt, san })
    }

    #[cfg(target_arch = "wasm32")]
    pub fn load_memory() -> anyhow::Result<Self> {
        const CRT: &str = include_str!("../testdata/ca.crt");
        const KEY: &str = include_str!("../testdata/ca.key");

        let crt = pem::parse(CRT)?;
        let key = pem::parse(KEY)?;

        Ok(State {
            key: Zeroizing::new(key.contents),
            crt: crt.contents,
            san: None,
        })
    }

    pub fn generate(san: Option<String>, hostname: &str) -> anyhow::Result<Self> {
        use const_oid::db::rfc5912::SECP_256_R_1 as P256;

        // Generate the private key.
        let key = PrivateKeyInfo::generate(P256)?;
        let pki = PrivateKeyInfo::from_der(key.as_ref())?;

        // Create a relative distinguished name.
        let rdns = RdnSequence::encode_from_string(&format!("CN={}", hostname))?;
        let rdns = RdnSequence::from_der(&rdns)?;

        // Create the extensions.
        let ku = KeyUsage(KeyUsages::KeyCertSign.into()).to_vec()?;
        let bc = BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        }
        .to_vec()?;

        // Create the certificate duration.
        let now = SystemTime::now();
        let dur = Duration::from_secs(60 * 60 * 24 * 365);
        let validity = Validity {
            not_before: Time::GeneralTime(GeneralizedTime::from_system_time(now)?),
            not_after: Time::GeneralTime(GeneralizedTime::from_system_time(now + dur)?),
        };

        // Create the certificate body.
        let tbs = TbsCertificate {
            version: x509::Version::V3,
            serial_number: UIntBytes::new(&[0u8])?,
            signature: pki.signs_with()?,
            issuer: rdns.clone(),
            validity,
            subject: rdns,
            subject_public_key_info: pki.public_key()?,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![
                x509::ext::Extension {
                    extn_id: ID_CE_KEY_USAGE,
                    critical: true,
                    extn_value: &ku,
                },
                x509::ext::Extension {
                    extn_id: ID_CE_BASIC_CONSTRAINTS,
                    critical: true,
                    extn_value: &bc,
                },
            ]),
        };

        // Self-sign the certificate.
        let crt = tbs.sign(&pki)?;
        Ok(Self { key, crt, san })
    }
}

#[cfg(target_arch = "wasm32")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    use std::os::wasi::io::FromRawFd;

    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let state = match (args.key, args.crt, args.host) {
        (None, None, Some(host)) => State::generate(args.san, &host)?,
        (Some(key), Some(crt), _) => State::load(args.san, key, crt)?,
        (None, None, None) => State::load_memory()?,
        _ => panic!("invalid configuration"),
    };

    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(3) };
    std_listener.set_nonblocking(true).unwrap();
    axum::Server::from_tcp(std_listener)
        .unwrap()
        .serve(app(state).into_make_service())
        .await?;

    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = std::env::args()
        .try_fold(Vec::new(), |mut args, arg| {
            if let Some(path) = arg.strip_prefix('@') {
                let conf = read(path).context(format!("failed to read config file at `{path}`"))?;
                match toml::from_slice(&conf)
                    .context(format!("failed to parse config file at `{path}` as TOML"))?
                {
                    toml::Value::Table(kv) => kv.into_iter().try_for_each(|(k, v)| {
                        match v {
                            toml::Value::String(v) => args.push(format!("--{k}={v}")),
                            toml::Value::Integer(v) => args.push(format!("--{k}={v}")),
                            toml::Value::Float(v) => args.push(format!("--{k}={v}")),
                            toml::Value::Boolean(v) => {
                                if v {
                                    args.push(format!("--{k}"))
                                }
                            }
                            _ => bail!(
                                "unsupported value type for field `{k}` in config file at `{path}`"
                            ),
                        }
                        Ok(())
                    })?,
                    _ => bail!("invalid config file format in file at `{path}`"),
                }
            } else {
                args.push(arg);
            }
            Ok(args)
        })
        .map(Args::parse_from)
        .context("Failed to parse arguments")?;
    let state = match (args.key, args.crt, args.host) {
        (None, None, Some(host)) => State::generate(args.san, &host)?,
        (Some(key), Some(crt), _) => State::load(args.san, key, crt)?,
        _ => {
            eprintln!("Either:\n* Specify the public key `--crt` and private key `--key`, or\n* Specify the host `--host`.\n\nRun with `--help` for more information.");
            return Err(anyhow!("invalid configuration"));
        }
    };

    let addr = SocketAddr::from((args.addr, args.port));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app(state).into_make_service())
        .await?;

    Ok(())
}

fn app(state: State) -> Router {
    Router::new()
        .route("/", post(attest))
        .route("/", get(health))
        .layer(Extension(Arc::new(state)))
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn attest(
    TypedHeader(ct): TypedHeader<ContentType>,
    body: Bytes,
    Extension(state): Extension<Arc<State>>,
) -> Result<Vec<u8>, StatusCode> {
    const ISE: StatusCode = StatusCode::INTERNAL_SERVER_ERROR;

    // Decode the signing certificate and key.
    let issuer = Certificate::from_der(&state.crt).or(Err(ISE))?;
    let isskey = PrivateKeyInfo::from_der(&state.key).or(Err(ISE))?;

    // Ensure the correct mime type.
    let mime: Mime = PKCS10.parse().unwrap();
    if ct != ContentType::from(mime) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Decode and verify the certification request.
    let cr = CertReq::from_der(body.as_ref()).or(Err(StatusCode::BAD_REQUEST))?;
    let cri = cr.verify().or(Err(StatusCode::BAD_REQUEST))?;

    // Validate requested extensions.
    let mut attested = false;
    let mut extensions = Vec::new();
    for attr in cri.attributes.iter() {
        if attr.oid != ID_EXTENSION_REQ {
            return Err(StatusCode::BAD_REQUEST);
        }

        for any in attr.values.iter() {
            let ereq: ExtensionReq<'_> = any.decode_into().or(Err(StatusCode::BAD_REQUEST))?;
            for ext in Vec::from(ereq) {
                // If the issuer is self-signed, we are in debug mode.
                let iss = &issuer.tbs_certificate;
                let dbg = iss.issuer_unique_id == iss.subject_unique_id;
                let dbg = dbg && iss.issuer == iss.subject;

                // Validate the extension.
                let (copy, att) = match ext.extn_id {
                    Kvm::OID => (Kvm::default().verify(&cri, &ext, dbg), Kvm::ATT),
                    Sgx::OID => (Sgx::default().verify(&cri, &ext, dbg), Sgx::ATT),
                    Snp::OID => (Snp::default().verify(&cri, &ext, dbg), Snp::ATT),
                    _ => return Err(StatusCode::BAD_REQUEST), // unsupported extension
                };

                // Save results.
                attested |= att;
                if copy.or(Err(StatusCode::BAD_REQUEST))? {
                    extensions.push(ext);
                }
            }
        }
    }
    if !attested {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Get the current time and the expiration of the cert.
    let now = SystemTime::now();
    let end = now + Duration::from_secs(60 * 60 * 24 * 28);
    let validity = Validity {
        not_before: Time::try_from(now).or(Err(ISE))?,
        not_after: Time::try_from(end).or(Err(ISE))?,
    };

    // Create the basic subject alt name.
    let mut sans = vec![GeneralName::DnsName(
        Ia5String::new("foo.bar.hub.profian.com").or(Err(ISE))?,
    )];

    // Optionally, add the configured subject alt name.
    if let Some(name) = state.san.as_ref() {
        sans.push(GeneralName::DnsName(Ia5String::new(name).or(Err(ISE))?));
    }

    // Encode the subject alt name.
    let sans: Vec<u8> = SubjectAltName(sans).to_vec().or(Err(ISE))?;
    extensions.push(x509::ext::Extension {
        extn_id: ID_CE_SUBJECT_ALT_NAME,
        critical: false,
        extn_value: &sans,
    });

    // Add extended key usage.
    let eku = ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH, ID_KP_CLIENT_AUTH])
        .to_vec()
        .or(Err(ISE))?;
    extensions.push(x509::ext::Extension {
        extn_id: ID_CE_EXT_KEY_USAGE,
        critical: false,
        extn_value: &eku,
    });

    // Generate the instance id.
    let uuid = uuid::Uuid::new_v4();

    // Create the new certificate.
    let tbs = TbsCertificate {
        version: x509::Version::V3,
        serial_number: UIntBytes::new(uuid.as_bytes()).or(Err(ISE))?,
        signature: isskey.signs_with().or(Err(ISE))?,
        issuer: issuer.tbs_certificate.subject.clone(),
        validity,
        subject: RdnSequence(Vec::new()),
        subject_public_key_info: cri.public_key,
        issuer_unique_id: issuer.tbs_certificate.subject_unique_id,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    // Sign the certificate.
    let crt = tbs.sign(&isskey).or(Err(ISE))?;
    let crt = Certificate::from_der(&crt).or(Err(ISE))?;

    // Create and return the PkiPath.
    PkiPath::from(vec![issuer, crt]).to_vec().or(Err(ISE))
}

#[cfg(test)]
mod tests {
    mod attest {
        use crate::*;

        use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1};
        use const_oid::ObjectIdentifier;
        use der::{Any, Encodable};
        use x509::attr::Attribute;
        use x509::request::CertReqInfo;
        use x509::{ext::Extension, name::RdnSequence};

        use axum::response::Response;
        use http::{header::CONTENT_TYPE, Request};
        use hyper::Body;
        use tower::ServiceExt; // for `app.oneshot()`

        #[cfg(not(target_os = "wasi"))]
        fn certificates_state() -> State {
            State::load(None, "testdata/ca.key", "testdata/ca.crt").unwrap()
        }

        fn hostname_state() -> State {
            State::generate(None, "localhost").unwrap()
        }

        fn cr(curve: ObjectIdentifier, exts: Vec<Extension<'_>>) -> Vec<u8> {
            let pki = PrivateKeyInfo::generate(curve).unwrap();
            let pki = PrivateKeyInfo::from_der(pki.as_ref())
                .map_err(|e| {
                    eprintln!(
                        "{}:{} PrivateKeyInfo::from_der() error: {:?}",
                        file!(),
                        line!(),
                        e
                    )
                })
                .unwrap();
            let spki = pki.public_key().unwrap();

            let req = ExtensionReq::from(exts).to_vec().unwrap();
            let any = Any::from_der(&req).unwrap();
            let att = Attribute {
                oid: ID_EXTENSION_REQ,
                values: vec![any].try_into().unwrap(),
            };

            // Create a certification request information structure.
            let cri = CertReqInfo {
                version: x509::request::Version::V1,
                attributes: vec![att].try_into().unwrap(),
                subject: RdnSequence::default(),
                public_key: spki,
            };

            // Sign the request.
            cri.sign(&pki).unwrap()
        }

        async fn attest_response(state: State, response: Response) {
            let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
            let path = PkiPath::from_der(&body).unwrap();
            let issr = Certificate::from_der(&state.crt).unwrap();
            assert_eq!(2, path.0.len());
            assert_eq!(issr, path.0[0]);
            issr.tbs_certificate.verify_crt(&path.0[1]).unwrap();
        }

        #[test]
        fn reencode() {
            let encoded = cr(SECP_256_R_1, vec![]);

            for byte in &encoded {
                eprint!("{:02X}", byte);
            }
            eprintln!();

            let decoded = CertReq::from_der(&encoded).unwrap();
            let reencoded = decoded.to_vec().unwrap();
            assert_eq!(encoded, reencoded);
        }

        #[tokio::test]
        #[cfg(not(target_os = "wasi"))]
        async fn kvm_certs() {
            let ext = Extension {
                extn_id: Kvm::OID,
                critical: false,
                extn_value: &[],
            };

            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr(SECP_256_R_1, vec![ext])))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            attest_response(certificates_state(), response).await;
        }

        #[tokio::test]
        async fn kvm_hostname() {
            let ext = Extension {
                extn_id: Kvm::OID,
                critical: false,
                extn_value: &[],
            };

            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr(SECP_256_R_1, vec![ext])))
                .unwrap();

            let state = hostname_state();
            let response = app(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            attest_response(state, response).await;
        }

        #[tokio::test]
        #[cfg(not(target_os = "wasi"))]
        async fn sgx_certs() {
            for quote in [
                include_bytes!("ext/sgx/quote.unknown").as_slice(),
                include_bytes!("ext/sgx/quote.icelake").as_slice(),
            ] {
                let ext = Extension {
                    extn_id: Sgx::OID,
                    critical: false,
                    extn_value: quote,
                };

                let request = Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(CONTENT_TYPE, PKCS10)
                    .body(Body::from(cr(SECP_256_R_1, vec![ext])))
                    .unwrap();

                let response = app(certificates_state()).oneshot(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                attest_response(certificates_state(), response).await;
            }
        }

        #[tokio::test]
        async fn sgx_hostname() {
            for quote in [
                include_bytes!("ext/sgx/quote.unknown").as_slice(),
                include_bytes!("ext/sgx/quote.icelake").as_slice(),
            ] {
                let ext = Extension {
                    extn_id: Sgx::OID,
                    critical: false,
                    extn_value: quote,
                };

                let request = Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(CONTENT_TYPE, PKCS10)
                    .body(Body::from(cr(SECP_256_R_1, vec![ext])))
                    .unwrap();

                let state = hostname_state();
                let response = app(state.clone()).oneshot(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                attest_response(state, response).await;
            }
        }

        #[tokio::test]
        #[cfg(not(target_os = "wasi"))]
        async fn snp_certs() {
            let evidence = ext::snp::Evidence {
                vcek: Certificate::from_der(include_bytes!("ext/snp/milan.vcek")).unwrap(),
                report: include_bytes!("ext/snp/milan.rprt"),
            }
            .to_vec()
            .unwrap();

            let ext = Extension {
                extn_id: Snp::OID,
                critical: false,
                extn_value: &evidence,
            };

            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr(SECP_384_R_1, vec![ext])))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            attest_response(certificates_state(), response).await;
        }

        #[tokio::test]
        async fn snp_hostname() {
            let evidence = ext::snp::Evidence {
                vcek: Certificate::from_der(include_bytes!("ext/snp/milan.vcek")).unwrap(),
                report: include_bytes!("ext/snp/milan.rprt"),
            }
            .to_vec()
            .unwrap();

            let ext = Extension {
                extn_id: Snp::OID,
                critical: false,
                extn_value: &evidence,
            };

            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr(SECP_384_R_1, vec![ext])))
                .unwrap();

            let state = hostname_state();
            let response = app(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            attest_response(state, response).await;
        }

        #[tokio::test]
        #[cfg(not(target_os = "wasi"))]
        async fn err_no_attestation_certs() {
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr(SECP_256_R_1, vec![])))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn err_no_attestation_hostname() {
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr(SECP_256_R_1, vec![])))
                .unwrap();

            let response = app(hostname_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        #[cfg(not(target_os = "wasi"))]
        async fn err_no_content_type() {
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .body(Body::from(cr(SECP_256_R_1, vec![])))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        #[cfg(not(target_os = "wasi"))]
        async fn err_bad_content_type() {
            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, "text/plain")
                .uri("/")
                .body(Body::from(cr(SECP_256_R_1, vec![])))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        #[cfg(not(target_os = "wasi"))]
        async fn err_empty_body() {
            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, PKCS10)
                .uri("/")
                .body(Body::empty())
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        #[cfg(not(target_os = "wasi"))]
        async fn err_bad_body() {
            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, PKCS10)
                .uri("/")
                .body(Body::from(vec![0x01, 0x02, 0x03, 0x04]))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        #[cfg(not(target_os = "wasi"))]
        async fn err_bad_csr_sig() {
            let mut cr = cr(SECP_256_R_1, vec![]);
            let last = cr.last_mut().unwrap();
            *last = last.wrapping_add(1); // Modify the signature...

            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, PKCS10)
                .uri("/")
                .body(Body::from(cr))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
}
