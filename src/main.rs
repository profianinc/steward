extern crate core;

mod crypto;

use crypto::*;
use x509::request::CertReq;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::{Extension, TypedHeader};
use axum::headers::ContentType;
use axum::routing::post;
use axum::{AddExtensionLayer, Router};
use der::asn1::UIntBytes;
use der::{Encodable, Sequence};
use hyper::StatusCode;
use mime::Mime;

use der::Decodable;
use pkcs8::PrivateKeyInfo;
use x509::time::{Time, Validity};
use x509::{Certificate, TbsCertificate};

use clap::Parser;
use zeroize::Zeroizing;

const PKCS10: &str = "application/pkcs10";

#[derive(Clone, Debug, Parser)]
struct Args {
    #[clap(short, long)]
    key: PathBuf,

    #[clap(short, long)]
    crt: PathBuf,
}

impl Args {
    fn load(self) -> std::io::Result<State> {
        Ok(State {
            key: std::fs::read(self.key)?.into(),
            crt: std::fs::read(self.crt)?,
            ord: AtomicUsize::default(),
        })
    }
}

#[derive(Debug)]
struct State {
    key: Zeroizing<Vec<u8>>,
    crt: Vec<u8>,
    ord: AtomicUsize,
}

// ECDSA-Sig-Value ::= SEQUENCE {
//    r INTEGER,
//    s INTEGER
// }
#[derive(Clone, Debug, Sequence)]
struct EcdsaSig<'a> {
    r: UIntBytes<'a>,
    s: UIntBytes<'a>,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SnpReportData {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub sig_algo: u32,
    pub plat_version: u64,
    pub plat_info: u64,
    pub author_key_en: u32,
    rsvd1: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub report_id: [u8; 32],
    pub report_id_ma: [u8; 32],
    pub reported_tcb: u64,
    rsvd2: [u8; 24],
    pub chip_id: [u8; 64],
    rsvd3: [u8; 192],
    pub signature: [u8; 512],
}

const SNP_SIGNATURE_OFFSET:usize = 0x2A0;
const SNP_BIGNUM_SIZE:usize = 0x48;

impl SnpReportData {
    fn get_message(&self) -> Vec<u8> {
        //let bytes = unsafe { any_as_u8_slice(&self) };
        let bytes = unsafe { std::mem::transmute::<&SnpReportData, &[u8;0x4A0]>(self) };
        println!("SnpReportSize: {}", bytes.len());
        bytes[..SNP_SIGNATURE_OFFSET].to_vec()
    }

    fn get_signature(&self) -> Vec<u8> {
        let bytes = unsafe { std::mem::transmute::<&SnpReportData, &[u8;0x4A0]>(self) };
        let mut r = bytes[SNP_SIGNATURE_OFFSET..SNP_SIGNATURE_OFFSET+SNP_BIGNUM_SIZE].to_vec();
        let mut s = bytes[SNP_SIGNATURE_OFFSET+SNP_BIGNUM_SIZE..SNP_SIGNATURE_OFFSET+2*SNP_BIGNUM_SIZE].to_vec();
        r.reverse();
        s.reverse();

        let ecdsa = EcdsaSig {
            r: UIntBytes::new(&r).unwrap(),
            s: UIntBytes::new(&s).unwrap(),
        };

        ecdsa.to_vec().unwrap()
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = Args::parse().load().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app(state).into_make_service())
        .await
        .unwrap();
}

fn app(state: State) -> Router {
    Router::new()
        .route("/attest", post(attest))
        .layer(AddExtensionLayer::new(Arc::new(state)))
}

async fn attest(
    TypedHeader(ct): TypedHeader<ContentType>,
    body: Bytes,
    Extension(state): Extension<Arc<State>>,
) -> Result<Vec<u8>, StatusCode> {
    // Ensure the correct mime type.
    let mime: Mime = PKCS10.parse().unwrap();
    if ct != ContentType::from(mime) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Decode and verify the certification request.
    let cr = CertReq::from_der(body.as_ref()).or(Err(StatusCode::BAD_REQUEST))?;
    let cr = cr.verify().or(Err(StatusCode::BAD_REQUEST))?;

    // TODO: validate attestation
    // TODO: validate other CSR fields

    // Get the current time and the expiration of the cert.
    let now = SystemTime::now();
    let end = now + Duration::from_secs(60 * 60 * 24);
    let validity = Validity {
        not_before: Time::try_from(now).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?,
        not_after: Time::try_from(end).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?,
    };

    // Get the next serial number.
    let serial = state.ord.fetch_add(1, Ordering::SeqCst).to_be_bytes();
    let serial = UIntBytes::new(&serial).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // Decode the signing certificate and key.
    let issuer = Certificate::from_der(&state.crt).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    let isskey = PrivateKeyInfo::from_der(&state.key).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // Create the new certificate.
    let tbs = TbsCertificate {
        version: x509::Version::V3,
        serial_number: serial,
        signature: isskey
            .signs_with()
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?,
        issuer: issuer.tbs_certificate.subject.clone(),
        validity,
        subject: issuer.tbs_certificate.subject.clone(), // FIXME
        subject_public_key_info: cr.public_key,
        issuer_unique_id: issuer.tbs_certificate.subject_unique_id,
        subject_unique_id: None,
        extensions: None,
    };

    // Sign the certificate.
    Ok(tbs
        .sign(&isskey)
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?)
}

#[cfg(test)]
mod tests {
    mod attest {
        use crate::crypto::oids::ECDSA_SHA384;
        use crate::*;

        use der::asn1::{SetOfVec, Utf8String};
        use der::{Encodable, asn1::UIntBytes};

        use x509::attr::AttributeTypeAndValue;
        use x509::name::RelativeDistinguishedName;
        use x509::request::CertReqInfo;

        use http::{header::CONTENT_TYPE, Request};
        use hyper::Body;
        use tower::ServiceExt; // for `app.oneshot()`

        const CRT: &[u8] = include_bytes!("../certs/test/crt.der");
        const KEY: &[u8] = include_bytes!("../certs/test/key.der");

        fn state() -> State {
            State {
                key: KEY.to_owned().into(),
                crt: CRT.into(),
                ord: Default::default(),
            }
        }

        fn cr() -> Vec<u8> {
            let pki = PrivateKeyInfo::generate(oids::NISTP256).unwrap();
            let pki = PrivateKeyInfo::from_der(pki.as_ref()).unwrap();
            let spki = pki.public_key().unwrap();

            // Create a relative distinguished name.
            let mut rdn = RelativeDistinguishedName::new();
            rdn.add(AttributeTypeAndValue {
                oid: x509::ext::pkix::oids::AT_COMMON_NAME,
                value: Utf8String::new("foo").unwrap().into(),
            })
            .unwrap();

            // Create a certification request information structure.
            let cri = CertReqInfo {
                version: x509::request::Version::V1,
                attributes: SetOfVec::new(), // Extension requests go here.
                subject: [rdn].into(),
                public_key: spki,
            };

            // Sign the request.
            cri.sign(&pki).unwrap()
        }

        #[test]
        fn test_milan_validation() {
            use std::fs;
            let mut test_file = fs::read("tests/test1_le.bin").unwrap();
            assert_eq!(test_file.len(), 0x4A0, "attestation blob size");

            let (test_message, test_signature) = test_file.split_at_mut(0x2A0);
            println!("Message to hash: {:02?}", test_message);
            assert_eq!(test_signature.len(), 0x0200, "attestation signature size");

            let (r, rest) = test_signature.split_at_mut(0x48);
            let (s, _) = rest.split_at_mut(0x48);
            r.reverse();
            s.reverse();

            let ecdsa = EcdsaSig {
                r: UIntBytes::new(&r).unwrap(),
                s: UIntBytes::new(&s).unwrap(),
            };

            let der = ecdsa.to_vec().unwrap();
            println!("Der bytes: {:?}", der);

            println!("R={:?}", r);
            println!("S={:?}", s);

            assert_eq!(r.len(), s.len(), "R & S bytes are equal");
            assert_eq!(r.len(), 0x48, "R & S are 0x48 bytes");

            const MILAN_VCEK: &str = include_str!("../certs/amd/milan_vcek.pem");
            let veck = PkiPath::parse_pem(MILAN_VCEK).unwrap();
            let vcek_path = PkiPath::from_ders(&veck).unwrap();
            assert_eq!(vcek_path.len(), 1, "The SNP cert is just one cert");
            let the_cert = vcek_path.first().unwrap();

            match the_cert.tbs_certificate.verify_raw(
                test_message,
                pkcs8::AlgorithmIdentifier {
                    oid: ECDSA_SHA384,
                    parameters: None,
                },
                &der,
            ) {
                Ok(_) => {
                    assert!(true, "Message passed");
                }
                Err(e) => {
                    assert!(false, "Message invalid {}", e);
                }
            }
        }

        #[test]
        fn test_milan_validation_struct() {
            use std::fs;
            let test_file = fs::read("tests/test1_le.bin").unwrap();
            assert_eq!(test_file.len(), 0x4A0, "attestation blob size");
            let mut test_file_bytes = [0u8; 0x4A0];
            for (i, v) in test_file.iter().enumerate() { test_file_bytes[i] = *v; }

            assert_eq!(test_file.len(), core::mem::size_of::<SnpReportData>());
            //let report_data = test_file.as_ptr() as *const SnpReportData;
            //let the_report = unsafe { report_data.read_unaligned() };

            let the_report:SnpReportData = unsafe { std::mem::transmute::<[u8;0x4A0],SnpReportData>(test_file_bytes) };
            //let (head, body, _tail) = unsafe { test_file.align_to::<SnpReportData>() };
            //assert!(head.is_empty(), "Data was not aligned");
            //let the_report = body[0];

            println!("{:?}", the_report);
            const MILAN_VCEK: &str = include_str!("../certs/amd/milan_vcek.pem");
            let veck = PkiPath::parse_pem(MILAN_VCEK).unwrap();
            let vcek_path = PkiPath::from_ders(&veck).unwrap();
            assert_eq!(vcek_path.len(), 1, "The SNP cert is just one cert");
            let the_cert = vcek_path.first().unwrap();

            match the_cert.tbs_certificate.verify_raw(
                the_report.get_message().as_slice(),
                pkcs8::AlgorithmIdentifier {
                    oid: ECDSA_SHA384,
                    parameters: None,
                },
                the_report.get_signature().as_slice(),
            ) {
                Ok(_) => {
                    assert!(true, "Message passed");
                }
                Err(e) => {
                    assert!(false, "Message invalid {}", e);
                }
            }
        }

        #[test]
        fn reencode() {
            let encoded = cr();

            for byte in &encoded {
                eprint!("{:02X}", byte);
            }
            eprintln!();

            let decoded = CertReq::from_der(&encoded).unwrap();
            let reencoded = decoded.to_vec().unwrap();
            assert_eq!(encoded, reencoded);
        }

        #[tokio::test]
        async fn ok() {
            let request = Request::builder()
                .method("POST")
                .uri("/attest")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr()))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = hyper::body::to_bytes(response.into_body()).await.unwrap();

            let sub = Certificate::from_der(&body).unwrap();
            let iss = Certificate::from_der(CRT).unwrap();
            iss.tbs_certificate.verify_crt(&sub).unwrap();
        }

        #[tokio::test]
        async fn err_no_content_type() {
            let request = Request::builder()
                .method("POST")
                .uri("/attest")
                .body(Body::from(cr()))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn err_bad_content_type() {
            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, "text/plain")
                .uri("/attest")
                .body(Body::from(cr()))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn err_empty_body() {
            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, PKCS10)
                .uri("/attest")
                .body(Body::empty())
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn err_bad_body() {
            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, PKCS10)
                .uri("/attest")
                .body(Body::from(vec![0x01, 0x02, 0x03, 0x04]))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn err_bad_csr_sig() {
            let mut cr = cr();
            *cr.last_mut().unwrap() = 0; // Modify the signature...

            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, PKCS10)
                .uri("/attest")
                .body(Body::from(cr))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
}
