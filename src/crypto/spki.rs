// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(dead_code, unused_imports, unused_variables)]

use const_oid::ObjectIdentifier;
use der::{Any, Decodable, Sequence};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY as ECPK, ID_MGF_1, ID_RSASSA_PSS,
    ID_SHA_256 as SHA256, ID_SHA_384 as SHA384, ID_SHA_512 as SHA512, RSA_ENCRYPTION as RSA,
    SECP_256_R_1 as P256, SECP_384_R_1 as P384,
};

use anyhow::{anyhow, Result};

#[cfg(not(target_os = "wasi"))]
use ring::signature::VerificationAlgorithm as VerAlg;
#[cfg(not(target_os = "wasi"))]
use ring::signature::*;

#[cfg(target_os = "wasi")]
use wasi_crypto_guest::signatures::{Signature, SignatureKeyPair};

const ES256: (ObjectIdentifier, Option<Any<'static>>) = (ECDSA_WITH_SHA_256, None);
const ES384: (ObjectIdentifier, Option<Any<'static>>) = (ECDSA_WITH_SHA_384, None);

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct RsaSsaPssParams<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    hash_algorithm: AlgorithmIdentifier<'a>,

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
    mask_algorithm: AlgorithmIdentifier<'a>,

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
    salt_length: u32,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT")]
    trailer_field: u32,
}

pub trait SubjectPublicKeyInfoExt {
    /// Verifies a signature
    ///
    /// The signature on the specified body will be validated with the
    /// specified algorithm. Note that the signature is provided in the
    /// already encoded form as it would appear in an X.509 certificate
    /// or a PKCS#10 certification request. If you have a signature in
    /// another format, you will have to reformat it to the correct format.
    fn verify(&self, body: &[u8], algo: AlgorithmIdentifier<'_>, signature: &[u8]) -> Result<()>;
}

impl<'a> SubjectPublicKeyInfoExt for SubjectPublicKeyInfo<'a> {
    fn verify(&self, body: &[u8], algo: AlgorithmIdentifier<'_>, sign: &[u8]) -> Result<()> {
        #[cfg(not(target_os = "wasi"))]
        {
            let alg: &'static dyn VerAlg =
                match (self.algorithm.oids()?, (algo.oid, algo.parameters)) {
                    ((ECPK, Some(P256)), ES256) => &ECDSA_P256_SHA256_ASN1,
                    ((ECPK, Some(P384)), ES384) => &ECDSA_P384_SHA384_ASN1,
                    ((RSA, None), (ID_RSASSA_PSS, Some(p))) => {
                        // Decompose the RSA PSS parameters.
                        let RsaSsaPssParams {
                            hash_algorithm: hash,
                            mask_algorithm: mask,
                            salt_length: salt,
                            trailer_field: tfld,
                        } = p.decode_into()?;

                        // Validate the sanity of the mask algorithm.
                        let algo = match (mask.oid, mask.parameters) {
                            (ID_MGF_1, Some(p)) => {
                                let p = p.decode_into::<AlgorithmIdentifier<'_>>()?;
                                match (p.oids()?, salt, tfld) {
                                    ((SHA256, None), 32, 1) => Ok(SHA256),
                                    ((SHA384, None), 48, 1) => Ok(SHA384),
                                    ((SHA512, None), 64, 1) => Ok(SHA512),
                                    _ => Err(anyhow!("unsupported")),
                                }
                            }
                            _ => Err(anyhow!("unsupported")),
                        }?;

                        // Prepare for validation.
                        match (hash.oids()?, algo) {
                            ((SHA256, None), SHA256) => &RSA_PSS_2048_8192_SHA256,
                            ((SHA384, None), SHA384) => &RSA_PSS_2048_8192_SHA384,
                            ((SHA512, None), SHA512) => &RSA_PSS_2048_8192_SHA512,
                            _ => return Err(anyhow!("unsupported")),
                        }
                    }
                    _ => return Err(anyhow!("unsupported")),
                };

            let upk = UnparsedPublicKey::new(alg, self.subject_public_key);
            Ok(upk.verify(body, sign)?)
        }

        #[cfg(target_os = "wasi")]
        {
            let (pk, sig) = match self.algorithm.oids()? {
                (ECPK, Some(P256)) => (
                    SignatureKeyPair::from_pkcs8("ECDSA_P256_SHA256", &self.subject_public_key)
                        .unwrap()
                        .publickey()
                        .unwrap(),
                    Signature::from_raw("ECDSA_P256_SHA256", sign).unwrap(),
                ),
                (ECPK, Some(P384)) => (
                    SignatureKeyPair::from_pkcs8("ECDSA_P384_SHA384", &self.subject_public_key)
                        .unwrap()
                        .publickey()
                        .unwrap(),
                    Signature::from_raw("ECDSA_P384_SHA384", sign).unwrap(),
                ),
                _ => return Err(anyhow!("unsupported")),
            };

            Ok(pk.signature_verify(body, &sig).unwrap())
        }
    }
}
