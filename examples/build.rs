// Licensed under the Apache-2.0 license

//! Generates the PoC Responder's per-device certificate chain.
//!
//! ```text
//! SPDMLIB DEMO CA                         certs/ (static, gen-demo-ca.sh)
//! └─ SPDMLIB SIGNING DEMO                 certs/ (static)
//!    └─ SPDMLIB IDENTITY SIGNING DEMO     certs/ (static, key kept)
//!       └─ SPDMLIB IDEVID DEMO            generated: Device Certificate CA
//!          └─ SPDMLIB LDEVID DEMO         generated: alias intermediate CA
//!             └─ SPDMLIB LEAF DEMO        generated: alias leaf, signs SPDM responses
//! ```
//!
//! This is the DSP0274 AliasCert model, shaped like a RoT's identity chain:
//! the IDevID is the immutable hardware identity (SPDM hardware-identity OID plus
//! the DMTF device-info otherName), and the LDevID and leaf are mutable alias
//! certificates below it (SPDM mutable-certificate OID). All keys are P-384 and
//! all signatures ECDSA-with-SHA384.
//!
//! A second, post-quantum chain is generated alongside it for SPDM 1.4: a
//! self-signed ML-DSA-87 root, then IDEVID → LDEVID → LEAF with the same shape
//! and extensions as above. Every key is ML-DSA-87 and every signature is pure
//! ML-DSA-87 with an empty context (RFC 9881). Unlike the classical hierarchy
//! the root is generated here too, so it changes on every clean build.
//!
//! Outputs, in `OUT_DIR`:
//! * `device_chain.der` — IDevID ‖ LDevID ‖ leaf, concatenated DER.
//! * `leaf_key.bin` — the leaf's raw 48-byte P-384 private scalar.
//! * `pq_chain.der` — ML-DSA-87 root ‖ IDevID ‖ LDevID ‖ leaf.
//! * `pq_leaf_seed.bin` — the ML-DSA-87 leaf's 32-byte key seed.
//!
//! Cargo re-runs this script after `cargo clean` or when `certs/` or this file
//! change, so every clean build gets fresh device keys and serial numbers.
//!
//! DEMO MATERIAL ONLY.

use std::{env, error::Error, fs, path::PathBuf, str::FromStr, time::SystemTime};

use ml_dsa::{MlDsa87, SigningKey as PqKey, B32};
use p384::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use p384::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha384};
use x509_cert::der::asn1::Utf8StringRef;
use x509_cert::der::asn1::{Any, BitString, GeneralizedTime, ObjectIdentifier, OctetString};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::der::{DateTime, Decode, Encode, Tag, TagNumber};
use x509_cert::ext::pkix::name::{GeneralName, OtherName};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::Certificate;

type Result<T> = core::result::Result<T, Box<dyn Error>>;

/// ecdsa-with-SHA384.
const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
/// DMTF device-info otherName: "manufacturer:product:serial" (DSP0274 §10.9.1).
const DMTF_DEVICE_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412.274.1");
/// SPDM extension container, holding the OIDs below (DSP0274 §10.9.2.2).
const SPDM_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412.274.6");
const SPDM_HARDWARE_IDENTITY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412.274.2");
const SPDM_MUTABLE_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412.274.5");
/// SPDM Responder Authentication EKU (DSP0274 §10.9.2.1).
const SPDM_RESPONDER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.412.274.3");

/// id-ml-dsa-87 (RFC 9881); used as both key and signature algorithm, no parameters.
const ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

/// A key that can be certified and can sign certificates.
enum Key {
    Ec(SigningKey),
    Pq(PqKey<MlDsa87>),
}

impl Key {
    fn pq_random() -> (Self, [u8; 32]) {
        let seed = random_bytes::<32>();
        (Key::Pq(PqKey::<MlDsa87>::from_seed(&B32::from(seed))), seed)
    }

    fn spki(&self) -> Result<SubjectPublicKeyInfoOwned> {
        Ok(match self {
            Key::Ec(k) => SubjectPublicKeyInfoOwned::from_der(
                k.verifying_key().to_public_key_der()?.as_bytes(),
            )?,
            Key::Pq(k) => SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: ML_DSA_87,
                    parameters: None,
                },
                subject_public_key: BitString::from_bytes(
                    &k.expanded_key().verifying_key().encode(),
                )?,
            },
        })
    }

    fn sig_alg(&self) -> AlgorithmIdentifierOwned {
        let oid = match self {
            Key::Ec(_) => ECDSA_WITH_SHA384,
            Key::Pq(_) => ML_DSA_87,
        };
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    /// Signature BIT STRING contents over `tbs`.
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>> {
        Ok(match self {
            Key::Ec(k) => {
                let sig: Signature = k.sign_prehash(&Sha384::digest(tbs))?;
                sig.to_der().as_bytes().to_vec()
            }
            Key::Pq(k) => k
                .expanded_key()
                .sign_deterministic(tbs, &[])
                .map_err(|e| format!("ML-DSA sign: {e:?}"))?
                .encode()
                .to_vec(),
        })
    }
}

/// A certificate authority that can sign the next certificate down.
struct Issuer {
    name: Name,
    key: Key,
    key_id: Vec<u8>,
}

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=certs");

    let certs = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("certs");
    let out = PathBuf::from(env::var("OUT_DIR")?);

    let identity_signing = load_issuer(
        &fs::read(certs.join("identity-signing-demo.cert.der"))?,
        &fs::read(certs.join("identity-signing-demo.key.der"))?,
    )?;

    let serial = hex(&random_bytes::<8>());
    let device_info = format!("OPENPROT:SPDMLIB DEMO:{serial}");

    let idevid_key = Key::Ec(SigningKey::random(&mut OsRng));
    let (idevid, idevid_issuer) = issue(
        "CN=SPDMLIB IDEVID DEMO",
        idevid_key,
        Some(&identity_signing),
        vec![
            ext(
                true,
                &BasicConstraints {
                    ca: true,
                    path_len_constraint: None,
                },
            )?,
            ext(
                true,
                &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::DigitalSignature),
            )?,
            ext(false, &device_info_san(&device_info)?)?,
            spdm_extension(SPDM_HARDWARE_IDENTITY)?,
        ],
    )?;

    let ldevid_key = Key::Ec(SigningKey::random(&mut OsRng));
    let (ldevid, ldevid_issuer) = issue(
        "CN=SPDMLIB LDEVID DEMO",
        ldevid_key,
        Some(&idevid_issuer),
        vec![
            ext(
                true,
                &BasicConstraints {
                    ca: true,
                    path_len_constraint: None,
                },
            )?,
            ext(true, &KeyUsage(KeyUsages::KeyCertSign.into()))?,
            spdm_extension(SPDM_MUTABLE_CERTIFICATE)?,
        ],
    )?;

    let leaf_key = Key::Ec(SigningKey::random(&mut OsRng));
    let Key::Ec(ec_leaf) = &leaf_key else {
        unreachable!()
    };
    let leaf_scalar = ec_leaf.to_bytes();
    let (leaf, _) = issue(
        "CN=SPDMLIB LEAF DEMO",
        leaf_key,
        Some(&ldevid_issuer),
        vec![
            ext(
                true,
                &BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                },
            )?,
            ext(true, &KeyUsage(KeyUsages::DigitalSignature.into()))?,
            ext(false, &ExtendedKeyUsage(vec![SPDM_RESPONDER_AUTH]))?,
            spdm_extension(SPDM_MUTABLE_CERTIFICATE)?,
        ],
    )?;

    let chain = [idevid, ldevid, leaf].concat();
    fs::write(out.join("device_chain.der"), chain)?;
    fs::write(out.join("leaf_key.bin"), &leaf_scalar[..])?;

    // ---- ML-DSA-87 chain: root → IDevID → LDevID → leaf ----
    let ca_ext = |usage: x509_cert::der::flagset::FlagSet<KeyUsages>,
                  extra: Vec<Extension>|
     -> Result<Vec<Extension>> {
        let mut v = vec![
            ext(
                true,
                &BasicConstraints {
                    ca: true,
                    path_len_constraint: None,
                },
            )?,
            ext(true, &KeyUsage(usage))?,
        ];
        v.extend(extra);
        Ok(v)
    };
    let (root_key, _) = Key::pq_random();
    let (pq_root, pq_root_iss) = issue(
        "CN=SPDMLIB PQC ROOT DEMO",
        root_key,
        None,
        ca_ext(KeyUsages::KeyCertSign.into(), vec![])?,
    )?;
    let (pq_idevid_key, _) = Key::pq_random();
    let (pq_idevid, pq_idevid_iss) = issue(
        "CN=SPDMLIB PQC IDEVID DEMO",
        pq_idevid_key,
        Some(&pq_root_iss),
        ca_ext(
            KeyUsages::KeyCertSign | KeyUsages::DigitalSignature,
            vec![
                ext(false, &device_info_san(&device_info)?)?,
                spdm_extension(SPDM_HARDWARE_IDENTITY)?,
            ],
        )?,
    )?;
    let (pq_ldevid_key, _) = Key::pq_random();
    let (pq_ldevid, pq_ldevid_iss) = issue(
        "CN=SPDMLIB PQC LDEVID DEMO",
        pq_ldevid_key,
        Some(&pq_idevid_iss),
        ca_ext(
            KeyUsages::KeyCertSign.into(),
            vec![spdm_extension(SPDM_MUTABLE_CERTIFICATE)?],
        )?,
    )?;
    let (pq_leaf_key, pq_leaf_seed) = Key::pq_random();
    let (pq_leaf, _) = issue(
        "CN=SPDMLIB PQC LEAF DEMO",
        pq_leaf_key,
        Some(&pq_ldevid_iss),
        vec![
            ext(
                true,
                &BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                },
            )?,
            ext(true, &KeyUsage(KeyUsages::DigitalSignature.into()))?,
            ext(false, &ExtendedKeyUsage(vec![SPDM_RESPONDER_AUTH]))?,
            spdm_extension(SPDM_MUTABLE_CERTIFICATE)?,
        ],
    )?;
    fs::write(
        out.join("pq_chain.der"),
        [pq_root, pq_idevid, pq_ldevid, pq_leaf].concat(),
    )?;
    fs::write(out.join("pq_leaf_seed.bin"), pq_leaf_seed)?;
    Ok(())
}

/// Issues a certificate for `subject_key`, signed by `issuer`, and returns its
/// DER plus an [`Issuer`] that can sign the next level down.
fn issue(
    subject: &str,
    subject_key: Key,
    issuer: Option<&Issuer>,
    mut extensions: Vec<Extension>,
) -> Result<(Vec<u8>, Issuer)> {
    let subject = Name::from_str(subject)?;
    let spki = subject_key.spki()?;
    let key_id = key_id(&spki);
    // `None` issuer: self-signed root.
    let (issuer_name, signer, issuer_key_id) = match issuer {
        Some(i) => (&i.name, &i.key, &i.key_id),
        None => (&subject, &subject_key, &key_id),
    };

    extensions.push(ext(
        false,
        &SubjectKeyIdentifier(OctetString::new(key_id.clone())?),
    )?);
    extensions.push(ext(
        false,
        &AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(issuer_key_id.clone())?),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        },
    )?);

    let sig_alg = signer.sig_alg();
    // Slot 0 certificates should not expire (DSP0274 1.4 §10.9.1).
    let not_after = GeneralizedTime::from_date_time(DateTime::new(9999, 12, 31, 23, 59, 59)?);
    let validity = Validity::<x509_cert::certificate::Rfc5280>::new(
        Time::try_from(SystemTime::now())?,
        Time::GeneralTime(not_after),
    );

    // TbsCertificate's fields are crate-private, so encode it field by field.
    let tbs = sequence(&[
        explicit(0, &2u8.to_der()?)?, // version v3
        SerialNumber::<x509_cert::certificate::Rfc5280>::new(&serial_number())?.to_der()?,
        sig_alg.to_der()?,
        issuer_name.to_der()?,
        validity.to_der()?,
        subject.to_der()?,
        spki.to_der()?,
        explicit(3, &extensions.to_der()?)?,
    ])?;

    let signature = signer.sign(&tbs)?;
    let cert = sequence(&[
        tbs,
        sig_alg.to_der()?,
        BitString::from_bytes(&signature)?.to_der()?,
    ])?;

    // Round-trip through the parser so a malformed certificate fails the build.
    Certificate::from_der(&cert)?;

    Ok((
        cert,
        Issuer {
            name: subject,
            key: subject_key,
            key_id,
        },
    ))
}

fn load_issuer(cert_der: &[u8], key_pkcs8_der: &[u8]) -> Result<Issuer> {
    let cert = Certificate::from_der(cert_der)?;
    let tbs = cert.tbs_certificate();
    let ski = tbs
        .extensions()
        .into_iter()
        .flatten()
        .find(|e| e.extn_id == SubjectKeyIdentifier::OID)
        .ok_or("identity-signing certificate has no subjectKeyIdentifier")?;
    let ski = SubjectKeyIdentifier::from_der(ski.extn_value.as_bytes())?;
    Ok(Issuer {
        name: tbs.subject().clone(),
        key: Key::Ec(SigningKey::from_pkcs8_der(key_pkcs8_der)?),
        key_id: ski.0.as_bytes().to_vec(),
    })
}

fn ext<T: Encode + AssociatedOid>(critical: bool, value: &T) -> Result<Extension> {
    Ok(Extension {
        extn_id: T::OID,
        critical,
        extn_value: OctetString::new(value.to_der()?)?,
    })
}

/// Non-critical SPDM extension holding a single OID with no definition:
/// `SEQUENCE OF SEQUENCE { spdmOID }`.
fn spdm_extension(oid: ObjectIdentifier) -> Result<Extension> {
    Ok(Extension {
        extn_id: SPDM_EXTENSION,
        critical: false,
        extn_value: OctetString::new(vec![vec![oid]].to_der()?)?,
    })
}

fn device_info_san(device_info: &str) -> Result<SubjectAltName> {
    Ok(SubjectAltName(vec![GeneralName::OtherName(OtherName {
        type_id: DMTF_DEVICE_INFO,
        value: Any::encode_from(&Utf8StringRef::new(device_info)?)?,
    })]))
}

/// RFC 7093 key identifier: leftmost 160 bits of SHA-384 over the public key bits.
fn key_id(spki: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
    Sha384::digest(spki.subject_public_key.raw_bytes())[..20].to_vec()
}

fn sequence(parts: &[Vec<u8>]) -> Result<Vec<u8>> {
    Ok(Any::new(Tag::Sequence, parts.concat())?.to_der()?)
}

fn explicit(number: u32, inner_der: &[u8]) -> Result<Vec<u8>> {
    let tag = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(number),
    };
    Ok(Any::new(tag, inner_der.to_vec())?.to_der()?)
}

/// 120-bit positive serial number.
fn serial_number() -> [u8; 15] {
    let mut serial = random_bytes::<15>();
    serial[0] = (serial[0] & 0x7F) | 0x40;
    serial
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}
