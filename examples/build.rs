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
//! Outputs, in `OUT_DIR`:
//! * `device_chain.der` — IDevID ‖ LDevID ‖ leaf, concatenated DER.
//! * `leaf_key.bin` — the leaf's raw 48-byte P-384 private scalar.
//!
//! Cargo re-runs this script after `cargo clean` or when `certs/` or this file
//! change, so every clean build gets fresh device keys and serial numbers.
//!
//! DEMO MATERIAL ONLY.

use std::{env, error::Error, fs, path::PathBuf, str::FromStr, time::SystemTime};

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

/// A certificate authority that can sign the next certificate down.
struct Issuer {
    name: Name,
    key: SigningKey,
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

    let idevid_key = SigningKey::random(&mut OsRng);
    let (idevid, idevid_issuer) = issue(
        "CN=SPDMLIB IDEVID DEMO",
        idevid_key,
        &identity_signing,
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

    let ldevid_key = SigningKey::random(&mut OsRng);
    let (ldevid, ldevid_issuer) = issue(
        "CN=SPDMLIB LDEVID DEMO",
        ldevid_key,
        &idevid_issuer,
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

    let leaf_key = SigningKey::random(&mut OsRng);
    let leaf_scalar = leaf_key.to_bytes();
    let (leaf, _) = issue(
        "CN=SPDMLIB LEAF DEMO",
        leaf_key,
        &ldevid_issuer,
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
    Ok(())
}

/// Issues a certificate for `subject_key`, signed by `issuer`, and returns its
/// DER plus an [`Issuer`] that can sign the next level down.
fn issue(
    subject: &str,
    subject_key: SigningKey,
    issuer: &Issuer,
    mut extensions: Vec<Extension>,
) -> Result<(Vec<u8>, Issuer)> {
    let subject = Name::from_str(subject)?;
    let spki_der = subject_key.verifying_key().to_public_key_der()?;
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())?;
    let key_id = key_id(&spki);

    extensions.push(ext(
        false,
        &SubjectKeyIdentifier(OctetString::new(key_id.clone())?),
    )?);
    extensions.push(ext(
        false,
        &AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(issuer.key_id.clone())?),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        },
    )?);

    let sig_alg = AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA384,
        parameters: None,
    };
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
        issuer.name.to_der()?,
        validity.to_der()?,
        subject.to_der()?,
        spki.to_der()?,
        explicit(3, &extensions.to_der()?)?,
    ])?;

    let digest = Sha384::digest(&tbs);
    let signature: Signature = issuer.key.sign_prehash(&digest)?;
    let cert = sequence(&[
        tbs,
        sig_alg.to_der()?,
        BitString::from_bytes(signature.to_der().as_bytes())?.to_der()?,
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
        key: SigningKey::from_pkcs8_der(key_pkcs8_der)?,
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
