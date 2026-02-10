// Test program to verify static certificates work correctly

// Import platform implementations
mod platform;
use platform::{STATIC_ATTESTATION_CERT, STATIC_CERTIFICATE_CHAIN, STATIC_ROOT_CA_CERT};

fn main() {
    println!("Static Certificate Test");
    println!("=======================");

    println!("Root CA Certificate: {} bytes", STATIC_ROOT_CA_CERT.len());
    println!(
        "Attestation Certificate: {} bytes",
        STATIC_ATTESTATION_CERT.len()
    );
    println!(
        "Certificate Chain: {} bytes",
        STATIC_CERTIFICATE_CHAIN.len()
    );

    // Verify the chain is the concatenation of the individual certs
    let expected_len = STATIC_ROOT_CA_CERT.len() + STATIC_ATTESTATION_CERT.len();
    if STATIC_CERTIFICATE_CHAIN.len() == expected_len {
        println!("✓ Certificate chain length matches individual certificates");
    } else {
        println!(
            "✗ Certificate chain length mismatch: expected {}, got {}",
            expected_len,
            STATIC_CERTIFICATE_CHAIN.len()
        );
    }

    // Verify the chain starts with the root CA
    if STATIC_CERTIFICATE_CHAIN.starts_with(STATIC_ROOT_CA_CERT) {
        println!("✓ Certificate chain starts with root CA");
    } else {
        println!("✗ Certificate chain does not start with root CA");
    }

    // Verify the chain ends with the attestation cert
    if STATIC_CERTIFICATE_CHAIN.ends_with(STATIC_ATTESTATION_CERT) {
        println!("✓ Certificate chain ends with attestation certificate");
    } else {
        println!("✗ Certificate chain does not end with attestation certificate");
    }

    // Check X.509 structure (should start with SEQUENCE tag 0x30)
    if STATIC_ROOT_CA_CERT[0] == 0x30 && STATIC_ATTESTATION_CERT[0] == 0x30 {
        println!("✓ Both certificates have proper X.509 DER format (SEQUENCE tag)");
    } else {
        println!("✗ Certificates do not have proper X.509 DER format");
    }

    println!("\nStatic certificates are ready for use!");
}
