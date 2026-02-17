// Licensed under the Apache-2.0 license

//! SPDM Example Responder utilizing the requester library.

use std::env;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::TcpStream;
use std::process;

use der::Decode;
use spdm_lib::codec::MessageBuf;
use spdm_lib::commands::certificate::request::generate_get_certificate;
use spdm_lib::context::SpdmContext;
use spdm_lib::error::SpdmError;
use spdm_lib::protocol::algorithms::{
    AeadCipherSuite, AlgorithmPriorityTable, BaseAsymAlgo, BaseHashAlgo, DeviceAlgorithms,
    DheNamedGroup, KeySchedule, LocalDeviceAlgorithms, MeasurementHashAlgo,
    MeasurementSpecification, MelSpecification, OtherParamSupport, ReqBaseAsymAlg,
};
use spdm_lib::protocol::{version, BaseHashAlgoType};
use spdm_lib::protocol::{CapabilityFlags, DeviceCapabilities};

// Import platform implementations - no duplicates!
mod platform;
use platform::{DemoCertStore, DemoEvidence, Sha384Hash, SpdmSocketTransport, SystemRng};

use spdm_lib::commands::algorithms::{
    request::generate_negotiate_algorithms_request, AlgStructure, AlgType, ExtendedAlgo, RegistryId,
};
use spdm_lib::commands::capabilities::request::generate_capabilities_request_local;
use spdm_lib::commands::digests::request::generate_digest_request;
use spdm_lib::commands::version::{request::generate_get_version, VersionReqPayload};

use crate::platform::cert_store::ExamplePeerCertStore;

use x509_cert::Certificate;

/// Responder configuration
#[derive(Debug, Clone)]
struct RequesterConfig {
    port: u16,
    cert_path: String,
    key_path: String,
    measurements_path: Option<String>,
    verbose: bool,
}

impl Default for RequesterConfig {
    fn default() -> Self {
        Self {
            port: 2323,
            cert_path: "device_cert.pem".to_string(),
            key_path: "device_key.pem".to_string(),
            measurements_path: Some("measurements.json".to_string()),
            verbose: false,
        }
    }
}

/// Create SPDM device capabilities
fn create_device_capabilities() -> DeviceCapabilities {
    let mut flags_value = 0u32;
    flags_value |= 1 << 1; // cert_cap
    flags_value |= 1 << 2; // chal_cap
    flags_value |= 2 << 3; // meas_cap (with signature)
    flags_value |= 1 << 5; // meas_fresh_cap
    flags_value |= 1 << 17; // chunk_cap

    let flags = CapabilityFlags::new(flags_value);

    DeviceCapabilities {
        ct_exponent: 0,
        flags,
        data_transfer_size: 1024,
        max_spdm_msg_size: 4096,
        include_supported_algorithms: false,
    }
}

/// Create local device algorithms
///
/// Default values are:
/// - Measurement Specification: DMTF (1)
/// - Measurement Hash Algorithm: TPM_ALG_SHA_384 (1)
/// - Base Asymmetric Algorithm: TPM_ALG_ECDSA_ECC_NIST_P384
/// - Base Hash Algorithm: TPM_ALG_SHA_384 (1)
/// - MEL Specification: 0
fn create_local_algorithms<'a>() -> LocalDeviceAlgorithms<'a> {
    // Configure supported algorithms with proper bitfield construction
    let mut measurement_spec = MeasurementSpecification::default();
    measurement_spec.set_dmtf_measurement_spec(1);

    let mut measurement_hash_algo = MeasurementHashAlgo::default();
    measurement_hash_algo.set_tpm_alg_sha_384(1);

    let mut base_asym_algo = BaseAsymAlgo::default();
    base_asym_algo.set_tpm_alg_ecdsa_ecc_nist_p384(1);

    let mut base_hash_algo = BaseHashAlgo::default();
    base_hash_algo.set_tpm_alg_sha_384(1);

    let device_algorithms = DeviceAlgorithms {
        measurement_spec,
        other_param_support: OtherParamSupport::default(),
        measurement_hash_algo,
        base_asym_algo,
        base_hash_algo,
        mel_specification: MelSpecification(1),
        dhe_group: DheNamedGroup(1),           // FFDHE2048
        aead_cipher_suite: AeadCipherSuite(1), // AES_128_GCM
        req_base_asym_algo: ReqBaseAsymAlg(1),
        key_schedule: KeySchedule::default(),
    };

    // Keep this empty for now, since we need to wait for responders answer.
    let algorithm_priority_table = AlgorithmPriorityTable::default();

    LocalDeviceAlgorithms {
        device_algorithms,
        algorithm_priority_table,
    }
}

// Perform a VCS flow (Version, Capabilities, Algorithms)
// using the real SPDM library processing with platform implementations.
fn full_flow(stream: TcpStream, config: &RequesterConfig) -> IoResult<()> {
    let mut transport = SpdmSocketTransport::new(
        stream,
        platform::socket_transport::SocketTransportType::None,
    );
    const EID: u8 = 0;

    // Create platform implementations - all from platform module!
    let mut hash = Sha384Hash::new();
    let mut m1_hash = Sha384Hash::new();
    let mut l1_hash = Sha384Hash::new();
    let mut rng = SystemRng::new();
    let mut cert_store = DemoCertStore::new();
    let evidence = DemoEvidence::new();

    // Create SPDM context
    let supported_versions = [
        version::SpdmVersion::V13,
        version::SpdmVersion::V12,
        version::SpdmVersion::V11,
    ];
    let capabilities = create_device_capabilities();
    let algorithms = create_local_algorithms();

    let mut peer_cert_store = ExamplePeerCertStore::default();

    if config.verbose {
        println!("Client connected - initializing SPDM context");
    }

    // TODO: The SpdmContext has to be adjusted (best in a generic way) to be requester compatible
    // For now, keep the context the same and ignore the internal state tracking.
    // Imho the the Responder is implemented wrong, since it tracks it's own state instead of the
    // other parties state.
    // So for now, we will re-use the state tracking and keep it in sync with the other parties state.
    let mut spdm_context = match SpdmContext::new(
        &supported_versions,
        &mut transport,
        capabilities,
        algorithms,
        &mut cert_store,
        Some(&mut peer_cert_store),
        &mut hash,
        &mut m1_hash,
        &mut l1_hash,
        &mut rng,
        &evidence,
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("Failed to create SPDM context: {:?}", e);
            return Err(Error::new(ErrorKind::Other, "SPDM context creation failed"));
        }
    };

    if config.verbose {
        println!("SPDM context created successfully");
    }

    // Before we can start, we need to do the inofficial handshake for SOCKET_TRANSPORT_TYPE_NONE
    // 1. Send SOCKET_SPDM_COMMAND_TEST with payload b'Client Hello!'
    // 2. Receive SOCKET_SPDM_COMMAND_TEST with payload b'Server Hello!'
    spdm_context.transport_init_sequence().map_err(|e| {
        eprintln!("Handshake failed: {:?}", e);
        Error::new(ErrorKind::Other, "SPDM handshake failed")
    })?;

    if config.verbose {
        println!("Initial handshake completed successfully");
    }

    // Process SPDM messages using the context
    let mut buffer = [0u8; 4096];
    let mut message_buffer = MessageBuf::new(&mut buffer);
    // For now, we just want to show, that the VCA (Version, Capability, Auth) flow works as expected
    // For that, we need to do the following:
    // 1.1 Send GET_VERSION
    // 1.2 Receive and verify VERSION
    // 1.3 Update tracking of remote party
    // 2.1 Send GET_CAPABILITIES
    // 2.2 Receive and verify CAPABILITIES
    // 2.3 Update tracking of remote party
    // 3.1 Send GET_AUTH

    // 1.1 Send GET_VERSION
    generate_get_version(
        &mut spdm_context,
        &mut message_buffer,
        VersionReqPayload::new(1, 1),
    )
    .map_err(|(_send_response, cmd_err)| SpdmError::Command(cmd_err))
    .unwrap();

    if config.verbose {
        println!("GET_VERSION: {:?}", &message_buffer.message_data());
    }

    spdm_context
        .requester_send_request(&mut message_buffer, EID)
        .unwrap();

    // 1.2 Receive and verify VERSION
    // 1.3 is done by the requester_process_message call
    spdm_context
        .requester_process_message(&mut message_buffer)
        .unwrap();

    if config.verbose {
        println!("Sent GET_VERSION: {:?}", &message_buffer.message_data());
    }

    // 2.1 Send GET_CAPABILITIES
    message_buffer.reset();
    generate_capabilities_request_local(&mut spdm_context, &mut message_buffer).unwrap();

    if config.verbose {
        println!("GET_CAPABILITIES: {:?}", &message_buffer.message_data());
    }

    spdm_context
        .requester_send_request(&mut message_buffer, EID)
        .unwrap();

    if config.verbose {
        println!(
            "Sent GET_CAPABILITIES: {:?}",
            &message_buffer.message_data()
        );
    }

    // 2.2 Receive and verify CAPABILITIES
    // 2.3 is done by the requester_process_message call
    spdm_context
        .requester_process_message(&mut message_buffer)
        .unwrap();

    if config.verbose {
        println!(
            "Processed CAPABILITIES: {:?}",
            &message_buffer.message_data()
        );
    }

    let ext_asym = [ExtendedAlgo::new(RegistryId::DMTF, 1)];
    let ext_hash = [ExtendedAlgo::new(RegistryId::DMTF, 1)];
    let alg_external = [ExtendedAlgo::new(RegistryId::DMTF, 1)];
    // TODO: since we re-generate them there is the potential issue of TOCTOU.
    let mut local_algorithms = create_local_algorithms();
    local_algorithms
        .device_algorithms
        .base_asym_algo
        .set_tpm_alg_rsapss_2048(1);
    local_algorithms
        .device_algorithms
        .base_hash_algo
        .set_tpm_alg_sha_256(1);

    let mut alg_structure = AlgStructure::new(&AlgType::Dhe, &local_algorithms);
    alg_structure.set_ext_alg_count(1);

    // 3.1 Send GET_ALGORITHMS
    message_buffer.reset();
    generate_negotiate_algorithms_request(
        &mut spdm_context,
        &mut message_buffer,
        Some(&ext_asym),
        Some(&ext_hash),
        alg_structure,
        Some(&alg_external),
    )
    .unwrap();

    spdm_context
        .requester_send_request(&mut message_buffer, EID)
        .unwrap();

    if config.verbose {
        println!(
            "NEGOTIATE_ALGORITHMS: {:x?}",
            &message_buffer.message_data()
        );
    }

    spdm_context
        .requester_process_message(&mut message_buffer)
        .unwrap();

    if config.verbose {
        println!("ALGORITHMS: {:x?}", &message_buffer.message_data());
    }

    println!("SPDM VCA flow completed successfully");

    message_buffer.reset();
    generate_digest_request(&mut spdm_context, &mut message_buffer).unwrap();
    spdm_context
        .requester_send_request(&mut message_buffer, EID)
        .unwrap();

    if config.verbose {
        println!("GET_DIGESTS: {:x?}", &message_buffer.message_data());
    }

    spdm_context
        .requester_process_message(&mut message_buffer)
        .unwrap();

    if config.verbose {
        println!("DIGESTS: {:x?}", &message_buffer.message_data());
    }

    // Get peer certificate chain
    loop {
        message_buffer.reset();
        generate_get_certificate(&mut spdm_context, &mut message_buffer, 0, 0, 0x200, false)
            .unwrap();
        spdm_context
            .requester_send_request(&mut message_buffer, EID)
            .unwrap();
        println!("requested GET_CERTIFICATE");
        println!("state: {:?}", spdm_context.connection_info().state());

        spdm_context
            .requester_process_message(&mut message_buffer)
            .unwrap();
        if config.verbose {
            println!("CERTIFICATE: Ok ({} bytes)", &message_buffer.msg_len(),);
        }
        if !matches!(
            spdm_context.connection_info().state(),
            spdm_lib::state::ConnectionState::DuringCertificate(_)
        ) {
            break;
        }
    }
    println!("sucessfully retrieved peer cert chain");
    if let Some(store) = spdm_context.peer_cert_store() {
        let hash_algo: BaseHashAlgoType = spdm_context
            .connection_info()
            .peer_algorithms()
            .base_hash_algo
            .try_into()
            .unwrap();
        let root_hash = store.get_root_hash(0, hash_algo).unwrap();
        println!(
            "slot 0: Root hash ({hash_algo:?}, {} bytes): {:02x?}",
            root_hash.len(),
            root_hash
        );
        let mut cert_chain = store.get_cert_chain(0, hash_algo).unwrap();

        println!("slot 0: Parsing {} bytes cert chain:", cert_chain.len());
        loop {
            let (cert, rest) = Certificate::from_der_partial(cert_chain).unwrap();
            cert_chain = rest;
            println!(
                "Cert with subject CN {:?}",
                cert.tbs_certificate().subject().common_name()
            );
            if rest.is_empty() {
                break;
            }
        }
    }

    Ok(())
}

/// Parse command line arguments
fn parse_args() -> RequesterConfig {
    let mut config = RequesterConfig::default();
    let args: Vec<String> = env::args().collect();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--port" => {
                if i + 1 < args.len() {
                    config.port = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("Invalid port number: {}", args[i + 1]);
                        process::exit(1);
                    });
                    i += 2;
                } else {
                    eprintln!("Port number required after {}", args[i]);
                    process::exit(1);
                }
            }
            "-c" | "--cert" => {
                if i + 1 < args.len() {
                    config.cert_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Certificate file path required after {}", args[i]);
                    process::exit(1);
                }
            }
            "-k" | "--key" => {
                if i + 1 < args.len() {
                    config.key_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Private key file path required after {}", args[i]);
                    process::exit(1);
                }
            }
            "-m" | "--measurements" => {
                if i + 1 < args.len() {
                    config.measurements_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Measurements file path required after {}", args[i]);
                    process::exit(1);
                }
            }
            "-v" | "--verbose" => {
                config.verbose = true;
                i += 1;
            }
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_help();
                process::exit(1);
            }
        }
    }

    config
}

fn print_help() {
    println!("Real SPDM Library Integrated DMTF Compatible Responder\n");
    println!("USAGE:");
    println!("    spdm-responder-clean [OPTIONS]\n");
    println!("OPTIONS:");
    println!("    -p, --port <PORT>              TCP port to connect to [default: None]");
    println!(
        "    -c, --cert <CERT_FILE>         Path to certificate file [default: device_cert.pem]"
    );
    println!(
        "    -k, --key <KEY_FILE>           Path to private key file [default: device_key.pem]"
    );
    println!(
        "    -m, --measurements <FILE>      Path to measurements file [default: measurements.json]"
    );
    println!("    -v, --verbose                  Enable verbose logging");
    println!("    -h, --help                     Print this help message\n");
    println!("EXAMPLES:");
    println!("    spdm-responder-clean --port 8080 --verbose");
    println!("    spdm-responder-clean --cert my_cert.pem --key my_key.pem");
    println!(
        "\nIntegrates real SPDM library with clean platform implementations - no code duplication!"
    );
}

/// Display configuration information
fn display_info(config: &RequesterConfig) {
    println!("Real SPDM Library Integrated DMTF Compatible Responder");
    println!("=====================================================");
    println!("Configuration:");
    println!("  Port: {}", config.port);
    println!("  Certificate: {}", config.cert_path);
    println!("  Private Key: {}", config.key_path);
    if let Some(ref measurements) = config.measurements_path {
        println!("  Measurements: {}", measurements);
    }
    println!("  Verbose: {}", config.verbose);
    println!();

    let capabilities = create_device_capabilities();
    println!("SPDM Device Capabilities:");
    println!(
        "  Certificate capability: {}",
        capabilities.flags.cert_cap()
    );
    println!("  Challenge capability: {}", capabilities.flags.chal_cap());
    println!(
        "  Measurements capability: {}",
        capabilities.flags.meas_cap()
    );
    println!(
        "  Fresh measurements: {}",
        capabilities.flags.meas_fresh_cap()
    );
    println!("  Chunk capability: {}", capabilities.flags.chunk_cap());
    println!(
        "  Data transfer size: {} bytes",
        capabilities.data_transfer_size
    );
    println!(
        "  Max SPDM message size: {} bytes",
        capabilities.max_spdm_msg_size
    );
    println!();

    println!("Clean Platform Implementation Features:");
    println!("  SPDM Versions: 1.2, 1.1");
    println!("  Protocol Processing: Real SPDM library integration");
    println!("  Hash Algorithm: SHA-384 (platform module)");
    println!("  Signature Algorithm: ECDSA P-384 (platform module)");
    println!("  Measurements: Demo device measurements (platform module)");
    println!("  Certificates: Static OpenSSL-generated certificate chain (platform module)");
    println!("  Transport: TCP socket with DMTF protocol (platform module)");
    println!("  ✅ NO CODE DUPLICATION - All implementations from unified platform module");
    println!();
}

/// Main function
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args();
    display_info(&config);

    let remote_addr = format!("0.0.0.0:{}", config.port);
    let stream = TcpStream::connect(&remote_addr)?;

    println!(
        "Clean SPDM library requester connecting to {}",
        &remote_addr
    );

    if let Ok(peer_addr) = stream.peer_addr() {
        println!("Connection from: {}", peer_addr);
    }

    // Handle client with real SPDM processing using platform implementations
    full_flow(stream, &config)?;

    Ok(())
}
