// Licensed under the Apache-2.0 license

//! Real SPDM Library Integrated DMTF Compatible Responder
//!
//! This responder integrates the actual SPDM library for real protocol processing
//! while maintaining compatibility with the DMTF SPDM emulator protocol.
//!
//! This version uses platform implementations with no duplicated code.

use std::env;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::{TcpListener, TcpStream};
use std::process;

use spdm_lib::codec::MessageBuf;
use spdm_lib::context::SpdmContext;
use spdm_lib::protocol::algorithms::{
    AeadCipherSuite, AlgorithmPriorityTable, BaseAsymAlgo, BaseHashAlgo, DeviceAlgorithms,
    DheNamedGroup, KeySchedule, LocalDeviceAlgorithms, MeasurementHashAlgo,
    MeasurementSpecification, MelSpecification, OtherParamSupport, ReqBaseAsymAlg,
};
use spdm_lib::protocol::version::SpdmVersion;
use spdm_lib::protocol::{CapabilityFlags, DeviceCapabilities};

// Import platform implementations - no duplicates!
mod platform;
use platform::{DemoCertStore, DemoEvidence, Sha384Hash, SpdmSocketTransport, SystemRng};

/// Responder configuration
#[derive(Debug, Clone)]
struct ResponderConfig {
    port: u16,
    cert_path: String,
    key_path: String,
    measurements_path: Option<String>,
    verbose: bool,
    raw: bool,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            port: 2323,
            cert_path: "device_cert.pem".to_string(),
            key_path: "device_key.pem".to_string(),
            measurements_path: Some("measurements.json".to_string()),
            verbose: false,
            raw: false,
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
        include_supported_algorithms: true,
    }
}

/// Create local device algorithms
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
        mel_specification: MelSpecification::default(),
        dhe_group: DheNamedGroup::default(),
        aead_cipher_suite: AeadCipherSuite::default(),
        req_base_asym_algo: ReqBaseAsymAlg::default(),
        key_schedule: KeySchedule::default(),
    };

    let algorithm_priority_table = AlgorithmPriorityTable {
        measurement_specification: None,
        opaque_data_format: None,
        base_asym_algo: None,
        base_hash_algo: None,
        mel_specification: None,
        dhe_group: None,
        aead_cipher_suite: None,
        req_base_asym_algo: None,
        key_schedule: None,
    };

    LocalDeviceAlgorithms {
        device_algorithms,
        algorithm_priority_table,
    }
}

/// Handle client connection with real SPDM processing
fn handle_spdm_client(stream: TcpStream, config: &ResponderConfig) -> IoResult<()> {
    let mut transport = SpdmSocketTransport::new(
        stream,
        platform::socket_transport::SocketTransportType::None,
    );

    // Create platform implementations - all from platform module!
    let mut hash = Sha384Hash::new();
    let mut m1_hash = Sha384Hash::new();
    let mut l1_hash = Sha384Hash::new();
    let mut rng = SystemRng::new();
    let mut cert_store = DemoCertStore::new();
    let evidence = DemoEvidence::new();

    // Create SPDM context
    let supported_versions = [SpdmVersion::V12, SpdmVersion::V11];
    let capabilities = create_device_capabilities();
    let algorithms = create_local_algorithms();

    if config.verbose {
        println!("Client connected - initializing SPDM context");
    }

    let mut spdm_context = match SpdmContext::new(
        &supported_versions,
        &mut transport,
        capabilities,
        algorithms,
        &mut cert_store,
        None,
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

    // Process SPDM messages using the context
    let mut buffer = [0u8; 4096];
    let mut message_buffer = MessageBuf::new(&mut buffer);
    loop {
        match spdm_context.responder_process_message(&mut message_buffer) {
            Ok(()) => {
                if config.verbose {
                    println!("Successfully processed SPDM message");
                }
            }
            Err(e) => {
                if config.verbose {
                    eprintln!("Error processing SPDM message: {:?}", e);
                }
                // Continue processing unless it's a fatal transport error
                match &e {
                    spdm_lib::error::SpdmError::Transport(_) => {
                        if config.verbose {
                            println!("Connection closed gracefully");
                        }
                        break;
                    }
                    _ => {
                        // Log error but continue processing
                        continue;
                    }
                }
            }
        }
    }

    if config.verbose {
        println!("Client connection closed");
    }

    Ok(())
}

/// Parse command line arguments
fn parse_args() -> ResponderConfig {
    let mut config = ResponderConfig::default();
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
    println!("    -p, --port <PORT>              TCP port to listen on [default: 2323]");
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
fn display_info(config: &ResponderConfig) {
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
    println!("  Raw (no TCP binding): {}", config.raw);
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

    // Create TCP listener
    let bind_addr = format!("0.0.0.0:{}", config.port);
    let listener = TcpListener::bind(&bind_addr)?;

    println!("Clean SPDM library responder listening on {}", bind_addr);
    println!("Compatible with DMTF SPDM device validator and emulator clients");
    println!("Uses unified platform implementations with no code duplication");
    println!("Waiting for connections... (Press Ctrl+C to exit)");
    println!();

    // Accept connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Ok(peer_addr) = stream.peer_addr() {
                    println!("Connection from: {}", peer_addr);
                }

                // Handle client with real SPDM processing using platform implementations
                if let Err(e) = handle_spdm_client(stream, &config) {
                    eprintln!("Client handling error: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }

    Ok(())
}
