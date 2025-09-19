// Licensed under the Apache-2.0 license

//! Simple SPDM Responder Application
//! 
//! A basic command-line SPDM responder that demonstrates how to use the SPDM library
//! to create an SPDM responder service.

use std::env;
use std::process;
use std::net::{TcpListener, TcpStream};

use spdm_lib::protocol::version::SpdmVersion;
use spdm_lib::protocol::{DeviceCapabilities, CapabilityFlags};

/// Configuration for the SPDM Responder
#[derive(Debug)]
struct ResponderConfig {
    port: u16,
    cert_path: String,
    key_path: String,
    measurements_path: Option<String>,
    verbose: bool,
}

impl Default for ResponderConfig {
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

/// Parse command line arguments
fn parse_args() -> ResponderConfig {
    let args: Vec<String> = env::args().collect();
    let mut config = ResponderConfig::default();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                if i + 1 < args.len() {
                    config.port = args[i + 1].parse().unwrap_or(config.port);
                    i += 2;
                } else {
                    eprintln!("Error: --port requires a value");
                    process::exit(1);
                }
            }
            "--cert" | "-c" => {
                if i + 1 < args.len() {
                    config.cert_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --cert requires a value");
                    process::exit(1);
                }
            }
            "--key" | "-k" => {
                if i + 1 < args.len() {
                    config.key_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --key requires a value");
                    process::exit(1);
                }
            }
            "--measurements" | "-m" => {
                if i + 1 < args.len() {
                    config.measurements_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --measurements requires a value");
                    process::exit(1);
                }
            }
            "--verbose" | "-v" => {
                config.verbose = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_help();
                process::exit(0);
            }
            _ => {
                eprintln!("Error: Unknown argument: {}", args[i]);
                print_help();
                process::exit(1);
            }
        }
    }

    config
}

/// Print help message
fn print_help() {
    println!("SPDM Responder Application");
    println!();
    println!("USAGE:");
    println!("    spdm-responder [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    -p, --port <PORT>              TCP port to listen on [default: 2323]");
    println!("    -c, --cert <CERT_FILE>         Path to certificate file [default: device_cert.pem]");
    println!("    -k, --key <KEY_FILE>           Path to private key file [default: device_key.pem]");
    println!("    -m, --measurements <FILE>      Path to measurements file [default: measurements.json]");
    println!("    -v, --verbose                  Enable verbose logging");
    println!("    -h, --help                     Print this help message");
    println!();
    println!("EXAMPLES:");
    println!("    spdm-responder --port 8080 --verbose");
    println!("    spdm-responder --cert my_cert.pem --key my_key.pem");
}

/// Create SPDM device capabilities
fn create_device_capabilities() -> DeviceCapabilities {
    let mut flags = CapabilityFlags::default();
    
    // Set required capabilities using the bitfield methods
    flags.set_cert_cap(1);      // Certificate capability
    flags.set_chal_cap(1);      // Challenge capability  
    flags.set_meas_cap(2);      // Measurements with signature
    flags.set_meas_fresh_cap(1); // Fresh measurements
    flags.set_chunk_cap(1);     // Chunking capability
    
    DeviceCapabilities {
        ct_exponent: 0,
        flags,
        data_transfer_size: 1024,
        max_spdm_msg_size: 4096,
    }
}

/// Create local device algorithms configuration
fn create_local_algorithms() -> String {
    // This is a placeholder that returns algorithm info as string
    // In a real implementation, you would create LocalDeviceAlgorithms
    "Algorithm configuration: SHA-384, ECDSA P-384, DMTF measurements".to_string()
}

/// Demo function that shows how to set up an SPDM context
/// This is a placeholder since we need actual platform implementations
fn demo_spdm_setup(config: &ResponderConfig) {
    println!("=== SPDM Responder Demo ===");
    println!("Configuration: {:?}", config);
    println!();
    
    // Show supported SPDM versions
    let supported_versions = &[SpdmVersion::V12, SpdmVersion::V11];
    println!("Supported SPDM versions: {:?}", supported_versions);
    
    // Show device capabilities
    let capabilities = create_device_capabilities();
    println!("Device capabilities:");
    println!("  - Certificate capability: {}", capabilities.flags.cert_cap());
    println!("  - Challenge capability: {}", capabilities.flags.chal_cap());
    println!("  - Measurements capability: {}", capabilities.flags.meas_cap());
    println!("  - Fresh measurements: {}", capabilities.flags.meas_fresh_cap());
    println!("  - Chunk capability: {}", capabilities.flags.chunk_cap());
    println!("  - Data transfer size: {} bytes", capabilities.data_transfer_size);
    println!("  - Max SPDM message size: {} bytes", capabilities.max_spdm_msg_size);
    println!();
    
    // Show algorithm configuration
    let _algorithms = create_local_algorithms();
    println!("Supported algorithms:");
    println!("  - Base hash: SHA-384");
    println!("  - Base asymmetric: ECDSA P-384");
    println!("  - Measurement hash: SHA-384");
    println!("  - Measurement spec: DMTF");
    println!();
    
    println!("=== Platform Implementation Required ===");
    println!("To create a working SPDM responder, implement:");
    println!("1. SpdmTransport trait for your transport layer (TCP, UDP, etc.)");
    println!("2. SpdmHash trait for cryptographic hashing");
    println!("3. SpdmRng trait for random number generation");
    println!("4. SpdmCertStore trait for certificate management");
    println!("5. SpdmEvidence trait for device measurements");
    println!();
    
    println!("Example usage with platform implementations:");
    println!("```rust");
    println!("let mut spdm_context = SpdmContext::new(");
    println!("    supported_versions,");
    println!("    &mut transport,     // Your SpdmTransport implementation");
    println!("    capabilities,");
    println!("    algorithms,");
    println!("    &mut cert_store,    // Your SpdmCertStore implementation");
    println!("    &mut main_hash,     // Your SpdmHash implementation");
    println!("    &mut m1_hash,       // Your SpdmHash implementation");
    println!("    &mut l1_hash,       // Your SpdmHash implementation");
    println!("    &mut rng,           // Your SpdmRng implementation");
    println!("    &evidence,          // Your SpdmEvidence implementation");
    println!(")?;");
    println!();
    println!("// Process SPDM messages");
    println!("let mut message_buffer = MessageBuf::new();");
    println!("loop {{");
    println!("    match spdm_context.process_message(&mut message_buffer) {{");
    println!("        Ok(()) => println!(\"Message processed successfully\"),");
    println!("        Err(e) => eprintln!(\"Error: {{:?}}\", e),");
    println!("    }}");
    println!("}}");
    println!("```");
}

/// Handle a single client connection (placeholder)
fn _handle_client(stream: TcpStream, config: &ResponderConfig) -> std::io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    
    if config.verbose {
        println!("New client connected: {}", peer_addr);
    }
    
    println!("Note: This is a demo. Actual SPDM message processing requires");
    println!("platform implementations (transport, crypto, certificates, etc.)");
    
    // In a real implementation, you would:
    // 1. Create platform implementations
    // 2. Create SpdmContext with those implementations
    // 3. Process SPDM messages in a loop
    
    std::thread::sleep(std::time::Duration::from_secs(1));
    
    if config.verbose {
        println!("Client {} disconnected (demo)", peer_addr);
    }
    
    Ok(())
}

/// Main function
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args();

    println!("SPDM Responder Demo Application");
    println!("===============================");
    
    // Show the demo setup
    demo_spdm_setup(&config);
    
    // Create TCP listener for demonstration
    let bind_addr = format!("0.0.0.0:{}", config.port);
    let listener = TcpListener::bind(&bind_addr)?;
    
    println!("Demo server listening on {}", bind_addr);
    println!("Certificate: {}", config.cert_path);
    println!("Private Key: {}", config.key_path);
    if let Some(ref measurements) = config.measurements_path {
        println!("Measurements: {}", measurements);
    }
    println!();
    println!("Waiting for connections... (Press Ctrl+C to exit)");
    println!("Note: This is a demonstration - implement platform traits for full functionality");

    // Accept connections (basic demo loop)
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("Connection from: {}", stream.peer_addr()?);
                println!("Demo: Would process SPDM messages here");
                // In a real implementation, you would handle the SPDM protocol here
                // using your SpdmContext with platform trait implementations
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ResponderConfig::default();
        assert_eq!(config.port, 2323);
        assert!(!config.cert_path.is_empty());
        assert!(!config.key_path.is_empty());
        assert!(!config.verbose);
    }

    #[test]
    fn test_parse_args_empty() {
        // This test would require mocking env::args()
        // For now, just test that the function exists
        let _config = ResponderConfig::default();
    }
}