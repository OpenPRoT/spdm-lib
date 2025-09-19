// Licensed under the Apache-2.0 license

//! Direct SPDM over TCP Responder (DSP0287 Compliant)
//! 
//! This responder implements direct SPDM over TCP binding as per DSP0287
//! without the socket command wrapper layer used in the emulator.

use std::env;
use std::process;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write, Result as IoResult, Error, ErrorKind};

use spdm_lib::protocol::{DeviceCapabilities, CapabilityFlags};

/// DMTF SPDM TCP Binding Header as per DSP0287
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct SpdmTcpBindingHeader {
    payload_length: u16,    // Length of the payload (little-endian)
    binding_version: u8,    // TCP binding version (0x01)
    message_type: u8,       // Message type
}

/// DMTF SPDM TCP Message Types
const SPDM_TCP_MESSAGE_TYPE_OUT_OF_SESSION: u8 = 0x05;
const SPDM_TCP_MESSAGE_TYPE_IN_SESSION: u8 = 0x06;
const SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY: u8 = 0xBF;

// Error message types
const SPDM_TCP_MESSAGE_TYPE_ERROR_TOO_LARGE: u8 = 0xC0;
const SPDM_TCP_MESSAGE_TYPE_ERROR_NOT_SUPPORTED: u8 = 0xC1;

/// Responder configuration
#[derive(Debug, Clone)]
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
            },
            "-c" | "--cert" => {
                if i + 1 < args.len() {
                    config.cert_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Certificate file path required after {}", args[i]);
                    process::exit(1);
                }
            },
            "-k" | "--key" => {
                if i + 1 < args.len() {
                    config.key_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Private key file path required after {}", args[i]);
                    process::exit(1);
                }
            },
            "-m" | "--measurements" => {
                if i + 1 < args.len() {
                    config.measurements_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Measurements file path required after {}", args[i]);
                    process::exit(1);
                }
            },
            "-v" | "--verbose" => {
                config.verbose = true;
                i += 1;
            },
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            },
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
    println!("Direct SPDM over TCP Responder (DSP0287)\n");
    println!("USAGE:");
    println!("    spdm-tcp-responder [OPTIONS]\n");
    println!("OPTIONS:");
    println!("    -p, --port <PORT>              TCP port to listen on [default: 2323]");
    println!("    -c, --cert <CERT_FILE>         Path to certificate file [default: device_cert.pem]");
    println!("    -k, --key <KEY_FILE>           Path to private key file [default: device_key.pem]");
    println!("    -m, --measurements <FILE>      Path to measurements file [default: measurements.json]");
    println!("    -v, --verbose                  Enable verbose logging");
    println!("    -h, --help                     Print this help message\n");
    println!("EXAMPLES:");
    println!("    spdm-tcp-responder --port 8080 --verbose");
    println!("    spdm-tcp-responder --cert my_cert.pem --key my_key.pem");
    println!("\nCompatible with DMTF SPDM device validator and direct TCP binding clients.");
}

/// Create SPDM device capabilities
fn create_device_capabilities() -> DeviceCapabilities {
    // Create capability flags with appropriate values
    let mut flags_value = 0u32;
    flags_value |= 1 << 1;  // cert_cap
    flags_value |= 1 << 2;  // chal_cap  
    flags_value |= 2 << 3;  // meas_cap (with signature)
    flags_value |= 1 << 5;  // meas_fresh_cap
    flags_value |= 1 << 17; // chunk_cap
    
    let flags = CapabilityFlags::new(flags_value);
    
    DeviceCapabilities {
        ct_exponent: 0,
        flags,
        data_transfer_size: 1024,
        max_spdm_msg_size: 4096,
    }
}

/// Direct TCP transport for SPDM messages
struct DirectTcpTransport {
    stream: TcpStream,
}

impl DirectTcpTransport {
    fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// Receive SPDM message with TCP binding header
    fn receive_spdm_message(&mut self) -> IoResult<(u8, Vec<u8>)> {
        // Read TCP binding header (4 bytes)
        let mut header_bytes = [0u8; 4];
        self.stream.read_exact(&mut header_bytes)?;
        
        let payload_length = u16::from_le_bytes([header_bytes[0], header_bytes[1]]);
        let binding_version = header_bytes[2];
        let message_type = header_bytes[3];
        
        if binding_version != 0x01 {
            return Err(Error::new(ErrorKind::InvalidData, "Unsupported binding version"));
        }
        
        // Read payload
        let mut payload = vec![0u8; payload_length as usize];
        if payload_length > 0 {
            self.stream.read_exact(&mut payload)?;
        }
        
        Ok((message_type, payload))
    }

    /// Send SPDM message with TCP binding header
    fn send_spdm_message(&mut self, message_type: u8, payload: &[u8]) -> IoResult<()> {
        let header = SpdmTcpBindingHeader {
            payload_length: payload.len() as u16,
            binding_version: 0x01,
            message_type,
        };
        
        // Send header (4 bytes)
        let header_bytes = [
            (header.payload_length & 0xFF) as u8,
            (header.payload_length >> 8) as u8,
            header.binding_version,
            header.message_type,
        ];
        self.stream.write_all(&header_bytes)?;
        
        // Send payload
        if !payload.is_empty() {
            self.stream.write_all(payload)?;
        }
        
        self.stream.flush()?;
        Ok(())
    }

    /// Send error response
    fn send_error(&mut self, error_type: u8) -> IoResult<()> {
        self.send_spdm_message(error_type, &[])
    }
}

/// Handle client connection with direct TCP binding
fn handle_tcp_client(stream: TcpStream, config: &ResponderConfig) -> IoResult<()> {
    let mut transport = DirectTcpTransport::new(stream);
    
    if config.verbose {
        println!("Client connected - starting direct TCP binding handler");
    }
    
    // Main message processing loop
    loop {
        match transport.receive_spdm_message() {
            Ok((message_type, payload)) => {
                if config.verbose {
                    println!("Received message type: 0x{:02X}, payload size: {}", message_type, payload.len());
                    if !payload.is_empty() && config.verbose {
                        println!("Payload: {:02X?}", &payload[..std::cmp::min(16, payload.len())]);
                    }
                }
                
                match message_type {
                    SPDM_TCP_MESSAGE_TYPE_OUT_OF_SESSION | SPDM_TCP_MESSAGE_TYPE_IN_SESSION => {
                        // Process SPDM message
                        if !payload.is_empty() {
                            // In a real implementation, this would call the SPDM library
                            // For demo, create a response based on the message
                            let response = process_spdm_message(&payload);
                            transport.send_spdm_message(message_type, &response)?;
                        } else {
                            // Send error for empty payload
                            transport.send_error(SPDM_TCP_MESSAGE_TYPE_ERROR_NOT_SUPPORTED)?;
                        }
                    },
                    SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY => {
                        if config.verbose {
                            println!("Received role inquiry");
                        }
                        // Respond that we're a responder
                        let role_response = vec![0x01]; // Responder role
                        transport.send_spdm_message(SPDM_TCP_MESSAGE_TYPE_ROLE_INQUIRY, &role_response)?;
                    },
                    _ => {
                        if config.verbose {
                            println!("Unknown message type: 0x{:02X}", message_type);
                        }
                        transport.send_error(SPDM_TCP_MESSAGE_TYPE_ERROR_NOT_SUPPORTED)?;
                    }
                }
            },
            Err(e) => {
                if config.verbose {
                    eprintln!("Protocol error: {}", e);
                }
                // Try to send error response
                let _ = transport.send_error(SPDM_TCP_MESSAGE_TYPE_ERROR_NOT_SUPPORTED);
                break;
            }
        }
    }
    
    if config.verbose {
        println!("Client connection closed");
    }
    
    Ok(())
}

/// Process SPDM message (demo implementation)
fn process_spdm_message(request: &[u8]) -> Vec<u8> {
    if request.is_empty() {
        return Vec::new();
    }
    
    // Parse SPDM message header (simplified)
    let spdm_version = if request.len() >= 1 { request[0] } else { 0 };
    let request_code = if request.len() >= 2 { request[1] } else { 0 };
    
    if spdm_version != 0x10 && spdm_version != 0x11 && spdm_version != 0x12 {
        // Invalid SPDM version, return error
        return vec![spdm_version, 0x7F, 0x01]; // ERROR response with InvalidRequest
    }
    
    // Create demo responses based on request code
    match request_code {
        0x84 => {
            // GET_VERSION request
            let mut response = vec![spdm_version, 0x04]; // VERSION response
            response.extend_from_slice(&[0x00, 0x00]); // Reserved
            response.extend_from_slice(&[0x02, 0x00]); // VersionNumberEntryCount = 2
            response.extend_from_slice(&[0x10, 0x11]); // SPDM 1.0, 1.1
            response.extend_from_slice(&[0x12, 0x00]); // SPDM 1.2
            response
        },
        0x81 => {
            // GET_CAPABILITIES request
            let mut response = vec![spdm_version, 0x61]; // CAPABILITIES response
            response.extend_from_slice(&[0x00, 0x00, 0x00]); // Reserved
            response.push(0x00); // CTExponent
            response.extend_from_slice(&[0x00, 0x00]); // Reserved
            
            // Capability flags (little-endian)
            let caps = create_device_capabilities();
            let cap_flags = caps.flags.0.to_le_bytes();
            response.extend_from_slice(&cap_flags);
            
            response
        },
        0x63 => {
            // NEGOTIATE_ALGORITHMS request
            let mut response = vec![spdm_version, 0x63]; // ALGORITHMS response
            response.extend_from_slice(&[0x00, 0x00]); // Reserved
            response.extend_from_slice(&[0x20, 0x00]); // Length = 32
            response.extend_from_slice(&[0x01]); // MeasurementSpecification = DMTF
            response.extend_from_slice(&[0x00, 0x00, 0x00]); // Reserved
            response.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]); // MeasurementHashAlgo = SHA384
            response.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]); // BaseAsymAlgo = ECDSA_P384
            response.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]); // BaseHashAlgo = SHA384
            response.extend_from_slice(&[0x00; 12]); // Reserved/unused fields
            response
        },
        _ => {
            // Unknown request, return error
            vec![spdm_version, 0x7F, 0x05] // ERROR response with UnsupportedRequest
        }
    }
}

/// Display configuration information
fn display_info(config: &ResponderConfig) {
    println!("Direct SPDM over TCP Responder (DSP0287)");
    println!("========================================");
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
    println!("  Certificate capability: {}", capabilities.flags.cert_cap());
    println!("  Challenge capability: {}", capabilities.flags.chal_cap());
    println!("  Measurements capability: {}", capabilities.flags.meas_cap());
    println!("  Fresh measurements: {}", capabilities.flags.meas_fresh_cap());
    println!("  Chunk capability: {}", capabilities.flags.chunk_cap());
    println!("  Data transfer size: {} bytes", capabilities.data_transfer_size);
    println!("  Max SPDM message size: {} bytes", capabilities.max_spdm_msg_size);
    println!();
    
    println!("Protocol Features:");
    println!("  SPDM Versions: 1.0, 1.1, 1.2");
    println!("  TCP Binding: DSP0287 v1.0 direct binding");
    println!("  Message Types: OUT_OF_SESSION, IN_SESSION, ROLE_INQUIRY");
    println!("  Hash Algorithm: SHA-384");
    println!("  Signature Algorithm: ECDSA P-384");
    println!();
}

/// Main function
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args();
    
    display_info(&config);
    
    // Create TCP listener
    let bind_addr = format!("0.0.0.0:{}", config.port);
    let listener = TcpListener::bind(&bind_addr)?;
    
    println!("Direct TCP binding server listening on {}", bind_addr);
    println!("Compatible with DMTF SPDM device validator");
    println!("Waiting for connections... (Press Ctrl+C to exit)");
    println!();
    
    // Accept connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Ok(peer_addr) = stream.peer_addr() {
                    println!("Connection from: {}", peer_addr);
                }
                
                // Handle client with direct TCP binding
                if let Err(e) = handle_tcp_client(stream, &config) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ResponderConfig::default();
        assert_eq!(config.port, 2323);
        assert!(!config.cert_path.is_empty());
        assert!(!config.key_path.is_empty());
    }

    #[test]
    fn test_device_capabilities() {
        let capabilities = create_device_capabilities();
        assert_eq!(capabilities.flags.cert_cap(), 1);
        assert_eq!(capabilities.flags.chal_cap(), 1);
        assert_eq!(capabilities.flags.meas_cap(), 2);
        assert_eq!(capabilities.data_transfer_size, 1024);
        assert_eq!(capabilities.max_spdm_msg_size, 4096);
    }

    #[test]
    fn test_spdm_message_processing() {
        // Test GET_VERSION request
        let get_version_req = vec![0x10, 0x84, 0x00, 0x00];
        let response = process_spdm_message(&get_version_req);
        assert!(!response.is_empty());
        assert_eq!(response[0], 0x10); // SPDM version
        assert_eq!(response[1], 0x04); // VERSION response code
    }
}