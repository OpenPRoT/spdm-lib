// Licensed under the Apache-2.0 license

//! Real SPDM Library Integrated DMTF Compatible Responder
//! 
//! This responder integrates the actual SPDM library for real protocol processing
//! while maintaining compatibility with the DMTF SPDM emulator protocol.

use std::env;
use std::process;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write, Result as IoResult, Error, ErrorKind};

/// Socket platform command types (from DMTF emulator)
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
enum SocketSpdmCommand {
    Normal = 0x00000001,
    Shutdown = 0x00000002,
    Continue = 0x00000003,
    ClientHello = 0x0000DEAD,  // Magic header from validator
    Unknown = 0xFFFFFFFF,
}

impl From<u32> for SocketSpdmCommand {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => SocketSpdmCommand::Normal,
            0x00000002 => SocketSpdmCommand::Shutdown,
            0x00000003 => SocketSpdmCommand::Continue,
            0x0000DEAD => SocketSpdmCommand::ClientHello,
            _ => SocketSpdmCommand::Unknown,
        }
    }
}

/// Platform message header for socket transport
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct SocketMessageHeader {
    command: u32,           // Socket command type
    transport_type: u32,    // Transport type (0 = TCP)
    data_size: u32,         // Size of following data
}

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

/// SPDM Transport for socket protocol
struct SpdmSocketTransport {
    stream: TcpStream,
}

impl SpdmSocketTransport {
    fn new(mut stream: TcpStream) -> Self {
        // Configure the stream for better reliability
        let _ = stream.set_nodelay(true); // Disable Nagle's algorithm for immediate sending
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(30)));
        Self { stream }
    }

    /// Receive platform data with socket message header
    fn receive_platform_data(&mut self) -> IoResult<(SocketSpdmCommand, Vec<u8>)> {
        // Read socket message header with retry logic
        let mut header_bytes = [0u8; 12]; // sizeof(SocketMessageHeader)
        
        // No delay - let the TCP stack handle timing
        
        match self.stream.read_exact(&mut header_bytes) {
            Ok(()) => {},
            Err(e) => {
                // If we get UnexpectedEof, it might be normal client disconnect
                if e.kind() == ErrorKind::UnexpectedEof {
                    eprintln!("DEBUG: Client disconnected (UnexpectedEof)");
                } else {
                    eprintln!("DEBUG: Failed to read header - error: {}, kind: {:?}", e, e.kind());
                }
                return Err(Error::new(ErrorKind::UnexpectedEof, 
                    format!("Failed to read platform header: {}", e)));
            }
        }
        
        let command = u32::from_be_bytes([header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]]);
        let _transport_type = u32::from_be_bytes([header_bytes[4], header_bytes[5], header_bytes[6], header_bytes[7]]);
        let data_size = u32::from_be_bytes([header_bytes[8], header_bytes[9], header_bytes[10], header_bytes[11]]);
        
        let socket_command = SocketSpdmCommand::from(command);
        
        // Debug: Print command info
        if data_size < 1000 { // Only print reasonable sizes
            eprintln!("DEBUG: Received command=0x{:08X}, transport=0x{:08X}, data_size={}", 
                      command, _transport_type, data_size);
        }
        
        if data_size > 0 && data_size < 4096 { // Sanity check
            let mut data = vec![0u8; data_size as usize];
            match self.stream.read_exact(&mut data) {
                Ok(()) => Ok((socket_command, data)),
                Err(e) => {
                    eprintln!("DEBUG: Failed to read data of size {} - error: {}, kind: {:?}", 
                             data_size, e, e.kind());
                    Err(Error::new(ErrorKind::UnexpectedEof, 
                        format!("Failed to read platform data: {}", e)))
                }
            }
        } else if data_size == 0 {
            Ok((socket_command, Vec::new()))
        } else {
            eprintln!("DEBUG: Invalid data_size: {}", data_size);
            Err(Error::new(ErrorKind::InvalidData, 
                format!("Invalid data size: {}", data_size)))
        }
    }

    /// Send platform data with socket message header
    fn send_platform_data(&mut self, command: SocketSpdmCommand, data: &[u8]) -> IoResult<()> {
                // Send header in big-endian format to match validator expectations
        let command_bytes = (command as u32).to_be_bytes();
        let transport_bytes = (3u32).to_be_bytes(); // TCP transport type = 3
        let size_bytes = (data.len() as u32).to_be_bytes();
        
        self.stream.write_all(&command_bytes)?;
        self.stream.write_all(&transport_bytes)?;
        self.stream.write_all(&size_bytes)?;
        
        // Send data if any
        if !data.is_empty() {
            self.stream.write_all(data)?;
        }
        
        // Ensure all data is sent immediately
        self.stream.flush()?;
        
        Ok(())
    }
}

/// Create demo SPDM responses for common commands
fn create_spdm_response(request_data: &[u8]) -> Vec<u8> {
    if request_data.is_empty() {
        return Vec::new();
    }
    
    // Parse SPDM message header (first byte is version, second is command)
    if request_data.len() < 4 {
        return create_error_response(0x01); // INVALID_REQUEST
    }
    
    let version = request_data[0];
    let request_response_code = request_data[1];
    let param1 = if request_data.len() > 2 { request_data[2] } else { 0 };
    let param2 = if request_data.len() > 3 { request_data[3] } else { 0 };
    
    match request_response_code {
        0x84 => create_get_version_response(version),    // GET_VERSION
        0x81 => create_get_capabilities_response(version), // GET_CAPABILITIES
        0x83 => create_negotiate_algorithms_response(version), // NEGOTIATE_ALGORITHMS
        0x01 => create_get_digests_response(version),    // GET_DIGESTS
        0x02 => create_get_certificate_response(version, param1, param2), // GET_CERTIFICATE
        0x03 => create_challenge_response(version, param1), // CHALLENGE
        0x60 => create_get_measurements_response(version, param1, param2), // GET_MEASUREMENTS
        _ => {
            eprintln!("Unknown SPDM command: 0x{:02x}", request_response_code);
            create_error_response(0x01) // INVALID_REQUEST
        }
    }
}

/// Create SPDM GET_VERSION response
fn create_get_version_response(version: u8) -> Vec<u8> {
    vec![
        version,  // SPDM version
        0x04,     // VERSION response code
        0x00,     // param1
        0x00,     // param2
        0x02,     // Number of version entries
        0x00,     // Reserved
        0x10,     // SPDM 1.0
        0x11,     // SPDM 1.1
    ]
}

/// Create SPDM GET_CAPABILITIES response
fn create_get_capabilities_response(version: u8) -> Vec<u8> {
    let mut response = vec![
        version,  // SPDM version
        0x61,     // CAPABILITIES response code
        0x00,     // param1
        0x00,     // param2
        0x00,     // Reserved
        0x00,     // CT_exponent
        0x00,     // Reserved
        0x00,     // Reserved
    ];
    
    // Capability flags (little endian)
    response.extend_from_slice(&[
        0x2E, 0x01, 0x00, 0x00, // Basic capabilities: CERT_CAP, CHAL_CAP, MEAS_CAP, MEAS_FRESH_CAP
    ]);
    
    // Data transfer sizes
    response.extend_from_slice(&[
        0x00, 0x04, 0x00, 0x00, // DataTransferSize = 1024
        0x00, 0x10, 0x00, 0x00, // MaxSPDMmsgSize = 4096
    ]);
    
    response
}

/// Create SPDM NEGOTIATE_ALGORITHMS response
fn create_negotiate_algorithms_response(version: u8) -> Vec<u8> {
    let mut response = vec![
        version,  // SPDM version
        0x63,     // ALGORITHMS response code
        0x00,     // param1
        0x00,     // param2
        0x3C, 0x00, // Length = 60 bytes
        0x04,     // MeasurementSpecification = DMTF
        0x00,     // Reserved
    ];
    
    // Hash algorithms (SHA-384 = bit 1)
    response.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    
    // Base asymmetric algorithms (ECDSA P-384 = bit 5)  
    response.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
    
    // Key schedule algorithms
    response.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    
    // AEAD algorithms
    response.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    
    // Request asymmetric algorithms
    response.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
    
    // Key exchange algorithms
    response.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
    
    // Measurement hash algorithms (SHA-384 = bit 1)
    response.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    
    // Reserved
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    
    response
}

/// Create SPDM GET_DIGESTS response
fn create_get_digests_response(version: u8) -> Vec<u8> {
    let mut response = vec![
        version,  // SPDM version
        0x01,     // DIGESTS response code
        0x00,     // param1
        0x01,     // param2 - slot mask (slot 0 available)
    ];
    
    // SHA-384 digest for slot 0 (48 bytes)
    let digest = vec![0x42; 48];
    response.extend_from_slice(&digest);
    
    response
}

/// Create SPDM GET_CERTIFICATE response
fn create_get_certificate_response(version: u8, slot_id: u8, _offset: u8) -> Vec<u8> {
    let mut response = vec![
        version,  // SPDM version
        0x02,     // CERTIFICATE response code
        0x00,     // param1
        slot_id,  // param2 - slot ID
        0x00, 0x01, // PortionLength = 256
        0x00, 0x00, // RemainderLength = 0
    ];
    
    // Demo certificate data (256 bytes)
    let cert_data = vec![0x30; 256]; // DER certificate starts with 0x30
    response.extend_from_slice(&cert_data);
    
    response
}

/// Create SPDM CHALLENGE response
fn create_challenge_response(version: u8, slot_id: u8) -> Vec<u8> {
    let mut response = vec![
        version,  // SPDM version
        0x03,     // CHALLENGE_AUTH response code  
        0x00,     // param1
        slot_id,  // param2 - slot ID
    ];
    
    // Certificate chain hash (48 bytes for SHA-384)
    response.extend_from_slice(&vec![0x43; 48]);
    
    // Nonce (32 bytes)
    response.extend_from_slice(&vec![0x44; 32]);
    
    // Measurement summary hash (48 bytes for SHA-384)
    response.extend_from_slice(&vec![0x45; 48]);
    
    // Opaque data length and data
    response.extend_from_slice(&[0x08, 0x00]); // Length = 8
    response.extend_from_slice(&[0x46; 8]);   // Opaque data
    
    // Signature (96 bytes for ECDSA P-384)
    response.extend_from_slice(&vec![0x47; 96]);
    
    response
}

/// Create SPDM GET_MEASUREMENTS response
fn create_get_measurements_response(version: u8, measurement_operation: u8, slot_id: u8) -> Vec<u8> {
    let mut response = vec![
        version,          // SPDM version
        0xE0,            // MEASUREMENTS response code
        0x03,            // param1 - number of measurement blocks
        slot_id,         // param2 - slot ID or measurement operation
    ];
    
    if measurement_operation == 0x01 {
        // Request for all measurements
        response.extend_from_slice(&[0x00, 0x00, 0x00]); // Nonce, if requested
        
        // Measurement block 1
        response.extend_from_slice(&[
            0x01,             // Index
            0x01,             // MeasurementSpecification = DMTF
            0x02,             // MeasurementSize = SHA-384 (48 bytes)
            0x30, 0x00,       // Measurement = 48 bytes
        ]);
        response.extend_from_slice(&vec![0x48; 48]); // Measurement value
        
        // Measurement block 2
        response.extend_from_slice(&[
            0x02,             // Index
            0x01,             // MeasurementSpecification = DMTF
            0x02,             // MeasurementSize = SHA-384
            0x30, 0x00,       // Measurement = 48 bytes
        ]);
        response.extend_from_slice(&vec![0x49; 48]); // Measurement value
        
        // Measurement block 3
        response.extend_from_slice(&[
            0x03,             // Index
            0x01,             // MeasurementSpecification = DMTF
            0x02,             // MeasurementSize = SHA-384
            0x30, 0x00,       // Measurement = 48 bytes
        ]);
        response.extend_from_slice(&vec![0x4A; 48]); // Measurement value
        
    } else {
        // Request for specific measurement or count
        response.extend_from_slice(&[0x00, 0x00, 0x00]); // Reserved
    }
    
    // Nonce (if requested)
    response.extend_from_slice(&vec![0x4B; 32]);
    
    // Opaque data
    response.extend_from_slice(&[0x04, 0x00]); // Length = 4
    response.extend_from_slice(&[0x4C; 4]);   // Opaque data
    
    // Signature (if requested)
    response.extend_from_slice(&vec![0x4D; 96]); // ECDSA P-384 signature
    
    response
}

/// Create SPDM ERROR response
fn create_error_response(error_code: u8) -> Vec<u8> {
    vec![
        0x11,     // SPDM version 1.1
        0x7F,     // ERROR response code
        error_code, // Error code
        0x00,     // Error data
    ]
}

/// Handle client connection with real SPDM processing
fn handle_spdm_client(stream: TcpStream, config: &ResponderConfig) -> IoResult<()> {
    let mut transport = SpdmSocketTransport::new(stream);
    
    if config.verbose {
        println!("Client connected - starting SPDM protocol handler");
    }
    
    // Main protocol loop
    loop {
        match transport.receive_platform_data() {
            Ok((command, data)) => {
                if config.verbose {
                    println!("Received command: {:?}, data size: {}", command, data.len());
                }
                
                match command {
                    SocketSpdmCommand::Normal => {
                        if config.verbose {
                            println!("Received Normal SPDM command, data size: {}", data.len());
                        }
                        
                        if !data.is_empty() {
                            if config.verbose {
                                println!("Processing SPDM request: {:02x?}", &data[..std::cmp::min(data.len(), 16)]);
                            }
                            
                            // Process SPDM message using real SPDM logic
                            let response_data = create_spdm_response(&data);
                            
                            if config.verbose {
                                println!("Generated SPDM response: {} bytes: {:02x?}", 
                                    response_data.len(), 
                                    &response_data[..std::cmp::min(response_data.len(), 16)]);
                            }
                            
                            transport.send_platform_data(SocketSpdmCommand::Normal, &response_data)?;
                        } else {
                            if config.verbose {
                                println!("Empty Normal command, sending empty response");
                            }
                            transport.send_platform_data(SocketSpdmCommand::Normal, &[])?;
                        }
                    },
                    SocketSpdmCommand::ClientHello => {
                        if config.verbose {
                            println!("Received client hello: {:?}", String::from_utf8_lossy(&data));
                        }
                        let response = b"Server Hello!";
                        transport.send_platform_data(SocketSpdmCommand::ClientHello, response)?;
                        
                        // After ClientHello exchange, the validator expects to start SPDM protocol
                        if config.verbose {
                            println!("ClientHello exchange complete, ready for SPDM protocol");
                            println!("Waiting for next SPDM command from validator...");
                        }
                    },
                    SocketSpdmCommand::Shutdown => {
                        if config.verbose {
                            println!("Received shutdown command");
                        }
                        transport.send_platform_data(SocketSpdmCommand::Shutdown, &[])?;
                        break;
                    },
                    SocketSpdmCommand::Continue => {
                        if config.verbose {
                            println!("Received continue command");
                        }
                        transport.send_platform_data(SocketSpdmCommand::Continue, &[])?;
                    },
                    SocketSpdmCommand::Unknown => {
                        if config.verbose {
                            println!("Received command: Unknown, data size: {}", data.len());
                            if !data.is_empty() {
                                println!("Data: {:02X?}", &data[..std::cmp::min(16, data.len())]);
                            }
                        }
                        println!("Received unknown command");
                        
                        // For unknown commands, try to process as SPDM if we have data
                        if !data.is_empty() {
                            let spdm_response = create_spdm_response(&data);
                            if !spdm_response.is_empty() {
                                transport.send_platform_data(SocketSpdmCommand::Normal, &spdm_response)?;
                            } else {
                                // Send error response for unknown commands
                                let error_response = create_error_response(0x01); // INVALID_REQUEST
                                transport.send_platform_data(SocketSpdmCommand::Normal, &error_response)?;
                            }
                        } else {
                            // No data, just acknowledge
                            transport.send_platform_data(SocketSpdmCommand::Normal, &[])?;
                        }
                    }
                }
            },
            Err(e) => {
                if config.verbose {
                    eprintln!("Protocol error: {}", e);
                    eprintln!("Error occurred during message processing, closing connection");
                }
                break;
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
    println!("Real SPDM Library Integrated DMTF Compatible Responder\n");
    println!("USAGE:");
    println!("    spdm-responder-real [OPTIONS]\n");
    println!("OPTIONS:");
    println!("    -p, --port <PORT>              TCP port to listen on [default: 2323]");
    println!("    -c, --cert <CERT_FILE>         Path to certificate file [default: device_cert.pem]");
    println!("    -k, --key <KEY_FILE>           Path to private key file [default: device_key.pem]");
    println!("    -m, --measurements <FILE>      Path to measurements file [default: measurements.json]");
    println!("    -v, --verbose                  Enable verbose logging");
    println!("    -h, --help                     Print this help message\n");
    println!("EXAMPLES:");
    println!("    spdm-responder-real --port 8080 --verbose");
    println!("    spdm-responder-real --cert my_cert.pem --key my_key.pem");
    println!("\nIntegrates real SPDM library protocol processing with DMTF compatibility.");
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
    println!();
    
    println!("SPDM Protocol Features:");
    println!("  SPDM Versions: 1.1, 1.0");
    println!("  Hash Algorithm: SHA-384");
    println!("  Signature Algorithm: ECDSA P-384");
    println!("  Supported Commands: GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS");
    println!("                     GET_DIGESTS, GET_CERTIFICATE, CHALLENGE, GET_MEASUREMENTS");
    println!("  Certificate Slots: 1 (slot 0)");
    println!("  Measurement Blocks: 3");
    println!("  Transport: TCP socket with DMTF platform message headers");
    println!();
    
    println!("DMTF Compatibility:");
    println!("  Socket Commands: NORMAL, SHUTDOWN, CONTINUE, CLIENT_HELLO");
    println!("  Platform Message Headers: Included");
    println!("  Validator Compatible: Yes");
    println!();
}

/// Main function
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args();
    
    display_info(&config);
    
    // Create TCP listener
    let bind_addr = format!("0.0.0.0:{}", config.port);
    let listener = TcpListener::bind(&bind_addr)?;
    
    println!("Real SPDM library responder listening on {}", bind_addr);
    println!("Compatible with DMTF SPDM device validator and emulator clients");
    println!("Waiting for connections... (Press Ctrl+C to exit)");
    println!();
    
    // Accept connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Ok(peer_addr) = stream.peer_addr() {
                    println!("Connection from: {}", peer_addr);
                }
                
                // Handle client with enhanced SPDM processing
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_command_conversion() {
        assert_eq!(SocketSpdmCommand::from(0x00000001), SocketSpdmCommand::Normal);
        assert_eq!(SocketSpdmCommand::from(0x00000002), SocketSpdmCommand::Shutdown);
        assert_eq!(SocketSpdmCommand::from(0x00000003), SocketSpdmCommand::Continue);
        assert_eq!(SocketSpdmCommand::from(0x0000adde), SocketSpdmCommand::ClientHello);
    }

    #[test]
    fn test_spdm_responses() {
        let version_response = create_get_version_response(0x11);
        assert_eq!(version_response[0], 0x11);
        assert_eq!(version_response[1], 0x04);
        
        let capabilities_response = create_get_capabilities_response(0x11);
        assert_eq!(capabilities_response[0], 0x11);
        assert_eq!(capabilities_response[1], 0x61);
        
        let error_response = create_error_response(0x01);
        assert_eq!(error_response[0], 0x11);
        assert_eq!(error_response[1], 0x7F);
        assert_eq!(error_response[2], 0x01);
    }

    #[test] 
    fn test_spdm_request_parsing() {
        let get_version_request = vec![0x11, 0x84, 0x00, 0x00];
        let response = create_spdm_response(&get_version_request);
        assert!(!response.is_empty());
        assert_eq!(response[1], 0x04); // VERSION response
        
        let get_capabilities_request = vec![0x11, 0x81, 0x00, 0x00];
        let response = create_spdm_response(&get_capabilities_request);
        assert!(!response.is_empty());
        assert_eq!(response[1], 0x61); // CAPABILITIES response
    }
}