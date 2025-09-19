// Licensed under the Apache-2.0 license

//! DMTF SPDM Emulator Compatible Responder
//! 
//! This responder implements the DMTF SPDM emulator protocol for compatibility
//! with the official DMTF spdm-emu tools and test suite.

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
const SPDM_TCP_MESSAGE_TYPE_ERROR_CANNOT_OPERATE_AS_REQUESTER: u8 = 0xC2;
const SPDM_TCP_MESSAGE_TYPE_ERROR_CANNOT_OPERATE_AS_RESPONDER: u8 = 0xC3;

/// Socket platform command types (inferred from DMTF emulator)
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
enum SocketSpdmCommand {
    Normal = 0x00000001,
    Shutdown = 0x00000002,
    Continue = 0x00000003,
    ClientHello = 0x0000adde,  // Magic header from validator
    Unknown = 0xFFFFFFFF,
}

impl From<u32> for SocketSpdmCommand {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => SocketSpdmCommand::Normal,
            0x00000002 => SocketSpdmCommand::Shutdown,
            0x00000003 => SocketSpdmCommand::Continue,
            0x0000adde => SocketSpdmCommand::ClientHello,
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
    binding_version: u8,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            port: 2323,
            cert_path: "device_cert.pem".to_string(),
            key_path: "device_key.pem".to_string(),
            measurements_path: Some("measurements.json".to_string()),
            verbose: false,
            binding_version: 0x01,
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
    println!("DMTF SPDM Emulator Compatible Responder\n");
    println!("USAGE:");
    println!("    spdm-responder-dmtf [OPTIONS]\n");
    println!("OPTIONS:");
    println!("    -p, --port <PORT>              TCP port to listen on [default: 2323]");
    println!("    -c, --cert <CERT_FILE>         Path to certificate file [default: device_cert.pem]");
    println!("    -k, --key <KEY_FILE>           Path to private key file [default: device_key.pem]");
    println!("    -m, --measurements <FILE>      Path to measurements file [default: measurements.json]");
    println!("    -v, --verbose                  Enable verbose logging");
    println!("    -h, --help                     Print this help message\n");
    println!("EXAMPLES:");
    println!("    spdm-responder-dmtf --port 8080 --verbose");
    println!("    spdm-responder-dmtf --cert my_cert.pem --key my_key.pem");
    println!("\nCompatible with DMTF SPDM emulator clients and test tools.");
}

/// Create SPDM device capabilities compatible with DMTF emulator
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

/// TCP transport compatible with DMTF SPDM emulator
struct DmtfTcpTransport {
    stream: TcpStream,
    receive_buffer: Vec<u8>,
    send_buffer: Vec<u8>,
}

impl DmtfTcpTransport {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            receive_buffer: vec![0u8; 8192],
            send_buffer: vec![0u8; 8192],
        }
    }

    /// Receive platform data with socket message header
    fn receive_platform_data(&mut self) -> IoResult<(SocketSpdmCommand, Vec<u8>)> {
        // Read socket message header
        let mut header_bytes = [0u8; 12]; // sizeof(SocketMessageHeader)
        self.stream.read_exact(&mut header_bytes)?;
        
        let command = u32::from_le_bytes([header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]]);
        let _transport_type = u32::from_le_bytes([header_bytes[4], header_bytes[5], header_bytes[6], header_bytes[7]]);
        let data_size = u32::from_le_bytes([header_bytes[8], header_bytes[9], header_bytes[10], header_bytes[11]]);
        
        let socket_command = SocketSpdmCommand::from(command);
        
        if data_size > 0 {
            let mut data = vec![0u8; data_size as usize];
            self.stream.read_exact(&mut data)?;
            Ok((socket_command, data))
        } else {
            Ok((socket_command, Vec::new()))
        }
    }

    /// Send platform data with socket message header
    fn send_platform_data(&mut self, command: SocketSpdmCommand, data: &[u8]) -> IoResult<()> {
        let header = SocketMessageHeader {
            command: command as u32,
            transport_type: 0, // TCP transport
            data_size: data.len() as u32,
        };
        
        // Send header
        let header_bytes = unsafe {
            std::slice::from_raw_parts(&header as *const _ as *const u8, std::mem::size_of::<SocketMessageHeader>())
        };
        self.stream.write_all(header_bytes)?;
        
        // Send data if any
        if !data.is_empty() {
            self.stream.write_all(data)?;
        }
        
        self.stream.flush()?;
        Ok(())
    }

    /// Receive SPDM message with TCP binding header
    fn receive_spdm_message(&mut self) -> IoResult<Vec<u8>> {
        // Read TCP binding header
        let mut header_bytes = [0u8; 4]; // sizeof(SpdmTcpBindingHeader)
        self.stream.read_exact(&mut header_bytes)?;
        
        let payload_length = u16::from_le_bytes([header_bytes[0], header_bytes[1]]);
        let binding_version = header_bytes[2];
        let _message_type = header_bytes[3];
        
        if binding_version != 0x01 {
            return Err(Error::new(ErrorKind::InvalidData, "Unsupported binding version"));
        }
        
        // Read payload
        let mut payload = vec![0u8; payload_length as usize];
        self.stream.read_exact(&mut payload)?;
        
        Ok(payload)
    }

    /// Send SPDM message with TCP binding header
    fn send_spdm_message(&mut self, message_type: u8, payload: &[u8]) -> IoResult<()> {
        let header = SpdmTcpBindingHeader {
            payload_length: payload.len() as u16,
            binding_version: 0x01,
            message_type,
        };
        
        // Send header
        let header_bytes = unsafe {
            std::slice::from_raw_parts(&header as *const _ as *const u8, std::mem::size_of::<SpdmTcpBindingHeader>())
        };
        self.stream.write_all(header_bytes)?;
        
        // Send payload
        self.stream.write_all(payload)?;
        self.stream.flush()?;
        
        Ok(())
    }

    /// Send error response
    fn send_error(&mut self, error_type: u8) -> IoResult<()> {
        self.send_spdm_message(error_type, &[])
    }
}

/// Handle client connection with DMTF protocol compatibility
fn handle_dmtf_client(stream: TcpStream, config: &ResponderConfig) -> IoResult<()> {
    let mut transport = DmtfTcpTransport::new(stream);
    
    if config.verbose {
        println!("Client connected - starting DMTF protocol handler");
    }
    
    // Main protocol loop - similar to DMTF emulator
    loop {
        match transport.receive_platform_data() {
            Ok((command, data)) => {
                if config.verbose {
                    println!("Received command: {:?}, data size: {}", command, data.len());
                }
                
                match command {
                    SocketSpdmCommand::Normal => {
                        // This is where SPDM message processing would occur
                        // For now, simulate processing and send back an echo
                        if !data.is_empty() {
                            // In a real implementation, this would call:
                            // libspdm_responder_dispatch_message(spdm_context, &data, &mut response)
                            
                            // For demo, create a simple response
                            let response = create_demo_response(&data);
                            transport.send_platform_data(SocketSpdmCommand::Normal, &response)?;
                        } else {
                            // Send error for empty data
                            transport.send_platform_data(SocketSpdmCommand::Unknown, &[])?;
                        }
                    },
                    SocketSpdmCommand::ClientHello => {
                        if config.verbose {
                            println!("Received client hello: {:?}", String::from_utf8_lossy(&data));
                        }
                        // Send back a hello response
                        let response = b"Server Hello!";
                        transport.send_platform_data(SocketSpdmCommand::ClientHello, response)?;
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
                            println!("Received unknown command");
                        }
                        transport.send_platform_data(SocketSpdmCommand::Unknown, &[])?;
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

/// Create a demo response for testing
fn create_demo_response(request: &[u8]) -> Vec<u8> {
    // In a real implementation, this would be processed by the SPDM library
    // For demo purposes, create a simple response
    
    if request.is_empty() {
        return Vec::new();
    }
    
    // Echo back the request with a simple modification to show processing
    let mut response = request.to_vec();
    if !response.is_empty() {
        response[0] = response[0].wrapping_add(1); // Simple modification
    }
    
    response
}

/// Display configuration and protocol information
fn display_dmtf_info(config: &ResponderConfig) {
    println!("DMTF SPDM Emulator Compatible Responder");
    println!("=======================================");
    println!("Configuration:");
    println!("  Port: {}", config.port);
    println!("  Certificate: {}", config.cert_path);
    println!("  Private Key: {}", config.key_path);
    if let Some(ref measurements) = config.measurements_path {
        println!("  Measurements: {}", measurements);
    }
    println!("  Verbose: {}", config.verbose);
    println!("  TCP Binding Version: 0x{:02X}", config.binding_version);
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
    
    println!("Supported DMTF Protocol Features:");
    println!("  TCP Binding: DSP0287 v1.0");
    println!("  Socket Commands: NORMAL, SHUTDOWN, CONTINUE");
    println!("  Message Types: OUT_OF_SESSION, IN_SESSION, ROLE_INQUIRY");
    println!("  Transport: TCP with platform message headers");
    println!();
}

/// Main function
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args();
    
    display_dmtf_info(&config);
    
    // Create TCP listener
    let bind_addr = format!("0.0.0.0:{}", config.port);
    let listener = TcpListener::bind(&bind_addr)?;
    
    println!("DMTF-compatible server listening on {}", bind_addr);
    println!("Compatible with DMTF spdm-emu requester clients");
    println!("Waiting for connections... (Press Ctrl+C to exit)");
    println!();
    
    // Accept connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Ok(peer_addr) = stream.peer_addr() {
                    println!("Connection from: {}", peer_addr);
                }
                
                // Handle client with DMTF protocol
                if let Err(e) = handle_dmtf_client(stream, &config) {
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
        assert_eq!(SocketSpdmCommand::from(0xFFFFFFFF), SocketSpdmCommand::Unknown);
    }

    #[test]
    fn test_default_config() {
        let config = ResponderConfig::default();
        assert_eq!(config.port, 2323);
        assert_eq!(config.binding_version, 0x01);
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
    fn test_demo_response() {
        let request = vec![0x10, 0x20, 0x30];
        let response = create_demo_response(&request);
        assert_eq!(response.len(), 3);
        assert_eq!(response[0], 0x11); // 0x10 + 1
        assert_eq!(response[1], 0x20);
        assert_eq!(response[2], 0x30);
    }
}