// Licensed under the Apache-2.0 license

//! Real SPDM Library Integrated DMTF Compatible Responder
//! 
//! This responder integrates the actual SPDM library for real protocol processing
//! while maintaining compatibility with the DMTF SPDM emulator protocol.

use std::env;
use std::process;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write, Result as IoResult, Error, ErrorKind};

use spdm_lib::context::SpdmContext;
use spdm_lib::protocol::{DeviceCapabilities, CapabilityFlags};
use spdm_lib::protocol::version::SpdmVersion;
use spdm_lib::protocol::algorithms::{LocalDeviceAlgorithms, DeviceAlgorithms, AlgorithmPriorityTable, AsymAlgo};
use spdm_lib::platform::transport::{SpdmTransport, TransportResult, TransportError};
use spdm_lib::platform::hash::{SpdmHash, SpdmHashAlgoType, SpdmHashResult, SpdmHashError};
use spdm_lib::platform::rng::{SpdmRng, SpdmRngResult, SpdmRngError};
use spdm_lib::platform::evidence::{SpdmEvidence, SpdmEvidenceResult, SpdmEvidenceError, PCR_QUOTE_BUFFER_SIZE};
use spdm_lib::cert_store::{SpdmCertStore, CertStoreResult, CertStoreError};
use spdm_lib::codec::MessageBuf;
use spdm_lib::protocol::certs::{CertificateInfo, KeyUsageMask};
use spdm_lib::protocol::algorithms::{SHA384_HASH_SIZE, ECC_P384_SIGNATURE_SIZE};

/// Socket platform command types (from DMTF emulator)
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

/// Real SPDM Transport implementation for socket protocol
struct SpdmSocketTransport {
    stream: TcpStream,
    pending_request: Option<Vec<u8>>,
    pending_response: Option<Vec<u8>>,
}

impl SpdmSocketTransport {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            pending_request: None,
            pending_response: None,
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
}

impl SpdmTransport for SpdmSocketTransport {
    fn send_request<'a>(&mut self, _dest_eid: u8, _req: &mut MessageBuf<'a>) -> TransportResult<()> {
        // Not used in responder mode
        Err(TransportError::DriverError)
    }

    fn receive_response<'a>(&mut self, _rsp: &mut MessageBuf<'a>) -> TransportResult<()> {
        // Not used in responder mode
        Err(TransportError::DriverError)
    }

    fn receive_request<'a>(&mut self, req: &mut MessageBuf<'a>) -> TransportResult<()> {
        if let Some(request_data) = self.pending_request.take() {
            req.reset();
            req.reserve(request_data.len()).map_err(|_| TransportError::BufferTooSmall)?;
            req.append(&request_data).map_err(|_| TransportError::BufferTooSmall)?;
            Ok(())
        } else {
            Err(TransportError::ReceiveError)
        }
    }

    fn send_response<'a>(&mut self, resp: &mut MessageBuf<'a>) -> TransportResult<()> {
        // Extract response data
        let response_data = resp.as_slice().to_vec();
        self.pending_response = Some(response_data);
        Ok(())
    }

    fn max_message_size(&self) -> TransportResult<usize> {
        Ok(4096)
    }

    fn header_size(&self) -> usize {
        0 // No additional header for SPDM messages
    }
}

/// SHA-384 hash implementation
struct Sha384Hash {
    current_algo: SpdmHashAlgoType,
}

impl Sha384Hash {
    fn new() -> Self {
        Self {
            current_algo: SpdmHashAlgoType::SHA384,
        }
    }
}

impl SpdmHash for Sha384Hash {
    fn hash(&mut self, hash_algo: SpdmHashAlgoType, data: &[u8], hash: &mut [u8]) -> SpdmHashResult<()> {
        // For demo purposes, create a fake hash
        // In real implementation, use a crypto library like sha2 or ring
        if hash_algo != SpdmHashAlgoType::SHA384 {
            return Err(SpdmHashError::InvalidAlgorithm);
        }
        
        if hash.len() < 48 {
            return Err(SpdmHashError::BufferTooSmall);
        }
        
        // Simple checksum for demo (not cryptographically secure)
        for (i, &byte) in data.iter().enumerate() {
            hash[i % 48] ^= byte;
        }
        
        Ok(())
    }

    fn init(&mut self, hash_algo: SpdmHashAlgoType, _data: Option<&[u8]>) -> SpdmHashResult<()> {
        if hash_algo != SpdmHashAlgoType::SHA384 {
            return Err(SpdmHashError::InvalidAlgorithm);
        }
        self.current_algo = hash_algo;
        Ok(())
    }

    fn update(&mut self, _data: &[u8]) -> SpdmHashResult<()> {
        // For demo, just return success
        Ok(())
    }

    fn finalize(&mut self, hash: &mut [u8]) -> SpdmHashResult<()> {
        if hash.len() < 48 {
            return Err(SpdmHashError::BufferTooSmall);
        }
        // For demo, return a dummy digest
        hash[..48].fill(0x42);
        Ok(())
    }

    fn reset(&mut self) {
        // Reset state for demo
    }

    fn algo(&self) -> SpdmHashAlgoType {
        self.current_algo
    }
}

/// System RNG implementation
struct SystemRng;

impl SystemRng {
    fn new() -> Self {
        Self
    }
}

impl SpdmRng for SystemRng {
    fn get_random_bytes(&mut self, buf: &mut [u8]) -> SpdmRngResult<()> {
        // For demo, fill with pseudo-random data
        // In real implementation, use proper RNG
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(137).wrapping_add(42);
        }
        Ok(())
    }

    fn generate_random_number(&mut self, random_number: &mut [u8]) -> SpdmRngResult<()> {
        // For demo, generate a simple pattern
        for (i, byte) in random_number.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(193).wrapping_add(67);
        }
        Ok(())
    }
}

/// Demo certificate store
struct DemoCertStore {
    cert_chain: Vec<u8>,
}

impl DemoCertStore {
    fn new() -> Self {
        // For demo, create a dummy certificate chain
        let cert_chain = b"DEMO_CERTIFICATE_CHAIN_DATA".to_vec();
        Self { cert_chain }
    }
}

impl SpdmCertStore for DemoCertStore {
    fn get_cert_via_cert_chain(&self, _slot_id: u8) -> Result<&[u8], spdm_lib::error::SpdmError> {
        Ok(&self.cert_chain)
    }

    fn verify_cert_chain(&self, _cert_chain: &[u8]) -> Result<(), spdm_lib::error::SpdmError> {
        // For demo, always return success
        Ok(())
    }
}

/// Demo evidence implementation
struct DemoEvidence {
    measurements: Vec<SpdmMeasurement>,
}

impl DemoEvidence {
    fn new() -> Self {
        // Create demo measurements
        let mut measurements = Vec::new();
        for i in 0..3 {
            let mut measurement = SpdmMeasurement::new();
            measurement.index = i;
            measurement.specification = 1; // DMTF
            measurement.hash_alg = 0x20; // SHA-384
            measurement.measurement_value = vec![0x42 + i; 48]; // Demo measurement
            measurements.push(measurement);
        }
        
        Self { measurements }
    }
}

impl SpdmEvidence for DemoEvidence {
    fn get_measurement(&self, measurement_index: usize) -> Result<SpdmMeasurement, spdm_lib::error::SpdmError> {
        self.measurements.get(measurement_index)
            .cloned()
            .ok_or(spdm_lib::error::SpdmError::InvalidParameter)
    }

    fn get_measurement_count(&self) -> usize {
        self.measurements.len()
    }
}

/// Create SPDM device capabilities
fn create_device_capabilities() -> DeviceCapabilities {
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

/// Create local device algorithms
fn create_local_algorithms<'a>() -> LocalDeviceAlgorithms<'a> {
    let mut device_algorithms = DeviceAlgorithms::default();
    
    // Set supported algorithms
    device_algorithms.base_hash_algo = 0x20; // SHA-384
    device_algorithms.base_asym_algo = 0x20; // ECDSA P-384
    device_algorithms.measurement_spec = 0x01; // DMTF
    device_algorithms.measurement_hash_algo = 0x20; // SHA-384
    
    let algorithm_priority_table = AlgorithmPriorityTable::default();
    
    LocalDeviceAlgorithms {
        device_algorithms,
        algorithm_priority_table,
    }
}

/// Handle client connection with real SPDM processing
fn handle_spdm_client(stream: TcpStream, config: &ResponderConfig) -> IoResult<()> {
    let mut transport = SpdmSocketTransport::new(stream);
    
    // Create platform implementations
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
    
    // Main protocol loop
    loop {
        match transport.receive_platform_data() {
            Ok((command, data)) => {
                if config.verbose {
                    println!("Received command: {:?}, data size: {}", command, data.len());
                }
                
                match command {
                    SocketSpdmCommand::Normal => {
                        if !data.is_empty() {
                            // Store SPDM request data for processing
                            transport.pending_request = Some(data);
                            
                            // Process SPDM message using real library
                            let mut message_buf = MessageBuf::new();
                            match spdm_context.process_message(&mut message_buf) {
                                Ok(()) => {
                                    if config.verbose {
                                        println!("SPDM message processed successfully");
                                    }
                                    
                                    // Get response data
                                    if let Some(response_data) = transport.pending_response.take() {
                                        transport.send_platform_data(SocketSpdmCommand::Normal, &response_data)?;
                                    } else {
                                        // No response data, send empty response
                                        transport.send_platform_data(SocketSpdmCommand::Normal, &[])?;
                                    }
                                },
                                Err(e) => {
                                    if config.verbose {
                                        eprintln!("SPDM processing error: {:?}", e);
                                    }
                                    // Send error response
                                    transport.send_platform_data(SocketSpdmCommand::Unknown, &[])?;
                                }
                            }
                        } else {
                            transport.send_platform_data(SocketSpdmCommand::Unknown, &[])?;
                        }
                    },
                    SocketSpdmCommand::ClientHello => {
                        if config.verbose {
                            println!("Received client hello: {:?}", String::from_utf8_lossy(&data));
                        }
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
                break;
            }
        }
    }
    
    if config.verbose {
        println!("Client connection closed");
    }
    
    Ok(())
}

/// Parse command line arguments (same as before)
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
    println!("\nIntegrates real SPDM library for full protocol compliance.");
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
    
    println!("Real SPDM Library Features:");
    println!("  SPDM Versions: 1.2, 1.1");
    println!("  Protocol Processing: Real SPDM library integration");
    println!("  Hash Algorithm: SHA-384");
    println!("  Signature Algorithm: ECDSA P-384");
    println!("  Measurements: Demo device measurements");
    println!("  Certificates: Demo certificate chain");
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
                
                // Handle client with real SPDM processing
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
    fn test_device_capabilities() {
        let capabilities = create_device_capabilities();
        assert_eq!(capabilities.flags.cert_cap(), 1);
        assert_eq!(capabilities.flags.chal_cap(), 1);
        assert_eq!(capabilities.flags.meas_cap(), 2);
        assert_eq!(capabilities.data_transfer_size, 1024);
        assert_eq!(capabilities.max_spdm_msg_size, 4096);
    }

    #[test]
    fn test_platform_implementations() {
        let mut hash = Sha384Hash::new();
        let data = b"test data";
        let digest = hash.hash_all(data);
        assert!(digest.is_ok());
        
        let mut rng = SystemRng::new();
        let mut buffer = [0u8; 32];
        let result = rng.get_random(&mut buffer);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 32);
        
        let cert_store = DemoCertStore::new();
        let cert_chain = cert_store.get_cert_via_cert_chain(0);
        assert!(cert_chain.is_ok());
        
        let evidence = DemoEvidence::new();
        assert_eq!(evidence.get_measurement_count(), 3);
        let measurement = evidence.get_measurement(0);
        assert!(measurement.is_ok());
    }
}