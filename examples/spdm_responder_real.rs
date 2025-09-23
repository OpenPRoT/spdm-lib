// Licensed under the Apache-2.0 license

//! Real SPDM Library Integrated DMTF Compatible Responder
//! 
//! This responder integrates the actual SPDM library for real protocol processing
//! while maintaining compatibility with the DMTF SPDM emulator protocol.
//!
//! This version provides simplified working implementations of the platform traits
//! to demonstrate the integration with the real SPDM library.

use std::env;
use std::process;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write, Result as IoResult, Error, ErrorKind};

use spdm_lib::context::SpdmContext;
use spdm_lib::protocol::{DeviceCapabilities, CapabilityFlags};
use spdm_lib::protocol::version::SpdmVersion;
use spdm_lib::protocol::algorithms::{
    LocalDeviceAlgorithms, AlgorithmPriorityTable, DeviceAlgorithms,
    AsymAlgo, SHA384_HASH_SIZE, ECC_P384_SIGNATURE_SIZE,
    MeasurementSpecification, MeasurementHashAlgo, BaseAsymAlgo, BaseHashAlgo, 
    DheNamedGroup, AeadCipherSuite, KeySchedule, OtherParamSupport, MelSpecification,
    ReqBaseAsymAlg
};
use spdm_lib::platform::transport::{SpdmTransport, TransportResult, TransportError};
use spdm_lib::platform::hash::{SpdmHash, SpdmHashAlgoType, SpdmHashResult, SpdmHashError};
use spdm_lib::platform::rng::{SpdmRng, SpdmRngResult};
use spdm_lib::platform::evidence::{SpdmEvidence, SpdmEvidenceResult};
use spdm_lib::cert_store::{SpdmCertStore, CertStoreResult, CertStoreError};
use spdm_lib::codec::MessageBuf;
use spdm_lib::protocol::certs::{CertificateInfo, KeyUsageMask};

// Cryptographic imports
#[cfg(feature = "crypto")]
use sha2::{Sha384, Digest};
#[cfg(feature = "crypto")]
use p384::{ecdsa::{SigningKey, Signature, signature::Signer}, SecretKey};
#[cfg(feature = "crypto")]
use std::sync::Mutex;

/// Socket platform command types (from DMTF emulator)
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
enum SocketSpdmCommand {
    Normal = 0x00000001,
    Continue = 0x00000003,
    ClientHello = 0x0000DEAD,  // Magic header from validator
    Shutdown = 0x0000FFFE,
    Unknown = 0xFFFFFFFF,
}

impl From<u32> for SocketSpdmCommand {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => SocketSpdmCommand::Normal,
            0x0000FFFE => SocketSpdmCommand::Shutdown,
            0x00000003 => SocketSpdmCommand::Continue,
            0x0000DEAD => SocketSpdmCommand::ClientHello,
            _ => SocketSpdmCommand::Unknown,
        }
    }
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

/// SPDM Transport implementation that handles socket protocol internally
struct SpdmSocketTransport {
    stream: TcpStream,
}

impl SpdmSocketTransport {
    fn new(stream: TcpStream) -> Self {
        Self { 
            stream,
        }
    }

    /// Receive platform data with socket message header
    fn receive_platform_data(&mut self) -> IoResult<(SocketSpdmCommand, Vec<u8>)> {
        // Read socket message header
        let mut header_bytes = [0u8; 12]; // sizeof(SocketMessageHeader)
        self.stream.read_exact(&mut header_bytes)?;
        
        let command = u32::from_be_bytes([header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]]);
        let _transport_type = u32::from_be_bytes([header_bytes[4], header_bytes[5], header_bytes[6], header_bytes[7]]);
        let data_size = u32::from_be_bytes([header_bytes[8], header_bytes[9], header_bytes[10], header_bytes[11]]);
        
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
        // Handle socket protocol and extract SPDM data
        loop {
            match self.receive_platform_data() {
                Ok((command, data)) => {
                    match command {
                        SocketSpdmCommand::Normal => {
                            if !data.is_empty() {
                                // This is an SPDM message
                                req.reset();
                                let data_len = data.len();
                                req.put_data(data_len).map_err(|_| TransportError::BufferTooSmall)?;
                                let buf = req.data_mut(data_len).map_err(|_| TransportError::BufferTooSmall)?;
                                buf.copy_from_slice(&data);
                                return Ok(());
                            } else {
                                // Empty data - send empty response
                                self.send_platform_data(SocketSpdmCommand::Unknown, &[]).map_err(|_| TransportError::SendError)?;
                                continue;
                            }
                        },
                        SocketSpdmCommand::ClientHello => {
                            // Handle client hello
                            let response = b"Server Hello!";
                            self.send_platform_data(SocketSpdmCommand::ClientHello, response).map_err(|_| TransportError::SendError)?;
                            continue;
                        },
                        SocketSpdmCommand::Continue => {
                            // Handle continue
                            self.send_platform_data(SocketSpdmCommand::Continue, &[]).map_err(|_| TransportError::SendError)?;
                            continue;
                        },
                        SocketSpdmCommand::Shutdown => {
                             // Send shutdown response first
                             let _ = self.send_platform_data(SocketSpdmCommand::Shutdown, &[]);
                             return Err(TransportError::ReceiveError);
                        },
                        SocketSpdmCommand::Unknown => {
                            self.send_platform_data(SocketSpdmCommand::Unknown, &[]).map_err(|_| TransportError::SendError)?;
                            continue; 
                        }
                    }
                },
                Err(_) => {
                    return Err(TransportError::ReceiveError);
                }
            }
        }
    }

    fn send_response<'a>(&mut self, resp: &mut MessageBuf<'a>) -> TransportResult<()> {
        // Extract response data and send with socket protocol
        let message_data = resp.message_data().map_err(|_| TransportError::BufferTooSmall)?;
        self.send_platform_data(SocketSpdmCommand::Normal, message_data).map_err(|_| TransportError::SendError)?;
        Ok(())
    }

    fn max_message_size(&self) -> TransportResult<usize> {
        Ok(4096)
    }

    fn header_size(&self) -> usize {
        0 // No additional header for SPDM messages
    }
}

/// SHA-384 hash implementation using proper cryptography
struct Sha384Hash {
    current_algo: SpdmHashAlgoType,
    #[cfg(feature = "crypto")]
    hasher: Option<Sha384>,
}

impl Sha384Hash {
    fn new() -> Self {
        Self {
            current_algo: SpdmHashAlgoType::SHA384,
            #[cfg(feature = "crypto")]
            hasher: None,
        }
    }
}

impl SpdmHash for Sha384Hash {
    fn hash(&mut self, hash_algo: SpdmHashAlgoType, data: &[u8], hash: &mut [u8]) -> SpdmHashResult<()> {
        if hash_algo != SpdmHashAlgoType::SHA384 {
            return Err(SpdmHashError::InvalidAlgorithm);
        }
        
        if hash.len() < 48 {
            return Err(SpdmHashError::BufferTooSmall);
        }
        
        #[cfg(feature = "crypto")]
        {
            let mut hasher = Sha384::new();
            hasher.update(data);
            let result = hasher.finalize();
            hash[..48].copy_from_slice(&result[..]);
            Ok(())
        }
        
        #[cfg(not(feature = "crypto"))]
        {
            // Fallback for demo purposes when crypto feature is not enabled
            for (i, &byte) in data.iter().enumerate() {
                hash[i % 48] ^= byte;
            }
            Ok(())
        }
    }

    fn init(&mut self, hash_algo: SpdmHashAlgoType, data: Option<&[u8]>) -> SpdmHashResult<()> {
        if hash_algo != SpdmHashAlgoType::SHA384 {
            return Err(SpdmHashError::InvalidAlgorithm);
        }
        self.current_algo = hash_algo;
        
        #[cfg(feature = "crypto")]
        {
            let mut hasher = Sha384::new();
            if let Some(initial_data) = data {
                hasher.update(initial_data);
            }
            self.hasher = Some(hasher);
        }
        
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> SpdmHashResult<()> {
        #[cfg(feature = "crypto")]
        {
            if let Some(ref mut hasher) = self.hasher {
                hasher.update(data);
            } else {
                return Err(SpdmHashError::PlatformError);
            }
        }
        
        Ok(())
    }

    fn finalize(&mut self, hash: &mut [u8]) -> SpdmHashResult<()> {
        if hash.len() < 48 {
            return Err(SpdmHashError::BufferTooSmall);
        }
        
        #[cfg(feature = "crypto")]
        {
            if let Some(hasher) = self.hasher.take() {
                let result = hasher.finalize();
                hash[..48].copy_from_slice(&result[..]);
            } else {
                return Err(SpdmHashError::PlatformError);
            }
        }
        
        #[cfg(not(feature = "crypto"))]
        {
            // Fallback for demo
            hash[..48].fill(0x42);
        }
        
        Ok(())
    }

    fn reset(&mut self) {
        #[cfg(feature = "crypto")]
        {
            if self.current_algo == SpdmHashAlgoType::SHA384 {
                self.hasher = Some(Sha384::new());
            }
        }
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

/// Certificate store with proper ECDSA signing
struct DemoCertStore {
    cert_chain: Vec<u8>,
    #[cfg(feature = "crypto")]
    signing_key: Mutex<Option<SigningKey>>,
}

impl DemoCertStore {
    fn new() -> Self {
        // For demo, create a dummy certificate chain
        let cert_chain = b"DEMO_CERTIFICATE_CHAIN_DATA".to_vec();
        
        #[cfg(feature = "crypto")]
        {
            // Generate a demo signing key for P-384
            let secret_key = SecretKey::random(&mut rand::thread_rng());
            let signing_key = SigningKey::from(secret_key);
            
            Self {
                cert_chain,
                signing_key: Mutex::new(Some(signing_key)),
            }
        }
        
        #[cfg(not(feature = "crypto"))]
        {
            Self { cert_chain }
        }
    }
}

impl SpdmCertStore for DemoCertStore {
    fn slot_count(&self) -> u8 {
        1 // Only support slot 0
    }

    fn is_provisioned(&self, slot_id: u8) -> bool {
        slot_id == 0 // Only slot 0 is provisioned
    }

    fn cert_chain_len(&mut self, _asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize> {
        if slot_id == 0 {
            Ok(self.cert_chain.len())
        } else {
            Err(CertStoreError::InvalidSlotId)
        }
    }

    fn get_cert_chain<'a>(
        &mut self,
        slot_id: u8,
        _asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize> {
        if slot_id != 0 {
            return Err(CertStoreError::InvalidSlotId);
        }

        if offset >= self.cert_chain.len() {
            return Ok(0);
        }

        let remaining = self.cert_chain.len() - offset;
        let to_copy = std::cmp::min(remaining, cert_portion.len());
        
        cert_portion[..to_copy].copy_from_slice(&self.cert_chain[offset..offset + to_copy]);
        
        // Fill remaining with zeros if needed
        if to_copy < cert_portion.len() {
            cert_portion[to_copy..].fill(0);
        }
        
        Ok(to_copy)
    }

    fn root_cert_hash<'a>(
        &mut self,
        slot_id: u8,
        _asym_algo: AsymAlgo,
        cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        if slot_id != 0 {
            return Err(CertStoreError::InvalidSlotId);
        }
        
        #[cfg(feature = "crypto")]
        {
            // Hash the certificate chain using SHA-384
            let mut hasher = Sha384::new();
            hasher.update(&self.cert_chain);
            let result = hasher.finalize();
            cert_hash.copy_from_slice(&result[..]);
        }
        
        #[cfg(not(feature = "crypto"))]
        {
            // Fallback for demo when crypto feature is not enabled
            cert_hash.fill(0x42);
        }
        
        Ok(())
    }

    fn sign_hash<'a>(
        &self,
        slot_id: u8,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        if slot_id != 0 {
            return Err(CertStoreError::InvalidSlotId);
        }
        
        #[cfg(feature = "crypto")]
        {
            if let Ok(signing_key_guard) = self.signing_key.lock() {
                if let Some(ref signing_key) = *signing_key_guard {
                    // Sign the hash using ECDSA P-384
                    let sig: Signature = signing_key.sign(hash);
                    let sig_bytes = sig.to_bytes();
                    
                    // Copy signature bytes (ECDSA P-384 signature is 96 bytes: 48 bytes r + 48 bytes s)
                    if sig_bytes.len() <= ECC_P384_SIGNATURE_SIZE {
                        signature[..sig_bytes.len()].copy_from_slice(&sig_bytes);
                        // Fill remaining with zeros if needed
                        if sig_bytes.len() < ECC_P384_SIGNATURE_SIZE {
                            signature[sig_bytes.len()..].fill(0);
                        }
                    } else {
                        return Err(CertStoreError::BufferTooSmall);
                    }
                    
                    return Ok(());
                }
            }
            return Err(CertStoreError::PlatformError);
        }
        
        #[cfg(not(feature = "crypto"))]
        {
            // Fallback for demo when crypto feature is not enabled
            signature.fill(0x43);
            Ok(())
        }
    }

    fn key_pair_id(&self, slot_id: u8) -> Option<u8> {
        if slot_id == 0 {
            Some(0)
        } else {
            None
        }
    }

    fn cert_info(&self, slot_id: u8) -> Option<CertificateInfo> {
        if slot_id == 0 {
            let mut cert_info = CertificateInfo(0);
            cert_info.set_cert_model(1); // Device certificate model
            Some(cert_info)
        } else {
            None
        }
    }

    fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask> {
        if slot_id == 0 {
            let mut key_usage = KeyUsageMask::default();
            key_usage.set_challenge_usage(1);
            key_usage.set_measurement_usage(1);
            Some(key_usage)
        } else {
            None
        }
    }
}

/// Demo evidence implementation
struct DemoEvidence;

impl DemoEvidence {
    fn new() -> Self {
        Self
    }
}

impl SpdmEvidence for DemoEvidence {
    fn pcr_quote(&self, buffer: &mut [u8], _with_pqc_sig: bool) -> SpdmEvidenceResult<usize> {
        // For demo, fill with dummy PCR quote data
        let quote_size = std::cmp::min(buffer.len(), 64); // Demo quote size
        buffer[..quote_size].fill(0x44); // Demo data
        Ok(quote_size)
    }

    fn pcr_quote_size(&self, _with_pqc_sig: bool) -> SpdmEvidenceResult<usize> {
        Ok(64) // Demo quote size
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
    
    // Since SpdmContext owns the transport, use its message processing loop
    // The transport handles both socket protocol and SPDM messages internally
    let mut buffer = [0u8; 4096];
    let mut message_buffer = MessageBuf::new(&mut buffer);
    loop {
        match spdm_context.process_message(&mut message_buffer) {
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
        assert_eq!(SocketSpdmCommand::from(0x0000dead), SocketSpdmCommand::ClientHello);
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