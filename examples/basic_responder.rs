// Licensed under the Apache-2.0 license

//! Basic SPDM Responder Application
//! 
//! This example demonstrates how to create a basic SPDM responder using the SPDM library.
//! The responder implements the SPDM protocol to handle authentication and measurement
//! requests from SPDM requesters.

use std::net::{TcpListener, TcpStream};
use std::thread;
use std::sync::Arc;
use std::io::{Read, Write};

use spdm_lib::context::SpdmContext;
use spdm_lib::protocol::version::SpdmVersion;
use spdm_lib::protocol::algorithms::*;
use spdm_lib::protocol::DeviceCapabilities;
use spdm_lib::codec::MessageBuf;
use spdm_lib::error::SpdmResult;
use spdm_lib::platform::transport::SpdmTransport;
use spdm_lib::platform::hash::SpdmHash;
use spdm_lib::platform::rng::SpdmRng;
use spdm_lib::platform::evidence::SpdmEvidence;
use spdm_lib::cert_store::SpdmCertStore;

// Import platform implementations
use spdm_lib::platform_impl::linux::{
    tcp::TcpTransport,
    rng::LinuxRng,
    evidence::LinuxEvidence,
    certs::LinuxCertStore,
};

/// Basic SPDM Responder Configuration
#[derive(Debug, Clone)]
pub struct ResponderConfig {
    /// TCP port to listen on
    pub port: u16,
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Device certificate chain path
    pub cert_chain_path: String,
    /// Device private key path
    pub private_key_path: String,
    /// Device measurements file path (optional)
    pub measurements_path: Option<String>,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            port: 2323,
            max_connections: 10,
            cert_chain_path: "device_cert_chain.pem".to_string(),
            private_key_path: "device_private_key.pem".to_string(),
            measurements_path: Some("device_measurements.json".to_string()),
        }
    }
}

/// SPDM Responder Application
pub struct SpdmResponder {
    config: ResponderConfig,
    listener: TcpListener,
}

impl SpdmResponder {
    /// Create a new SPDM Responder
    pub fn new(config: ResponderConfig) -> SpdmResult<Self> {
        let bind_addr = format!("0.0.0.0:{}", config.port);
        let listener = TcpListener::bind(&bind_addr)
            .map_err(|e| spdm_lib::error::SpdmError::Transport(
                spdm_lib::error::TransportError::IoError(format!("Failed to bind to {}: {}", bind_addr, e))
            ))?;

        println!("SPDM Responder listening on {}", bind_addr);

        Ok(Self {
            config,
            listener,
        })
    }

    /// Start the SPDM Responder server
    pub fn run(&self) -> SpdmResult<()> {
        println!("Starting SPDM Responder server...");
        println!("Configuration: {:?}", self.config);

        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    let config = self.config.clone();
                    thread::spawn(move || {
                        if let Err(e) = Self::handle_client(stream, config) {
                            eprintln!("Error handling client: {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Handle a single client connection
    fn handle_client(stream: TcpStream, config: ResponderConfig) -> SpdmResult<()> {
        println!("New client connected: {:?}", stream.peer_addr());

        // Initialize platform implementations
        let mut transport = TcpTransport::new(stream);
        let mut rng = LinuxRng::new()?;
        let mut cert_store = LinuxCertStore::new(&config.cert_chain_path, &config.private_key_path)?;
        let evidence = LinuxEvidence::new(config.measurements_path.as_deref())?;

        // Initialize hash contexts (SHA-384 for SPDM)
        let mut main_hash = spdm_lib::platform_impl::linux::hash::Sha384Hash::new();
        let mut m1_hash = spdm_lib::platform_impl::linux::hash::Sha384Hash::new();
        let mut l1_hash = spdm_lib::platform_impl::linux::hash::Sha384Hash::new();

        // Configure supported SPDM versions
        let supported_versions = &[
            SpdmVersion::V12,
            SpdmVersion::V11,
        ];

        // Configure device capabilities
        let local_capabilities = DeviceCapabilities {
            cache_cap: false,
            cert_cap: true,
            chal_cap: true,
            meas_cap_no_sig: false,
            meas_cap_sig: true,
            meas_fresh_cap: true,
            encrypt_cap: false,
            mac_cap: false,
            mut_auth_cap: false,
            key_ex_cap: false,
            psk_cap_requester: false,
            psk_cap_responder: false,
            encap_cap_requester: false,
            encap_cap_responder: false,
            hbeat_cap: false,
            key_upd_cap: false,
            handshake_in_the_clear_cap: false,
            pub_key_id_cap: false,
            chunk_cap: true,
            alias_cert_cap: false,
        
            // Data transfer capabilities
            ct_exponent: 0,
            flags: DeviceCapabilitiesFlags::empty(),
            data_transfer_size: 1024,
            max_spdm_msg_size: 4096,
        };

        // Configure supported algorithms
        let device_algorithms = DeviceAlgorithms {
            measurement_spec: MeasurementSpec::DMTF.into(),
            measurement_hash_algo: MeasurementHashAlgo::TPM_ALG_SHA_384.into(),
            base_asym_algo: BaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384.into(),
            base_hash_algo: BaseHashAlgo::TPM_ALG_SHA_384.into(),
            dhe_named_group: DheNamedGroup::empty(),
            aead_cipher_suite: AeadCipherSuite::empty(),
            req_base_asym_alg: BaseAsymAlgo::empty(),
            key_schedule: KeySchedule::empty(),
            other_params_support: OtherParamsSupport::empty(),
            mel_spec: MelSpec::empty(),
        };

        let algorithm_priority_table = AlgorithmPriorityTable::default();

        let local_algorithms = LocalDeviceAlgorithms {
            device_algorithms,
            algorithm_priority_table,
        };

        // Create SPDM context
        let mut spdm_context = SpdmContext::new(
            supported_versions,
            &mut transport,
            local_capabilities,
            local_algorithms,
            &mut cert_store,
            &mut main_hash,
            &mut m1_hash,
            &mut l1_hash,
            &mut rng,
            &evidence,
        )?;

        // Message processing loop
        let mut message_buffer = MessageBuf::new();
        loop {
            match spdm_context.process_message(&mut message_buffer) {
                Ok(()) => {
                    println!("Successfully processed SPDM message");
                }
                Err(e) => {
                    eprintln!("Error processing SPDM message: {:?}", e);
                    // Continue processing unless it's a fatal transport error
                    match &e {
                        spdm_lib::error::SpdmError::Transport(_) => {
                            println!("Transport error, closing connection");
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

        println!("Client connection closed");
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    // Parse command line arguments or use default configuration
    let config = ResponderConfig::default();

    // Create and run the SPDM Responder
    let responder = SpdmResponder::new(config)?;
    responder.run()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_responder_config_default() {
        let config = ResponderConfig::default();
        assert_eq!(config.port, 2323);
        assert_eq!(config.max_connections, 10);
        assert!(!config.cert_chain_path.is_empty());
        assert!(!config.private_key_path.is_empty());
    }

    #[test]
    fn test_responder_creation() {
        let mut config = ResponderConfig::default();
        config.port = 0; // Use any available port for testing
        
        let result = SpdmResponder::new(config);
        assert!(result.is_ok());
    }
}