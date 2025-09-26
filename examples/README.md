# SPDM Responder Examples

This directory contains example applications demonstrating how to use the SPDM Responder Library.

## Basic SPDM Responder (`spdm_responder.rs`)

A demonstration SPDM responder application that shows how to:
- Configure SPDM device capabilities and supported algorithms
- Set up CLI argument parsing for responder configuration
- Create a basic TCP server framework for SPDM communication
- Display the platform trait requirements for a complete implementation

### Usage

```bash
# Build the example
cargo build --example spdm_responder --features std,crypto

# Run with default settings
cargo run --example spdm_responder --features std,crypto

# Run with custom configuration
cargo run --example spdm_responder --features std,crypto -- --port 8080 --verbose

# See all options
cargo run --example spdm_responder --features std,crypto -- --help
```

### Command Line Options

- `-p, --port <PORT>`: TCP port to listen on (default: 2323)
- `-c, --cert <CERT_FILE>`: Path to certificate file (default: device_cert.pem)
- `-k, --key <KEY_FILE>`: Path to private key file (default: device_key.pem)
- `-m, --measurements <FILE>`: Path to measurements file (default: measurements.json)
- `-v, --verbose`: Enable verbose logging
- `-h, --help`: Print help message

### What This Example Shows

1. **Configuration Setup**: How to parse command line arguments and set up responder configuration
2. **SPDM Capabilities**: How to configure device capabilities using the `CapabilityFlags` bitfield
3. **Algorithm Support**: How to specify supported cryptographic algorithms
4. **Platform Requirements**: Clear documentation of what platform traits need to be implemented

### For a Complete Implementation

To create a working SPDM responder, you need to implement the following platform traits:

#### 1. Transport Layer (`SpdmTransport`)
```rust
// Example: TCP transport implementation
struct TcpTransport {
    stream: TcpStream,
}

impl SpdmTransport for TcpTransport {
    fn send(&mut self, buffer: &[u8]) -> Result<usize, SpdmError>;
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, SpdmError>;
}
```

#### 2. Cryptographic Hash (`SpdmHash`)
```rust
// Example: SHA-384 implementation
struct Sha384Hash {
    hasher: Sha384,
}

impl SpdmHash for Sha384Hash {
    fn hash_all(&mut self, data: &[u8]) -> Result<SpdmDigest, SpdmError>;
    fn hash_update(&mut self, data: &[u8]) -> Result<(), SpdmError>;
    fn hash_finalize(&mut self) -> Result<SpdmDigest, SpdmError>;
}
```

#### 3. Random Number Generation (`SpdmRng`)
```rust
// Example: System RNG implementation
struct SystemRng {
    rng: ThreadRng,
}

impl SpdmRng for SystemRng {
    fn get_random(&mut self, data: &mut [u8]) -> Result<usize, SpdmError>;
}
```

#### 4. Certificate Management (`SpdmCertStore`)
```rust
// Example: File-based certificate store
struct FileCertStore {
    cert_chain: Vec<u8>,
}

impl SpdmCertStore for FileCertStore {
    fn get_cert_via_cert_chain(&self, slot_id: u8) -> Result<&[u8], SpdmError>;
    fn verify_cert_chain(&self, cert_chain: &[u8]) -> Result<(), SpdmError>;
}
```

#### 5. Device Evidence/Measurements (`SpdmEvidence`)
```rust
// Example: Static measurements implementation
struct StaticEvidence {
    measurements: Vec<SpdmMeasurement>,
}

impl SpdmEvidence for StaticEvidence {
    fn get_measurement(&self, measurement_index: usize) -> Result<SpdmMeasurement, SpdmError>;
    fn get_measurement_count(&self) -> usize;
}
```

### Integration Example

```rust
use spdm_lib::context::SpdmContext;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize platform implementations
    let mut transport = TcpTransport::new("0.0.0.0:2323")?;
    let mut hash = Sha384Hash::new();
    let mut rng = SystemRng::new();
    let cert_store = FileCertStore::load("device_cert.pem")?;
    let evidence = StaticEvidence::load("measurements.json")?;
    
    // Configure SPDM context
    let supported_versions = vec![SpdmVersion::V12, SpdmVersion::V11];
    let capabilities = DeviceCapabilities::new()
        .with_cert_cap(true)
        .with_chal_cap(true)
        .with_meas_cap(MeasurementCapability::WithSignature)
        .with_fresh_cap(true)
        .with_chunk_cap(true)
        .with_data_transfer_size(1024)
        .with_max_spdm_msg_size(4096);
    
    let algorithms = create_local_algorithms();
    
    // Create SPDM context
    let mut spdm_context = SpdmContext::new(
        supported_versions,
        &mut transport,
        capabilities,
        algorithms,
        &mut cert_store,
        &mut hash,      // main hash
        &mut hash,      // m1 hash  
        &mut hash,      // l1 hash
        &mut rng,
        &evidence,
    )?;
    
    // Message processing loop
    let mut message_buffer = MessageBuf::new();
    loop {
        match spdm_context.process_message(&mut message_buffer) {
            Ok(()) => println!("Message processed successfully"),
            Err(e) => {
                eprintln!("SPDM Error: {:?}", e);
                // Handle error appropriately
            }
        }
    }
}
```

## Platform Implementation Examples

For reference platform implementations, see the `examples/platform/` directory which contains:

- `socket_transport.rs`: TCP socket transport implementation with DMTF protocol support
- `crypto.rs`: SHA-384 hash implementation and system RNG
- `cert_store.rs`: Certificate store with ECDSA signing
- `evidence.rs`: Demo device evidence/measurements
- `certs.rs`: Static OpenSSL-generated certificates

These provide working implementations that can serve as starting points for your own platform-specific code.

## Testing

The example includes basic unit tests:

```bash
cargo test --features std,crypto
```

## Protocol Support

This example demonstrates support for:
- SPDM versions 1.1 and 1.2
- SHA-384 hashing
- ECDSA P-384 signatures
- Certificate-based authentication
- Device measurements
- Chunked message transfer

## Security Notes

This is a demonstration example. For production use:
1. Implement proper certificate validation
2. Use secure random number generation
3. Validate all input messages
4. Implement proper error handling
5. Add appropriate logging and monitoring
6. Consider rate limiting and DoS protection

## Further Reading

- [SPDM Specification](https://www.dmtf.org/standards/spdm)
- [SPDM Library Documentation](../README.md)
- [Platform Implementation Guide](../docs/platform_implementation.md)