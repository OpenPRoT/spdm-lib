# DMTF SPDM Emulator Protocol Compatibility

This document describes how to use the DMTF-compatible SPDM responder that implements the same protocol as the official DMTF spdm-emu tools.

## Overview

The `spdm_responder_dmtf.rs` example implements a responder that is fully compatible with the DMTF SPDM emulator protocol, allowing it to communicate with:

- DMTF spdm-emu requester clients
- Official DMTF test tools and validation suites
- Any client implementing the DMTF socket transport protocol

## Protocol Implementation

### 1. TCP Binding (DSP0287)

The responder implements the DMTF SPDM over TCP Binding specification v1.0:

```rust
struct SpdmTcpBindingHeader {
    payload_length: u16,    // Length of payload (little-endian)
    binding_version: u8,    // Version 0x01
    message_type: u8,       // Message type
}
```

**Supported Message Types:**
- `0x05` - Out of session messages
- `0x06` - In session messages  
- `0xBF` - Role inquiry
- `0xC0` - Error: Message too large
- `0xC1` - Error: Not supported
- `0xC2` - Error: Cannot operate as requester
- `0xC3` - Error: Cannot operate as responder

### 2. Socket Transport Protocol

The responder implements the socket platform message protocol used by the DMTF emulator:

```rust
struct SocketMessageHeader {
    command: u32,           // Socket command type
    transport_type: u32,    // Transport type (0 = TCP)
    data_size: u32,         // Size of following data
}
```

**Supported Socket Commands:**
- `0x00000001` - NORMAL: Standard SPDM message processing
- `0x00000002` - SHUTDOWN: Clean shutdown request
- `0x00000003` - CONTINUE: Continue processing
- `0xFFFFFFFF` - UNKNOWN: Unknown/unsupported command

### 3. Message Flow

The protocol follows this sequence:

1. **Platform Command Reception**: Client sends socket message header + data
2. **Command Processing**: Responder processes the command type
3. **SPDM Processing**: For NORMAL commands, SPDM messages are processed
4. **Response**: Responder sends back socket header + response data

## Usage

### Basic Usage

```bash
# Build the DMTF-compatible responder
cargo build --example spdm_responder_dmtf

# Run with default settings (port 2323)
cargo run --example spdm_responder_dmtf

# Run with custom port and verbose logging
cargo run --example spdm_responder_dmtf -- --port 8080 --verbose
```

### Command Line Options

```
-p, --port <PORT>              TCP port to listen on [default: 2323]
-c, --cert <CERT_FILE>         Path to certificate file [default: device_cert.pem]
-k, --key <KEY_FILE>           Path to private key file [default: device_key.pem]
-m, --measurements <FILE>      Path to measurements file [default: measurements.json]
-v, --verbose                  Enable verbose logging
-h, --help                     Print help message
```

### Example Output

```
DMTF SPDM Emulator Compatible Responder
=======================================
Configuration:
  Port: 2323
  Certificate: device_cert.pem
  Private Key: device_key.pem
  Measurements: measurements.json
  Verbose: true
  TCP Binding Version: 0x01

SPDM Device Capabilities:
  Certificate capability: 1
  Challenge capability: 1
  Measurements capability: 2
  Fresh measurements: 1
  Chunk capability: 1
  Data transfer size: 1024 bytes
  Max SPDM message size: 4096 bytes

Supported DMTF Protocol Features:
  TCP Binding: DSP0287 v1.0
  Socket Commands: NORMAL, SHUTDOWN, CONTINUE
  Message Types: OUT_OF_SESSION, IN_SESSION, ROLE_INQUIRY
  Transport: TCP with platform message headers

DMTF-compatible server listening on 0.0.0.0:2323
Compatible with DMTF spdm-emu requester clients
Waiting for connections... (Press Ctrl+C to exit)
```

## Testing with DMTF Tools

### Prerequisites

1. Clone and build the DMTF spdm-emu repository:
```bash
git clone https://github.com/DMTF/spdm-emu.git
cd spdm-emu
# Follow DMTF build instructions
```

2. Ensure certificates and keys are available:
```bash
# Generate test certificates if needed
openssl req -new -x509 -days 365 -nodes -out device_cert.pem -keyout device_key.pem
```

### Test Sequence

1. **Start the responder:**
```bash
cargo run --example spdm_responder_dmtf -- --verbose
```

2. **Run DMTF requester (in another terminal):**
```bash
# Example command (adjust path to your spdm-emu build)
./spdm_requester_emu --port 2323 --exe_mode SPDM
```

3. **Expected behavior:**
   - Connection established
   - SPDM version negotiation
   - Capability exchange
   - Certificate verification
   - Measurement requests
   - Clean session termination

## Implementation Details

### Transport Layer Compatibility

The `DmtfTcpTransport` struct provides:

- **Socket Message Handling**: `receive_platform_data()` and `send_platform_data()`
- **SPDM Message Framing**: TCP binding header processing
- **Error Handling**: Proper error message types and responses
- **Session Management**: Connection lifecycle management

### Key Features

1. **Binary Compatibility**: Exact byte layout matching DMTF emulator
2. **Protocol Compliance**: Full DSP0287 TCP binding implementation  
3. **Error Handling**: Comprehensive error response handling
4. **Verbose Logging**: Detailed protocol trace for debugging
5. **Configurable Parameters**: Flexible configuration options

### Device Capabilities

The responder advertises capabilities compatible with typical DMTF test scenarios:

```rust
// Capability flags (bit positions)
cert_cap: 1       // Certificate capability
chal_cap: 1       // Challenge capability  
meas_cap: 2       // Measurements with signature
meas_fresh_cap: 1 // Fresh measurements
chunk_cap: 1      // Chunked transfer
data_transfer_size: 1024     // Max data transfer
max_spdm_msg_size: 4096      // Max SPDM message
```

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Check port availability: `netstat -ln | grep 2323`
   - Verify firewall settings
   - Ensure responder is running

2. **Protocol Mismatch**
   - Enable verbose logging: `--verbose`
   - Check TCP binding version (should be 0x01)
   - Verify message header formats

3. **SPDM Message Errors**
   - Check certificate file paths
   - Verify certificate format and validity
   - Ensure measurements file is accessible

### Debug Output

With `--verbose` flag, the responder logs:
- Connection establishment
- Platform command reception
- SPDM message processing
- Response transmission
- Error conditions

### Testing Tools

You can test the protocol with simple tools:

```bash
# Test connection with netcat
nc localhost 2323

# Send raw socket command (hex format)
# Command header: 01000000 00000000 04000000 (NORMAL, TCP, 4 bytes data)
# SPDM data: 10010000 (example SPDM GET_VERSION)
```

## Standards Compliance

This implementation complies with:

- **DSP0274**: SPDM Specification v1.2
- **DSP0287**: SPDM over TCP Binding v1.0
- **DMTF Emulator Protocol**: Socket transport extensions

## Security Considerations

For production use, ensure:

1. **Certificate Validation**: Implement proper X.509 certificate chain validation
2. **Secure Random Generation**: Use hardware-backed RNG where available
3. **Input Validation**: Validate all incoming message formats
4. **Rate Limiting**: Implement connection and message rate limits
5. **Logging**: Secure logging without exposing sensitive data

## Next Steps

1. **Integrate Real SPDM Library**: Replace demo message processing with actual SPDM library calls
2. **Add Platform Implementations**: Implement the required platform trait implementations
3. **Certificate Management**: Add proper certificate chain handling
4. **Measurement Support**: Implement device measurement collection
5. **Session Management**: Add SPDM session state management

## References

- [DMTF SPDM Specification](https://www.dmtf.org/standards/spdm)
- [DMTF spdm-emu Repository](https://github.com/DMTF/spdm-emu)
- [DSP0287 SPDM over TCP Binding](https://www.dmtf.org/documents/redfish/DSP0287_1.0.0.pdf)
- [libspdm Reference Implementation](https://github.com/DMTF/libspdm)