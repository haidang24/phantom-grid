# Dynamic Asymmetric SPA - Technical Documentation

## Overview

Dynamic Asymmetric SPA enhances Single Packet Authorization with:

1. **TOTP-based Nonce**: Time-based one-time password prevents replay attacks
2. **Ed25519 Signature**: Asymmetric cryptography for authentication
3. **Anti-Replay Protection**: LRU hash map tracks used signatures
4. **Packet Obfuscation**: Binary packet format makes SPA packets look like noise
5. **BPF Maps Configuration**: No hardcoded secrets - all config loaded from user-space

## Architecture

### Packet Format

```
+--------+------+----------+------+----------+----------+
| Version| Mode |Timestamp | TOTP | Padding  |Signature |
|  (1B)  | (1B) |  (8B)    | (4B) | (16-64B)| (32/64B) |
+--------+------+----------+------+----------+----------+
```

- **Version**: Protocol version (currently 1)
- **Mode**: 0=Static, 1=Dynamic (HMAC), 2=Asymmetric (Ed25519)
- **Timestamp**: Unix timestamp (8 bytes, big-endian)
- **TOTP**: Time-based one-time password (4 bytes, big-endian)
- **Padding**: Random data for obfuscation (16-64 bytes)
- **Signature**: HMAC-SHA256 (32 bytes) or Ed25519 (64 bytes)

## Security Features

### 1. TOTP Nonce
- Prevents replay attacks by using time-based nonce
- Configurable time step (default: 30 seconds)
- Tolerance window (default: ±1 step = ±30 seconds)

### 2. Ed25519 Signature
- Fast, secure asymmetric cryptography
- 64-byte signatures
- Public key stored in BPF map (no hardcoding)

### 3. Anti-Replay Protection
- LRU hash map tracks signature hashes
- Configurable replay window (default: 60 seconds)
- Automatic cleanup of old entries

### 4. Packet Obfuscation
- Random padding (16-64 bytes) makes packets look like noise
- Harder to detect by IDS/IPS systems
- Binary format instead of ASCII

## Modes

### Static Mode (Legacy)
- Backward compatible with existing deployments
- Uses hardcoded token from config
- No TOTP or signature

### Dynamic Mode (HMAC)
- TOTP + HMAC-SHA256
- Symmetric cryptography (shared secret)
- Faster than Ed25519 but requires secret distribution

### Asymmetric Mode (Recommended)
- TOTP + Ed25519 signature
- Asymmetric cryptography (public/private key)
- No secret distribution needed
- Best for enterprise deployments

## Configuration

### 1. Generate Keys

```bash
# Generate Ed25519 key pair
go run ./cmd/spa-keygen -dir ./keys

# This creates:
# - ./keys/spa_public.key  (32 bytes, server-side)
# - ./keys/spa_private.key (64 bytes, client-side)
```

### 2. Configure Server

```bash
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys \
  -spa-totp-secret "$(cat totp_secret.txt)"
```

### 3. Configure Client

```go
spaConfig := config.DefaultDynamicSPAConfig()
spaConfig.Mode = config.SPAModeAsymmetric

// Load private key
_, privateKey, err := config.LoadKeysFromFile("", "./keys/spa_private.key")
spaConfig.PrivateKey = privateKey

// Set TOTP secret (must match server)
spaConfig.TOTPSecret = []byte("your-shared-totp-secret-32-bytes")

// Create client
client, err := spa.NewDynamicClient("192.168.1.100", spaConfig)
if err != nil {
    log.Fatal(err)
}

// Send magic packet
err = client.SendMagicPacket()
```

## Implementation

### Components

- **`internal/spa/packet.go`**: Packet creation and parsing
- **`internal/spa/totp.go`**: TOTP generation and validation
- **`internal/spa/verifier.go`**: Packet verification logic
- **`internal/spa/handler.go`**: User-space SPA handler
- **`internal/spa/map_loader.go`**: BPF map loader
- **`pkg/spa/client_dynamic.go`**: Client implementation
- **`internal/ebpf/programs/phantom_spa_dynamic.c`**: eBPF verification program

### BPF Maps

- `spa_public_key`: Ed25519 public key (32 bytes)
- `spa_totp_secret`: TOTP shared secret (32 bytes)
- `spa_hmac_secret`: HMAC secret for dynamic mode (32 bytes)
- `spa_replay_protection`: LRU map for replay detection
- `spa_config`: SPA configuration (mode, time step, tolerance)

## Security Considerations

1. **Key Management**
   - Private keys must be kept secure (client-side only)
   - Public keys can be distributed freely
   - Use proper file permissions (0600 for private keys)

2. **TOTP Secret**
   - Must be shared securely between client and server
   - Use secure key exchange (e.g., out-of-band)
   - Consider using key derivation from master secret

3. **Replay Protection**
   - Replay window should be set based on network latency
   - Too small: legitimate packets may be rejected
   - Too large: increases memory usage

4. **Clock Synchronization**
   - TOTP requires synchronized clocks
   - Use NTP for time synchronization
   - Tolerance window compensates for small clock skew

## Performance

- **Ed25519 Signing**: ~0.1ms per packet
- **Ed25519 Verification**: ~0.2ms per packet
- **TOTP Generation**: <0.01ms
- **HMAC-SHA256**: <0.01ms
- **BPF Map Lookup**: <0.001ms

## Migration from Static SPA

See [`MIGRATION_STATIC_TO_DYNAMIC_SPA.md`](MIGRATION_STATIC_TO_DYNAMIC_SPA.md) for complete migration guide.

## Troubleshooting

### "Invalid TOTP"
- Check clock synchronization (NTP)
- Verify TOTP secret matches on both sides
- Check tolerance window setting

### "Invalid signature"
- Verify public/private key pair
- Check key file permissions
- Ensure correct mode (asymmetric vs dynamic)

### "Replay detected"
- Normal if packet is resent too quickly
- Check replay window setting
- Verify packet is not being duplicated

## See Also

- [`DYNAMIC_SPA_USAGE_GUIDE.md`](DYNAMIC_SPA_USAGE_GUIDE.md) - Complete usage guide
- [`MIGRATION_STATIC_TO_DYNAMIC_SPA.md`](MIGRATION_STATIC_TO_DYNAMIC_SPA.md) - Migration guide
- [`internal/config/spa.go`](../internal/config/spa.go) - Configuration
- [`internal/spa/packet.go`](../internal/spa/packet.go) - Packet creation/parsing
- [`pkg/spa/client_dynamic.go`](../pkg/spa/client_dynamic.go) - Client implementation
