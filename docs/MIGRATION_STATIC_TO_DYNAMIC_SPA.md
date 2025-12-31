# Migration Guide: Static to Dynamic SPA

This guide helps you migrate from static SPA (legacy) to dynamic asymmetric SPA.

## Overview

**Static SPA** uses a hardcoded token that never changes.  
**Dynamic SPA** uses TOTP + Ed25519 signatures for enhanced security.

## Benefits of Migration

1. **Replay Attack Protection**: TOTP nonce prevents packet replay
2. **Asymmetric Cryptography**: No shared secret distribution needed
3. **Key Rotation**: Easy to rotate keys without code changes
4. **Packet Obfuscation**: Binary format makes packets harder to detect
5. **Anti-Replay**: Automatic detection and blocking of replay attacks

## Prerequisites

- Phantom Grid agent running with static SPA
- Access to server and client machines
- Ability to generate and distribute keys

## Migration Steps

### Step 1: Generate Keys

On the server machine:

```bash
# Generate Ed25519 key pair
go run ./cmd/spa-keygen -dir ./keys

# This creates:
# - ./keys/spa_public.key  (32 bytes, keep on server)
# - ./keys/spa_private.key (64 bytes, distribute to clients)
```

**Security Note**: 
- Public key stays on server
- Private key must be distributed securely to clients
- Use secure channels (SSH, encrypted email, etc.)

### Step 2: Distribute Private Keys to Clients

For each client that needs access:

```bash
# Copy private key to client (use secure method)
scp ./keys/spa_private.key user@client:/path/to/keys/

# Set proper permissions
chmod 600 /path/to/keys/spa_private.key
```

### Step 3: Configure TOTP Secret

Generate a shared TOTP secret (32 bytes):

```bash
# Generate random secret
openssl rand -base64 32 > totp_secret.txt

# Distribute to both server and clients securely
```

**Important**: The TOTP secret must be the same on server and all clients.

### Step 4: Update Server Configuration

#### Option A: Command Line Flags

```bash
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys \
  -spa-totp-secret "$(cat totp_secret.txt)"
```

#### Option B: Environment Variables

```bash
export SPA_MODE=asymmetric
export SPA_KEY_DIR=./keys
export SPA_TOTP_SECRET="$(cat totp_secret.txt)"

sudo ./bin/phantom-grid -interface ens33
```

#### Option C: Configuration File (Future)

Edit `internal/config/spa.go` or create a config file (if implemented).

### Step 5: Update Client Code

Update your client applications to use `DynamicClient`:

```go
package main

import (
    "phantom-grid/internal/config"
    "phantom-grid/pkg/spa"
)

func main() {
    // Load configuration
    spaConfig := config.DefaultDynamicSPAConfig()
    spaConfig.Mode = config.SPAModeAsymmetric
    
    // Load private key
    _, privateKey, err := config.LoadKeysFromFile("", "./keys/spa_private.key")
    if err != nil {
        log.Fatal(err)
    }
    spaConfig.PrivateKey = privateKey
    
    // Load TOTP secret (must match server)
    totpSecret, err := os.ReadFile("totp_secret.txt")
    if err != nil {
        log.Fatal(err)
    }
    spaConfig.TOTPSecret = totpSecret
    
    // Create client
    client, err := spa.NewDynamicClient("192.168.1.100", spaConfig)
    if err != nil {
        log.Fatal(err)
    }
    
    // Send magic packet
    if err := client.SendMagicPacket(); err != nil {
        log.Fatal(err)
    }
    
    fmt.Println("SPA packet sent successfully!")
}
```

### Step 6: Test Migration

1. **Start server with dynamic SPA**:
   ```bash
   sudo ./bin/phantom-grid -interface ens33 -spa-mode asymmetric
   ```

2. **Send test packet from client**:
   ```bash
   go run ./cmd/spa-client -server 192.168.1.100
   ```

3. **Verify whitelisting**:
   - Check server logs for successful authentication
   - Try connecting to protected port (SSH, etc.)
   - Should work without additional SPA packet

### Step 7: Monitor and Validate

- Check server logs for authentication events
- Monitor for any failed authentication attempts
- Verify TOTP validation is working (check timestamps)
- Test replay protection (resend same packet - should be blocked)

## Rollback Plan

If you need to rollback to static SPA:

1. **Stop dynamic SPA server**
2. **Restart with static mode**:
   ```bash
   sudo ./bin/phantom-grid -interface ens33 -spa-mode static
   ```
3. **Update clients** to use static token

## Troubleshooting

### "Invalid TOTP"

**Cause**: Clock synchronization issue or wrong secret

**Solution**:
- Check NTP synchronization: `ntpdate -q pool.ntp.org`
- Verify TOTP secret matches on both sides
- Increase tolerance window if needed

### "Invalid signature"

**Cause**: Wrong key pair or corrupted key file

**Solution**:
- Verify public/private key pair match
- Regenerate keys if needed
- Check file permissions (private key should be 600)

### "Replay detected"

**Cause**: Packet was sent multiple times too quickly

**Solution**:
- This is normal behavior (security feature)
- Wait for replay window to expire
- Check replay window setting

### "Failed to load keys"

**Cause**: Key file not found or wrong path

**Solution**:
- Verify key file paths
- Check file permissions
- Ensure keys are in correct format (32/64 bytes)

## Performance Considerations

- **Ed25519 Signing**: ~0.1ms per packet (client-side)
- **Ed25519 Verification**: ~0.2ms per packet (server-side)
- **TOTP Generation**: <0.01ms
- **Total Overhead**: <0.5ms per authentication

## Security Best Practices

1. **Key Management**:
   - Store private keys securely (encrypted at rest)
   - Use key rotation schedule
   - Revoke compromised keys immediately

2. **TOTP Secret**:
   - Generate strong random secret (32 bytes)
   - Distribute securely
   - Rotate periodically

3. **Network Security**:
   - Use encrypted channels for key distribution
   - Monitor authentication logs
   - Set up alerts for failed attempts

4. **Access Control**:
   - Limit who has access to private keys
   - Use least privilege principle
   - Audit key usage

## Advanced Configuration

### Custom TOTP Settings

```go
spaConfig.TOTPTimeStep = 60      // 60-second windows
spaConfig.TOTPTolerance = 2      // Allow ±2 steps (±120s)
```

### Custom Replay Window

```go
spaConfig.ReplayWindowSeconds = 120  // 2-minute replay protection
```

### Disable Obfuscation

```go
spaConfig.EnableObfuscation = false  // Disable random padding
```

## Testing Checklist

- [ ] Keys generated successfully
- [ ] Private keys distributed to clients
- [ ] TOTP secret configured on server and clients
- [ ] Server starts with dynamic SPA mode
- [ ] Client can send magic packet
- [ ] Server verifies and whitelists IP
- [ ] Protected ports accessible after authentication
- [ ] Replay protection working (resend blocked)
- [ ] TOTP validation working (time-based)
- [ ] Signature verification working
- [ ] Logs show successful authentication
- [ ] Performance acceptable (<1ms overhead)

## Support

For issues or questions:
- Check logs: `tail -f logs/audit.json`
- Review documentation: `docs/DYNAMIC_SPA.md`
- Open issue on GitHub

## See Also

- [`docs/DYNAMIC_SPA.md`](DYNAMIC_SPA.md) - Complete Dynamic SPA documentation
- [`internal/config/spa.go`](../internal/config/spa.go) - Configuration
- [`pkg/spa/client_dynamic.go`](../pkg/spa/client_dynamic.go) - Client implementation

