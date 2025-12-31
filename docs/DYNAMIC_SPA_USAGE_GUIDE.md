# Dynamic Asymmetric SPA - Usage Guide

## Overview

Dynamic Asymmetric SPA provides enhanced security for Single Packet Authorization using:

- **TOTP (Time-based One-Time Password)**: Time-based nonce prevents replay attacks
- **Ed25519 Signature**: Asymmetric cryptography for authentication
- **Anti-Replay Protection**: LRU hash map tracks used signatures
- **Packet Obfuscation**: Binary format makes packets harder to detect

## Comparison with Static SPA

| Feature | Static SPA | Dynamic Asymmetric SPA |
|---------|------------|------------------------|
| Token | Fixed, never changes | Time-based (TOTP) |
| Security | Token can be leaked | Digital signature, cannot be forged |
| Replay Attack | Vulnerable | Protected by TOTP + replay map |
| Key Management | Shared secret | Public/Private key pair |

## Prerequisites

- **Server**: Linux with eBPF support (kernel >= 5.8)
- **Client**: Machine with Go or client binary
- **Network**: UDP port 1337 accessible between server and client

## Server Setup

### Step 1: Generate Keys

```bash
# Create keys directory
mkdir -p keys

# Generate Ed25519 key pair
go run ./cmd/spa-keygen -dir ./keys

# Output:
# Keys generated successfully!
# Public key:  ./keys/spa_public.key
# Private key: ./keys/spa_private.key
```

**Important**:
- `spa_public.key`: Keep on server (32 bytes)
- `spa_private.key`: Distribute to clients securely (64 bytes)
- Set permissions: `chmod 600 keys/spa_private.key`

### Step 2: Generate TOTP Secret

```bash
# Generate random TOTP secret (32 bytes)
openssl rand -base64 32 > keys/totp_secret.txt

# Or using Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))" > keys/totp_secret.txt

# View secret (save to share with clients)
cat keys/totp_secret.txt
```

**Note**: This secret must be the same on server and all clients.

### Step 3: Configure Server

#### Option A: Command Line Flags (Recommended)

```bash
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys \
  -spa-totp-secret "$(cat keys/totp_secret.txt)"
```

#### Option B: Environment Variables

```bash
export SPA_MODE=asymmetric
export SPA_KEY_DIR=./keys
export SPA_TOTP_SECRET="$(cat keys/totp_secret.txt)"

sudo ./bin/phantom-grid -interface ens33
```

#### Option C: Systemd Service

Create `/etc/systemd/system/phantom-grid.service`:

```ini
[Unit]
Description=Phantom Grid Security Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/phantom-grid
Environment="SPA_MODE=asymmetric"
Environment="SPA_KEY_DIR=/opt/phantom-grid/keys"
Environment="SPA_TOTP_SECRET=$(cat /opt/phantom-grid/keys/totp_secret.txt)"
ExecStart=/opt/phantom-grid/bin/phantom-grid -interface ens33
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable phantom-grid
sudo systemctl start phantom-grid
sudo systemctl status phantom-grid
```

### Step 4: Verify Server is Running

```bash
# View logs
sudo journalctl -u phantom-grid -f

# Or if running directly, check terminal output
```

Expected output:
```
[SPA] User-space handler started on port 1337
[SPA] Mode: asymmetric
[SYSTEM] XDP attached to interface: ens33
```

## Client Setup

### Step 1: Copy Private Key

**Secure Method**: Use SCP or encrypted transfer

```bash
# From client machine
scp user@server:/path/to/phantom-grid/keys/spa_private.key ./keys/

# Set permissions
chmod 600 keys/spa_private.key
```

### Step 2: Copy TOTP Secret

```bash
# From server
cat keys/totp_secret.txt

# Save to file on client
echo "your-totp-secret-here" > keys/totp_secret.txt
chmod 600 keys/totp_secret.txt
```

### Step 3: Create Client Application

#### Option A: Go Client

Create `client.go`:

```go
package main

import (
	"fmt"
	"log"
	"os"

	"phantom-grid/internal/config"
	"phantom-grid/pkg/spa"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: ./client <server-ip>")
	}
	serverIP := os.Args[1]

	// Load configuration
	spaConfig := config.DefaultDynamicSPAConfig()
	spaConfig.Mode = config.SPAModeAsymmetric

	// Load private key
	_, privateKey, err := config.LoadKeysFromFile("", "./keys/spa_private.key")
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}
	spaConfig.PrivateKey = privateKey

	// Load TOTP secret
	totpSecret, err := os.ReadFile("./keys/totp_secret.txt")
	if err != nil {
		log.Fatalf("Failed to load TOTP secret: %v", err)
	}
	// Remove newline if present
	if len(totpSecret) > 0 && totpSecret[len(totpSecret)-1] == '\n' {
		totpSecret = totpSecret[:len(totpSecret)-1]
	}
	spaConfig.TOTPSecret = totpSecret

	// Create client
	client, err := spa.NewDynamicClient(serverIP, spaConfig)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Send magic packet
	fmt.Printf("Sending SPA packet to %s...\n", serverIP)
	if err := client.SendMagicPacket(); err != nil {
		log.Fatalf("Failed to send packet: %v", err)
	}

	fmt.Println("SPA packet sent successfully!")
	fmt.Println("Your IP should now be whitelisted for 30 seconds.")
}
```

Build and run:

```bash
go build -o client client.go
./client 192.168.1.100
```

#### Option B: Using Example Client

```bash
# Use provided example
go run ./examples/spa-client-example.go \
  -server 192.168.1.100 \
  -mode asymmetric \
  -key-dir ./keys \
  -totp-secret "$(cat keys/totp_secret.txt)"
```

## Usage

### Basic Authentication Flow

1. **Client sends SPA packet**:
   ```bash
   ./client SERVER_IP
   ```

2. **Server verifies**:
   - TOTP nonce (time-based)
   - Ed25519 signature
   - Replay protection check

3. **IP whitelisted**:
   - Source IP added to whitelist
   - Valid for 30 seconds (configurable)
   - Protected ports become accessible

4. **Access protected services**:
   ```bash
   ssh user@SERVER_IP
   ```

### Testing

#### Test from External Machine

```bash
# 1. Verify SSH is blocked (before SPA)
ssh user@SERVER_IP
# Should timeout or be refused

# 2. Send SPA packet
./client SERVER_IP

# 3. SSH should now work (within 30 seconds)
ssh user@SERVER_IP
# Should connect successfully
```

#### Verify Server Logs

```bash
# Check authentication events
sudo journalctl -u phantom-grid | grep SPA

# Expected output:
# [SPA] Authentication successful from 192.168.1.100
# [SPA] IP whitelisted: 192.168.1.100
```

## Configuration Options

### TOTP Settings

```go
spaConfig.TOTPTimeStep = 60      // 60-second windows (default: 30)
spaConfig.TOTPTolerance = 2      // Allow ±2 steps (default: 1)
```

### Replay Protection

```go
spaConfig.ReplayWindowSeconds = 120  // 2-minute replay protection (default: 60)
```

### Packet Obfuscation

```go
spaConfig.EnableObfuscation = true   // Enable random padding (default: true)
```

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

### Server Not Receiving Packets

**Checklist**:
- Verify UDP port 1337 is not blocked by firewall
- Check server is listening: `sudo netstat -ulnp | grep 1337`
- Verify network connectivity: `ping SERVER_IP`
- Check server logs for errors

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

## Performance

- **Ed25519 Signing**: ~0.1ms per packet (client-side)
- **Ed25519 Verification**: ~0.2ms per packet (server-side)
- **TOTP Generation**: <0.01ms
- **Total Overhead**: <0.5ms per authentication

## See Also

- [`DYNAMIC_SPA.md`](DYNAMIC_SPA.md) - Technical implementation details
- [`MIGRATION_STATIC_TO_DYNAMIC_SPA.md`](MIGRATION_STATIC_TO_DYNAMIC_SPA.md) - Migration guide
- [`README.md`](../README.md) - Main project documentation
