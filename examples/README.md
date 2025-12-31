# Examples

## SPA Client Example

Simple command-line client for sending SPA packets.

### Usage

```bash
# Build
go build -o spa-client examples/spa-client-example.go

# Run
./spa-client -server 192.168.1.100

# With custom paths
./spa-client \
  -server 192.168.1.100 \
  -key ./my-keys/spa_private.key \
  -totp ./my-keys/totp_secret.txt
```

### Prerequisites

1. Private key file: `./keys/spa_private.key`
2. TOTP secret file: `./keys/totp_secret.txt`

See [`../docs/DYNAMIC_SPA_USAGE_GUIDE.md`](../docs/DYNAMIC_SPA_USAGE_GUIDE.md) for setup instructions.

