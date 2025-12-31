# Configuring Protected Ports

## Overview

Phantom Grid protects critical ports using the **Phantom Protocol** - a zero-trust access control mechanism that requires Single Packet Authorization (SPA) before allowing access. All traffic to protected ports is **DROPPED** unless the source IP has been whitelisted via SPA Magic Packet.

## Current Protected Ports

Phantom Grid protects 60+ critical ports by default, including:

### Core Services
- **22** - SSH (Secure Shell)

### Databases
- **3306** - MySQL
- **5432** - PostgreSQL
- **27017** - MongoDB
- **6379** - Redis
- **1433** - MSSQL Server
- **1521** - Oracle Database

### Admin Panels & Management
- **8080** - HTTP Admin Panel / Proxy
- **8443** - HTTPS Admin Panel
- **9000** - Admin Panel / Portainer
- **9200** - Elasticsearch
- **5601** - Kibana
- **3000** - Grafana / Node.js
- **9090** - Prometheus

### Remote Access
- **3389** - RDP (Windows Remote Desktop)
- **5985** - WinRM HTTP
- **5986** - WinRM HTTPS

### Container Services
- **2375** - Docker (unencrypted)
- **2376** - Docker (TLS)

### Directory Services
- **389** - LDAP
- **636** - LDAP (SSL)

See [`internal/config/ports.go`](../internal/config/ports.go) for the complete list.

## Adding Protected Ports

Phantom Grid uses a **centralized configuration system**. All port definitions are managed in Go code, and eBPF C code is automatically generated.

### Step 1: Update Port Definitions

Edit `internal/config/ports.go`:

```go
var CriticalPortDefinitions = []PortDefinition{
    // ... existing ports ...
    {12345, "MyService", "My Custom Service", config.CategoryApplication, "MY_SERVICE_PORT"},
}
```

### Step 2: Regenerate and Rebuild

```bash
make generate-config
make build
```

**That's it!** The eBPF C code is automatically generated. No manual C editing required.

## Example: Adding Port 5433 (PostgreSQL Alternative)

### 1. Update `internal/config/ports.go`:

```go
var CriticalPortDefinitions = []PortDefinition{
    // ... existing ports ...
    {5432, "PostgreSQL", "PostgreSQL Database", config.CategoryDatabase, "POSTGRES_PORT"},
    {5433, "PostgreSQL Alt", "PostgreSQL Alternative Port", config.CategoryDatabase, "POSTGRES_ALT_PORT"},
}
```

### 2. Regenerate and Rebuild:

```bash
make generate-config
make build
sudo ./bin/phantom-grid -interface ens33
```

## Port Categories

When adding ports, consider which category they belong to:

- **CategoryCore**: Core services (SSH, Telnet, etc.)
- **CategoryDatabase**: Database services
- **CategoryAdmin**: Admin panels and management interfaces
- **CategoryRemote**: Remote access protocols
- **CategoryContainer**: Container services (Docker, etc.)
- **CategoryApplication**: Application frameworks
- **CategoryDirectory**: Directory services (LDAP, etc.)
- **CategoryCache**: Cache services
- **CategoryFile**: File services (NFS, etc.)

## Testing Protected Ports

After adding a port, test that it's properly protected:

1. **Without SPA whitelist** (should be blocked):
   ```bash
   # From external machine
   nc TARGET_IP 12345
   # Connection should timeout or be refused
   ```

2. **With SPA whitelist** (should work):
   ```bash
   # Send Magic Packet
   ./bin/spa-client TARGET_IP
   
   # Now connection should work
   nc TARGET_IP 12345
   ```

## Removing Protected Ports

To remove a port from protection:

1. Remove from `CriticalPortDefinitions` in `internal/config/ports.go`
2. Regenerate and rebuild:
   ```bash
   make generate-config
   make build
   ```

## Troubleshooting

### Port Not Being Protected

1. **Check Definition**: Verify port is in `CriticalPortDefinitions`
2. **Regenerate**: Run `make generate-config`
3. **Rebuild**: Run `make build`
4. **Verify Include**: Check eBPF files include `phantom_ports.h`

### Port Still Accessible Without SPA

1. **Check XDP attachment**: Ensure XDP is attached to the correct interface
2. **Verify eBPF program**: Check that the new eBPF program was loaded
3. **Test from external IP**: Test from a different machine, not localhost
4. **Check logs**: Look for XDP drop messages in system logs

## Best Practices

1. **Document all changes**: Add comments explaining why ports are protected
2. **Test thoroughly**: Always test after adding ports
3. **Group related ports**: Keep related ports together in code
4. **Review regularly**: Periodically review protected ports list

## See Also

- [`CONFIGURATION_MANAGEMENT.md`](CONFIGURATION_MANAGEMENT.md) - Complete configuration management guide
- [`internal/config/ports.go`](../internal/config/ports.go) - Port definitions (single source of truth)
- [`README.md`](../README.md) - Main documentation
