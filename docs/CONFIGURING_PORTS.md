# Configuring Protected Ports

## Overview

Phantom Grid protects critical ports using the **Phantom Protocol** - a zero-trust access control mechanism that requires Single Packet Authorization (SPA) before allowing access. All traffic to protected ports is **DROPPED** unless the source IP has been whitelisted via SPA Magic Packet.

## Current Protected Ports

The following ports are currently protected by default:

### Core Services
- **22** - SSH (Secure Shell)

### Databases
- **3306** - MySQL
- **5432** - PostgreSQL
- **5433** - PostgreSQL (Alternative)
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
- **15672** - RabbitMQ Management
- **5984** - CouchDB

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

### Cache Services
- **11211** - Memcached

### File Services
- **2049** - NFS

## How to Add More Protected Ports

To add a new port to the protected list, you need to update **two files**:

### Step 1: Update Go Config (`internal/config/config.go`)

Add your port to the `CriticalPorts` slice:

```go
var CriticalPorts = []int{
    // ... existing ports ...
    5432,   // PostgreSQL
    12345,  // Your new port
}
```

### Step 2: Update eBPF Program (`internal/ebpf/programs/phantom.c`)

#### 2a. Add Port Definition

Add a `#define` for your port at the top of the file (around line 24):

```c
#define YOUR_SERVICE_PORT 12345
```

#### 2b. Add Port Check

Update the `is_critical_asset_port()` function (around line 153) to include your port:

```c
static __always_inline int is_critical_asset_port(__be16 port) {
    __u16 p = bpf_ntohs(port);
    
    // ... existing checks ...
    
    // Your new service
    if (p == YOUR_SERVICE_PORT) return 1;
    
    return 0;
}
```

### Step 3: Rebuild

After making changes, rebuild the project:

```bash
make clean
make generate
make build
```

**Important:** You must rebuild the eBPF programs (`make generate`) for changes to take effect.

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

**That's it!** The eBPF C code is automatically generated. No manual C editing required.

## Port Categories

When adding ports, consider which category they belong to:

- **Core Services**: SSH, Telnet, etc.
- **Databases**: MySQL, PostgreSQL, MongoDB, Redis, etc.
- **Admin Panels**: Web-based management interfaces
- **Remote Access**: RDP, VNC, WinRM, etc.
- **Container Services**: Docker, Kubernetes, etc.
- **Directory Services**: LDAP, Active Directory, etc.
- **Cache Services**: Memcached, Redis (if used as cache)
- **File Services**: NFS, SMB, etc.

Grouping ports by category helps maintain code organization.

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

## Important Notes

1. **eBPF Limitations**: The `is_critical_asset_port()` function uses multiple `if` statements. While eBPF can handle many comparisons, extremely long functions may fail verification. If you encounter verification errors, consider grouping ports more efficiently.

2. **Performance**: Each port check adds a small overhead. For best performance, order checks from most common to least common.

3. **Port Conflicts**: If a port is both in `CriticalPorts` and `FakePorts`, the critical port protection takes priority (SPA required).

4. **Documentation**: Always document why a port is being protected in comments.

## Removing Protected Ports

To remove a port from protection:

1. Remove from `CriticalPorts` in `internal/config/config.go`
2. Remove the `#define` and check from `internal/ebpf/programs/phantom.c`
3. Rebuild with `make clean && make generate && make build`

## Troubleshooting

### Port Not Being Protected

1. **Check eBPF compilation**: Ensure `make generate` completed without errors
2. **Verify port number**: Check that port number matches in both files
3. **Check function logic**: Ensure the port check is correctly added to `is_critical_asset_port()`
4. **Rebuild**: Always rebuild after changes

### eBPF Verification Error

If you get an eBPF verification error when adding many ports:

1. **Group ports**: Use `||` operators to group multiple ports in one check
2. **Simplify logic**: Break complex checks into simpler ones
3. **Check limits**: eBPF has limits on instruction count - too many ports may exceed this

### Port Still Accessible Without SPA

1. **Check XDP attachment**: Ensure XDP is attached to the correct interface
2. **Verify eBPF program**: Check that the new eBPF program was loaded
3. **Test from external IP**: Test from a different machine, not localhost
4. **Check logs**: Look for XDP drop messages in system logs

## Best Practices

1. **Document all changes**: Add comments explaining why ports are protected
2. **Test thoroughly**: Always test after adding ports
3. **Keep lists synchronized**: Ensure `CriticalPorts` and eBPF checks match
4. **Group related ports**: Keep related ports together in code
5. **Review regularly**: Periodically review protected ports list

## See Also

- [`internal/config/config.go`](../internal/config/config.go) - Core configuration
- [`internal/config/ports.go`](../internal/config/ports.go) - Port definitions (single source of truth)
- [`internal/config/constants.go`](../internal/config/constants.go) - eBPF constants
- [`docs/CONFIGURATION_MANAGEMENT.md`](CONFIGURATION_MANAGEMENT.md) - Complete configuration management guide
- [`README.md`](../README.md) - Main documentation

