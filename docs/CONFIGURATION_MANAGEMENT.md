# Configuration Management System

## Overview

Phantom Grid uses a **fully centralized configuration management system** where **ALL configuration is managed in Go code**, and eBPF C code is automatically generated. This eliminates configuration drift, reduces errors, and ensures consistency across the entire codebase.

**Key Principle:** Single Source of Truth - No manual C code editing required!

## Architecture

### Configuration Files (Go)

All configuration is defined in Go:

1. **`internal/config/config.go`**: Core constants
   - SPA configuration (magic port, token, duration)
   - Network ports (honeypot port, SSH port)
   - Output modes (dashboard, ELK, both)
   - ELK configuration

2. **`internal/config/ports.go`**: Port definitions
   - `CriticalPortDefinitions`: Ports protected by Phantom Protocol
   - `FakePortDefinitions`: Ports for honeypot deception
   - Port metadata (name, description, category, alias)

3. **`internal/config/constants.go`**: eBPF-specific constants
   - OS fingerprint TTL values
   - OS fingerprint window sizes
   - Egress DLP settings

### Code Generation

The configuration generator (`cmd/config-gen/main.go`) automatically generates:

1. **`internal/ebpf/programs/phantom_ports.h`**: Complete C header with:
   - Core ports (`HONEYPOT_PORT`, `SSH_PORT`)
   - SPA configuration (`SPA_MAGIC_PORT`, `SPA_SECRET_TOKEN`, etc.)
   - OS fingerprint values (`TTL_WINDOWS`, `TTL_LINUX`, etc.)
   - Window sizes (`WINDOW_WINDOWS`, `WINDOW_LINUX`, etc.)
   - All port definitions (critical and fake)
   - Egress DLP settings (`MAX_PAYLOAD_SCAN`)

2. **`internal/ebpf/programs/phantom_ports_functions.c`**: C functions:
   - `is_critical_asset_port()`: Checks if port requires SPA
   - `is_fake_port()`: Checks if port is a honeypot port

These generated files are included in all eBPF programs:
- `phantom.c` (XDP ingress)
- `phantom_spa.c` (SPA module)
- `phantom_egress.c` (TC egress DLP)

## Adding or Modifying Configuration

### Modifying Ports

**Step 1:** Edit `internal/config/ports.go`:

```go
var CriticalPortDefinitions = []PortDefinition{
    // ... existing ports ...
    {12345, "MyService", "My Custom Service", config.CategoryApplication, "MY_SERVICE_PORT"},
}
```

**Step 2:** Regenerate and rebuild:

```bash
make generate-config
make build
```

### Modifying Core Constants

**Step 1:** Edit `internal/config/config.go`:

```go
const (
    SPAMagicPort         = 1337
    SPASecretToken      = "YOUR_NEW_TOKEN"
    SPAWhitelistDuration = 60  // Change to 60 seconds
    HoneypotPort        = 9999
    SSHPort             = 22
)
```

**Step 2:** Regenerate and rebuild:

```bash
make generate-config
make build
```

### Modifying OS Fingerprint Values

**Step 1:** Edit `internal/config/constants.go`:

```go
func GetEBPFConstants() EBFPConstants {
    return EBFPConstants{
        // ... other constants ...
        TTLWindows: 128,  // Modify as needed
        TTLLinux:   64,
        WindowWindows: 65535,
        WindowLinux: 29200,
        // ...
    }
}
```

**Step 2:** Regenerate and rebuild:

```bash
make generate-config
make build
```

**Important:** Always run `make generate-config` after modifying any configuration in Go files. This ensures eBPF C code stays synchronized.

## Port Categories

Ports are organized by category for better maintainability:

- `CategoryCore`: Core services (SSH, etc.)
- `CategoryDatabase`: Database services
- `CategoryAdmin`: Admin panels and management interfaces
- `CategoryRemote`: Remote access protocols
- `CategoryContainer`: Container services (Docker, etc.)
- `CategoryApplication`: Application frameworks
- `CategoryDirectory`: Directory services (LDAP, etc.)
- `CategoryCache`: Cache services
- `CategoryFile`: File services (NFS, etc.)
- `CategoryMessaging`: Messaging protocols

## Generated Files

### `phantom_ports.h`

Contains **ALL** eBPF configuration constants:

```c
// Core Ports
#define HONEYPOT_PORT 9999
#define SSH_PORT 22

// SPA Configuration
#define SPA_MAGIC_PORT 1337
#define SPA_SECRET_TOKEN "PHANTOM_GRID_SPA_2025"
#define SPA_TOKEN_LEN 21
#define SPA_WHITELIST_DURATION_NS (30ULL * 1000000000ULL)

// OS Fingerprint Values (TTL)
#define TTL_WINDOWS 128
#define TTL_LINUX 64
#define TTL_FREEBSD 64
#define TTL_SOLARIS 255

// OS Fingerprint Values (Window Size)
#define WINDOW_WINDOWS 65535
#define WINDOW_LINUX 29200
#define WINDOW_FREEBSD 65535

// Egress DLP
#define MAX_PAYLOAD_SCAN 512

// Port Definitions
#define SSH_PORT 22  // SSH - Secure Shell
#define MYSQL_PORT 3306  // MySQL - MySQL Database
// ... all other ports
```

### `phantom_ports_functions.c`

Contains port checking functions:

```c
static __always_inline int is_critical_asset_port(__be16 port) {
    __u16 p = bpf_ntohs(port);
    
    // Core Services
    if (p == SSH_PORT) return 1;
    
    // Databases
    if (p == MYSQL_PORT) return 1;
    // ...
    
    return 0;
}

static __always_inline int is_fake_port(__be16 port) {
    __u16 p = bpf_ntohs(port);
    
    if (p == HTTP_PORT) return 1;
    // ... all fake ports
    
    return 0;
}
```

## Build Process

The build process automatically:

1. **Generate Config** (`make generate-config`): Creates eBPF C files from Go config
2. **Generate eBPF Bindings** (`go generate`): Creates Go bindings from eBPF C code
3. **Build Binaries** (`make build`): Compiles Go code with eBPF bindings

Full build:

```bash
make all
# or
make generate-config generate build
```

## Validation

The configuration system includes automatic validation:

- **Duplicate Detection**: Ensures no duplicate port numbers
- **Range Validation**: Verifies ports are in valid range (1-65535)
- **Consistency Checks**: Ensures Go config matches definitions
- **Alias Validation**: Verifies all ports have C macro aliases

Run validation:

```bash
go test ./internal/config
```

## Benefits

### 1. Single Source of Truth

- All configuration in Go code
- No manual synchronization required
- Reduced risk of configuration drift
- Easy to audit and review

### 2. Type Safety

- Port definitions are structured with metadata
- Compile-time validation
- Runtime consistency checks

### 3. Maintainability

- Easy to add/modify ports
- Automatic code generation
- Clear documentation in code
- No need to edit C code manually

### 4. Testing

- Automated validation tests
- Consistency verification
- Port range validation

### 5. Professional Quality

- Enterprise-grade configuration management
- Eliminates human error
- Scalable and maintainable

## Complete Configuration List

All configuration is managed in Go:

### Core Configuration (`internal/config/config.go`)
- `SPAMagicPort`: SPA magic packet port (default: 1337)
- `SPASecretToken`: SPA authentication token
- `SPATokenLen`: SPA token length
- `SPAWhitelistDuration`: SPA whitelist duration in seconds (default: 30)
- `HoneypotPort`: Honeypot fallback port (default: 9999)
- `SSHPort`: SSH port (default: 22)

### Port Definitions (`internal/config/ports.go`)
- `CriticalPortDefinitions`: All protected ports (SPA required) - 60+ ports
- `FakePortDefinitions`: All honeypot deception ports - 20+ ports

### eBPF Constants (`internal/config/constants.go`)
- OS fingerprint TTL values (Windows: 128, Linux: 64, FreeBSD: 64, Solaris: 255)
- OS fingerprint window sizes (Windows: 65535, Linux: 29200, FreeBSD: 65535)
- Egress DLP max payload scan size (default: 512)

**No C code editing required!** Everything is generated from Go configuration.

## Troubleshooting

### Port Not Being Protected

1. **Check Definition**: Verify port is in `CriticalPortDefinitions`
2. **Regenerate**: Run `make generate-config`
3. **Rebuild**: Run `make build`
4. **Verify Include**: Check eBPF files include `phantom_ports.h`

### Generation Errors

1. **Check Validation**: Run `go test ./internal/config`
2. **Check Duplicates**: Look for duplicate port numbers
3. **Check Aliases**: Ensure all ports have unique aliases
4. **Check Categories**: Verify category constants are correct

### Build Errors

1. **Clean Build**: Run `make clean` then `make all`
2. **Check Dependencies**: Ensure Go and clang are installed
3. **Check Permissions**: Ensure write permissions for generated files
4. **Check Generated Files**: Verify `phantom_ports.h` exists

## Best Practices

1. **Always Use Generator**: Never manually edit generated files
2. **Run Tests**: Always run validation tests after changes
3. **Document Changes**: Add comments explaining why configs are added
4. **Group by Category**: Keep related ports together
5. **Use Descriptive Names**: Make port names and descriptions clear
6. **Version Control**: Commit Go config files but ignore generated files
7. **Review Changes**: Review generated files in CI/CD pipeline

## Example: Adding a New Port

```go
// 1. Add to CriticalPortDefinitions in ports.go
{5433, "PostgreSQL Alt", "PostgreSQL Alternative Port", 
 CategoryDatabase, "POSTGRES_ALT_PORT"},

// 2. Run generator
make generate-config

// 3. Verify generated files
cat internal/ebpf/programs/phantom_ports.h | grep POSTGRES_ALT

// 4. Rebuild
make build

// 5. Test
make test
```

## Migration Notes

If upgrading from manual configuration:

1. **All constants moved to Go**: No more hardcoded values in C
2. **Generated files**: `phantom_ports.h` and `phantom_ports_functions.c` are auto-generated
3. **Include statements**: eBPF files now include generated header
4. **No manual edits**: Never edit generated files directly

## See Also

- [`internal/config/config.go`](../internal/config/config.go) - Core configuration
- [`internal/config/ports.go`](../internal/config/ports.go) - Port definitions
- [`internal/config/constants.go`](../internal/config/constants.go) - eBPF constants
- [`cmd/config-gen/main.go`](../cmd/config-gen/main.go) - Configuration generator
- [`docs/CONFIGURING_PORTS.md`](CONFIGURING_PORTS.md) - Port configuration guide
