# Phantom Grid

> "The best defense is not just blocking – it is confusing, deceiving, and recording."

**Phantom Grid** is a kernel-level active defense system built on **eBPF/XDP** that transforms Linux servers into a controlled, deceptive attack surface. It provides enterprise-grade security through deception, zero-trust access control, and real-time threat intelligence.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org/)
[![Linux Kernel](https://img.shields.io/badge/Kernel-5.4+-blue)](https://www.kernel.org/)

## Features

### Core Defense Mechanisms

- **The Phantom Protocol** - Critical services invisible by default, requiring Single Packet Authorization (SPA) for access
- **The Mirage** - Randomized fake services to confuse reconnaissance tools
- **The Portal** - Transparent redirection of suspicious traffic to honeypots

### Advanced Capabilities

- **Dynamic Asymmetric SPA** - Zero-trust access control with TOTP and Ed25519 signatures
- **Stealth Scan Detection** - Kernel-level detection and dropping of malicious scans
- **OS Personality Mutation** - Real-time OS fingerprint spoofing
- **Egress Containment (DLP)** - Kernel-level data loss prevention
- **Real-Time Dashboard** - Terminal-based forensics and threat visualization
- **ELK Integration** - Export events to Elasticsearch for centralized analysis

## Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- **Kernel**: 5.4+ (eBPF/XDP support)
- **Go**: 1.21+
- **Build Tools**: `clang`, `llvm`, `libbpf-dev`, `make`

### Quick Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update && sudo apt install -y clang llvm libbpf-dev golang-go make git
```

**CentOS/RHEL:**
```bash
sudo yum install -y clang llvm libbpf-devel golang make git
```

## Quick Start

### 1. Clone and Build

```bash
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid
go mod tidy
make build
```

### 2. Run Phantom Grid

```bash
# List network interfaces
ip link show

# Run with specific interface (recommended)
sudo ./bin/phantom-grid -interface ens33
```

### 3. Authenticate with SPA

From another machine:

```bash
./bin/spa-client SERVER_IP
```

You now have 30 seconds to access protected services (e.g., SSH).

## Installation

### From Source

```bash
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid
go mod tidy
make build
```

Binaries will be in `bin/`:
- `bin/phantom-grid` - Main agent
- `bin/spa-client` - SPA authentication client

### Docker

```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f
```

See [`docs/DOCKER.md`](docs/DOCKER.md) for detailed Docker deployment.

## Usage

### Basic Usage

```bash
# Show help
sudo ./bin/phantom-grid -h

# Run with auto-detected interface (testing only)
sudo ./bin/phantom-grid

# Run with specific interface (recommended)
sudo ./bin/phantom-grid -interface INTERFACE_NAME
```

### Output Modes

**Dashboard Only (Default):**
```bash
sudo ./bin/phantom-grid -interface ens33 -output dashboard
```

**ELK Only:**
```bash
sudo ./bin/phantom-grid -interface ens33 -output elk \
  -elk-address http://localhost:9200 \
  -elk-index phantom-grid
```

**Both Dashboard and ELK:**
```bash
sudo ./bin/phantom-grid -interface ens33 -output both \
  -elk-address http://localhost:9200 \
  -elk-index phantom-grid
```

### Command Line Options

```bash
Options:
  -interface string       Network interface name (required for production)
  -output string          Output mode: 'dashboard', 'elk', or 'both' (default: "dashboard")
  -elk-address string     Elasticsearch address (default: "http://localhost:9200")
  -elk-index string       Elasticsearch index name (default: "phantom-grid")
  -elk-user string        Elasticsearch username (optional)
  -elk-pass string        Elasticsearch password (optional)
  -elk-tls                Enable TLS for Elasticsearch
  -elk-skip-verify        Skip TLS certificate verification (testing only)
  -h, -help               Show help message
```

## Configuration

### Protected Ports

Phantom Grid protects 60+ critical ports by default (SSH, databases, admin panels). See [`docs/CONFIGURING_PORTS.md`](docs/CONFIGURING_PORTS.md) for configuration details.

### Dynamic SPA

For advanced Single Packet Authorization with TOTP and Ed25519, see:
- [`docs/DYNAMIC_SPA_USAGE_GUIDE.md`](docs/DYNAMIC_SPA_USAGE_GUIDE.md) - Complete usage guide
- [`docs/MIGRATION_STATIC_TO_DYNAMIC_SPA.md`](docs/MIGRATION_STATIC_TO_DYNAMIC_SPA.md) - Migration guide

## Documentation

- [`docs/ELK_INTEGRATION.md`](docs/ELK_INTEGRATION.md) - ELK stack integration
- [`docs/CONFIGURING_PORTS.md`](docs/CONFIGURING_PORTS.md) - Port configuration
- [`docs/DYNAMIC_SPA_USAGE_GUIDE.md`](docs/DYNAMIC_SPA_USAGE_GUIDE.md) - Dynamic SPA guide
- [`docs/DOCKER.md`](docs/DOCKER.md) - Docker deployment
- [`CONTRIBUTING.md`](CONTRIBUTING.md) - Development guidelines
- [`SECURITY.md`](SECURITY.md) - Security policy

## Development

### Project Structure

```
phantom-grid/
├── cmd/
│   ├── agent/          # Main Phantom Grid agent
│   ├── spa-client/     # SPA client CLI
│   └── config-gen/     # Configuration generator
├── internal/
│   ├── agent/          # Agent core logic
│   ├── config/         # Configuration (ports, constants)
│   ├── dashboard/      # Terminal UI
│   ├── ebpf/           # eBPF loader and programs
│   ├── honeypot/       # Honeypot implementation
│   └── spa/            # SPA manager
├── pkg/
│   └── spa/            # Reusable SPA client
└── docs/               # Documentation
```

### Build Commands

```bash
make build          # Build all binaries
make test           # Run tests
make test-coverage  # Run tests with coverage
make fmt            # Format code
make lint           # Lint code
make clean          # Clean build artifacts
make generate       # Regenerate eBPF bindings
```

### Regenerating eBPF Bindings

If you modify eBPF C programs:

```bash
go generate ./...
# or
make generate
```

## Troubleshooting

### XDP attach failed: "device or resource busy"

```bash
# Detach existing XDP program
sudo ip link set dev INTERFACE_NAME xdp off

# Then retry
sudo ./bin/phantom-grid -interface INTERFACE_NAME
```

### Port 9999 already in use

```bash
# Find and kill process
sudo lsof -i :9999
sudo kill -9 <PID>
```

### eBPF program load failed: "permission denied"

Ensure you're running with root privileges:

```bash
sudo ./bin/phantom-grid -interface INTERFACE_NAME
```

For more troubleshooting, see the [documentation](docs/).

## Security Considerations

- **Change Default SPA Token**: Never use default token in production
- **Network Interface**: Always specify external interface for production
- **Firewall Rules**: XDP operates before iptables/firewalld
- **Logging**: Implement log rotation for production deployments
- **Access Control**: Limit who can send SPA Magic Packets

See [`SECURITY.md`](SECURITY.md) for security policy and vulnerability reporting.

## Contributing

Contributions are welcome! Please read:

- [`CONTRIBUTING.md`](CONTRIBUTING.md) - Development workflow and guidelines
- [`SECURITY.md`](SECURITY.md) - Security vulnerability reporting

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE) for details.

## Author

**Mai Hai Dang – HD24SecurityLabs**

Focus areas: system programming, eBPF, and active defense.

## Acknowledgments

Built with:

- [Cilium eBPF](https://github.com/cilium/ebpf) - eBPF library for Go
- [TermUI](https://github.com/gizak/termui) - Terminal dashboard library

## Disclaimer

**WARNING:** This tool is for authorized security testing and research purposes only. Use responsibly and in compliance with applicable laws and regulations. The authors and contributors are not responsible for any misuse or damage caused by this software.
