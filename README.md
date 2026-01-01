# Phantom Grid

<div align="center">

**Kernel-Level Active Defense System Built on eBPF/XDP**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org/)
[![Linux Kernel](https://img.shields.io/badge/Kernel-5.4+-blue)](https://www.kernel.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-orange)](CONTRIBUTING.md)

> _"The best defense is not just blocking – it is confusing, deceiving, and recording."_

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing) • [Security](#-security)

</div>

---

## 📖 Overview

**Phantom Grid** is an enterprise-grade, kernel-level active defense system that transforms Linux servers into a controlled, deceptive attack surface. Built on **eBPF/XDP**, it provides zero-trust access control, advanced honeypot deception, and real-time threat intelligence at the network packet level.

### What Makes Phantom Grid Different?

- **🛡️ Zero-Trust Architecture**: Critical services are invisible by default, requiring cryptographic authentication for access
- **🎭 Advanced Deception**: Randomized fake services confuse reconnaissance tools and waste attacker time
- **⚡ Kernel-Level Performance**: eBPF/XDP processing at line rate with minimal overhead
- **🔐 Dynamic SPA**: Time-based one-time passwords (TOTP) + Ed25519 signatures for replay-resistant authentication
- **📊 Real-Time Intelligence**: Terminal dashboard and ELK integration for threat visualization

---

## ✨ Features

### Core Defense Mechanisms

| Feature                  | Description                                                                                                                                    |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| **The Phantom Protocol** | Critical services (SSH, databases, admin panels) are completely invisible to network scans. Access requires Single Packet Authorization (SPA). |
| **The Mirage**           | Randomized fake services on non-existent ports confuse port scanners and reconnaissance tools.                                                 |
| **The Portal**           | Suspicious traffic is transparently redirected to honeypots, capturing attacker behavior.                                                      |

### Advanced Capabilities

- **🔑 Dynamic Asymmetric SPA**: Zero-trust access control with TOTP and Ed25519 signatures
- **🕵️ Stealth Scan Detection**: Kernel-level detection and dropping of malicious scans
- **🎭 OS Personality Mutation**: Real-time OS fingerprint spoofing to mislead attackers
- **🚫 Egress Containment (DLP)**: Kernel-level data loss prevention for sensitive data exfiltration
- **📈 Real-Time Dashboard**: Terminal-based forensics and threat visualization
- **📊 ELK Integration**: Export security events to Elasticsearch for centralized analysis

---

## 🚀 Quick Start

### Prerequisites

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- **Kernel**: 5.4+ (eBPF/XDP support required)
- **Go**: 1.21+
- **Build Tools**: `clang`, `llvm`, `libbpf-dev`, `make`

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid

# Install dependencies (Ubuntu/Debian)
sudo apt update && sudo apt install -y clang llvm libbpf-dev golang-go make git

# Build the project
make build

# Generate SPA keys
./bin/spa-keygen -dir ./keys
openssl rand -base64 32 > keys/totp_secret.txt
```

### Run with Interactive Menu (Recommended)

```bash
# Launch the interactive menu
./bin/phantom
```

The menu provides easy access to:

- 🔑 Key management (generate keys, view status)
- 🖥️ Agent management (start/stop/configure)
- 🧪 SPA testing
- ⚙️ Configuration management
- ℹ️ System information
- 📚 Documentation viewer

### Run from Command Line

```bash
# Start the agent (requires root)
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys

# Authenticate from client
./bin/spa-client -server SERVER_IP -mode asymmetric
```

You now have 30 seconds to access protected services (SSH, FTP, etc.).

> **📖 For detailed instructions, see [Quick Start Guide](docs/quick-start.md)**

---

## 📚 Documentation

Complete documentation is available in the [`docs/`](docs/) directory.

### Essential Guides

- **[Installation Guide](docs/installation.md)** - Complete installation instructions for all platforms
- **[Quick Start Guide](docs/quick-start.md)** - Get up and running in 5 minutes
- **[Configuration Guide](docs/configuration.md)** - Configure ports, SPA modes, and output options
- **[SPA Documentation](docs/spa.md)** - Understanding SPA mechanism and modes

### Core Concepts

- **[Architecture Overview](docs/architecture.md)** - System architecture and design principles
- **[Deployment Guide](docs/deployment.md)** - Production deployment best practices
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions

### For Developers

- **[Development Guide](docs/development.md)** - Contributing and development workflow
- **[API Reference](docs/api.md)** - Command-line interface and configuration reference

> **📚 See [Documentation Index](docs/README.md) for complete documentation**

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Phantom Grid Architecture                 │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Client     │         │   Network    │         │   Server     │
│              │         │  Interface   │         │              │
│  SPA Client  │────────▶│   (ens33)    │────────▶│  Phantom     │
│              │         │              │         │  Grid Agent  │
└──────────────┘         └──────┬───────┘         └──────┬───────┘
                                │                        │
                                ▼                        ▼
                         ┌──────────────┐         ┌──────────────┐
                         │  eBPF/XDP    │         │  User-Space  │
                         │   Program    │         │   Handler    │
                         │              │         │              │
                         │ • Packet     │         │ • SPA Verify │
                         │   Filtering  │         │ • Whitelist  │
                         │ • Redirect   │         │ • Honeypot   │
                         │ • OS Mutation│         │ • Dashboard  │
                         └──────────────┘         └──────────────┘
```

### Key Components

1. **eBPF/XDP Programs**: Kernel-level packet processing

   - `phantom.c` - Main XDP program for ingress traffic
   - `phantom_egress.c` - TC program for egress DLP
   - `phantom_spa.c` - SPA authentication handler

2. **User-Space Agent**: Orchestrates all components

   - SPA handler for dynamic authentication
   - Honeypot server for deception
   - Dashboard for real-time monitoring
   - ELK exporter for centralized logging

3. **SPA Client**: Cross-platform authentication tool
   - Static token mode
   - Dynamic HMAC mode
   - Asymmetric Ed25519 mode

> **📖 See [Architecture Overview](docs/architecture.md) for detailed architecture**

---

## 💻 Usage Examples

### Basic Usage

```bash
# Show help
sudo ./bin/phantom-grid -h

# Run with specific interface (recommended)
sudo ./bin/phantom-grid -interface ens33
```

### SPA Modes

**Static Mode** (Simple token-based):

```bash
sudo ./bin/phantom-grid -interface ens33 -spa-mode static -spa-static-token "YOUR_TOKEN"
```

**Asymmetric Mode** (Ed25519 signatures - Recommended):

```bash
sudo ./bin/phantom-grid -interface ens33 -spa-mode asymmetric \
  -spa-key-dir ./keys \
  -spa-totp-secret "$(cat keys/totp_secret.txt)"
```

### Output Modes

**Dashboard Only (Default):**

```bash
sudo ./bin/phantom-grid -interface ens33 -output dashboard
```

**ELK Integration:**

```bash
sudo ./bin/phantom-grid -interface ens33 -output both \
  -elk-address http://localhost:9200 \
  -elk-index phantom-grid
```

> **📖 See [Configuration Guide](docs/configuration.md) for all options**

---

## 🔧 Development

### Build Commands

```bash
make build          # Build all binaries
make build-client   # Build only client (no eBPF)
make test           # Run tests
make test-coverage  # Run tests with coverage
make fmt            # Format code
make lint           # Lint code
make clean          # Clean build artifacts
make generate       # Regenerate eBPF bindings
make generate-config # Generate eBPF config from Go
```

### Project Structure

```
phantom-grid/
├── cmd/                    # Application entry points
│   ├── agent/             # Main agent
│   ├── spa-client/        # SPA client CLI
│   ├── spa-keygen/        # Key generator
│   ├── config-gen/         # Config generator
│   └── phantom/           # Interactive menu
├── internal/              # Internal packages
│   ├── agent/             # Agent logic
│   ├── config/            # Configuration
│   ├── dashboard/         # Terminal UI
│   ├── ebpf/              # eBPF loader and programs
│   ├── honeypot/          # Honeypot implementation
│   ├── logger/            # Logging
│   ├── network/           # Network utilities
│   └── spa/               # SPA implementation
├── pkg/                   # Public packages
│   └── spa/               # SPA client library
└── docs/                  # Documentation
```

> **📖 See [Development Guide](docs/development.md) for contribution guidelines**

---

## 🐛 Troubleshooting

### Common Issues

**XDP attach failed: "device or resource busy"**

```bash
sudo ip link set dev INTERFACE_NAME xdp off
sudo ./bin/phantom-grid -interface INTERFACE_NAME
```

**SPA authentication failed**

- Check clock synchronization (NTP)
- Verify keys match on client and server
- Check TOTP secret matches

**Port already in use**

```bash
sudo lsof -i :9999
sudo kill -9 <PID>
```

> **📖 See [Troubleshooting Guide](docs/troubleshooting.md) for detailed solutions**

---

## 🔒 Security

### Production Deployment

- **Change Default SPA Token**: Never use default token in production
- **Use Asymmetric Mode**: Best security with Ed25519 signatures
- **Secure Key Storage**: Encrypt keys at rest
- **Network Interface**: Always specify external interface
- **Monitor Authentication**: Log all attempts

### Security Best Practices

1. **Key Management**: Store private keys securely, rotate periodically
2. **TOTP Secret**: Distribute securely, rotate periodically
3. **Network Security**: Use encrypted channels for key distribution
4. **Access Control**: Limit who can send SPA Magic Packets

> **📖 See [Deployment Guide](docs/deployment.md) for production best practices**  
> **📖 See [SECURITY.md](SECURITY.md) for security policy**

---

## 🤝 Contributing

Contributions are welcome! Please read:

- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Development workflow and guidelines
- **[SECURITY.md](SECURITY.md)** - Security vulnerability reporting
- **[Development Guide](docs/development.md)** - Detailed development guide

### Quick Contribution Steps

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Format code (`make fmt`)
6. Commit your changes
7. Push to the branch
8. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE) for details.

```
MIT License

Copyright (c) 2025 Mai Hai Dang

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 👤 Author

**Mai Hai Dang – HD24SecurityLabs**

Focus areas: system programming, eBPF, and active defense.

---

## 🙏 Acknowledgments

Built with:

- [Cilium eBPF](https://github.com/cilium/ebpf) - eBPF library for Go
- [TermUI](https://github.com/gizak/termui) - Terminal dashboard library
- [netlink](https://github.com/vishvananda/netlink) - Netlink library for Go

---

## ⚠️ Disclaimer

**WARNING:** This tool is for authorized security testing and research purposes only. Use responsibly and in compliance with applicable laws and regulations. The authors and contributors are not responsible for any misuse or damage caused by this software.

---

## 📊 Project Status

**Status**: Active Development  
**Stability**: Production-ready for testing environments

---

<div align="center">

**⭐ If you find this project useful, please consider giving it a star! ⭐**

Made with ❤️ by the Phantom Grid community

[Documentation](docs/README.md) • [Contributing](CONTRIBUTING.md) • [Security](SECURITY.md)

</div>
