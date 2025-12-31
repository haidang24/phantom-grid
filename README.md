# Phantom Grid

> "The best defense is not just blocking – it is confusing, deceiving, and recording."

**Phantom Grid** is a kernel-level active defense system built on **eBPF (Extended Berkeley Packet Filter)** that transforms a standard Linux server into a controlled, deceptive attack surface. It provides enterprise-grade security through deception, zero-trust access control, and real-time threat intelligence.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Testing](#testing)
- [Development](#development)
- [Docker Deployment](#docker-deployment)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

## Overview

Phantom Grid implements three core defense mechanisms:

1. **The Phantom Protocol** - Makes critical services invisible by default, requiring Single Packet Authorization (SPA) for access
2. **The Mirage** - Presents randomized fake services to confuse reconnaissance tools
3. **The Portal** - Transparently redirects suspicious traffic to honeypots for analysis

All traffic processing happens in kernel space using eBPF/XDP for wire-speed performance with minimal overhead.

## Features

### Core Defense Mechanisms

- **The Phantom Protocol**  
  Critical assets (SSH, databases, admin panels) are completely invisible by default. All traffic to protected ports is dropped unless the source IP is whitelisted via Single Packet Authorization (SPA). Attackers see a "dead host" while authorized administrators maintain access.

- **The Mirage**  
  Dynamically presents a wide range of seemingly open ports with randomized service banners. Reconnaissance tools see a noisy, misleading surface instead of real services. Each connection receives a randomized service type (SSH, HTTP, MySQL, Redis, FTP, Telnet) with different OS fingerprints, creating an inconsistent "Ghost Grid" that confuses attackers.

- **The Portal**  
  Transparent redirection of suspicious traffic to an internal honeypot without changing the destination IP. All non-critical traffic is silently redirected to the honeypot for analysis and logging.

### Advanced Capabilities

- **Single Packet Authorization (SPA)**  
  Zero-trust access control mechanism. The server is completely invisible by default. Administrators send a Magic Packet (UDP packet with secret token) to port 1337. Upon successful validation, the source IP is whitelisted for 30 seconds, allowing SSH access. This implements the highest level of Zero Trust security.

- **Stealth Scan Detection**  
  Automatically detects and silently drops malicious scan types (Xmas, Null, FIN, ACK scans) at the kernel level, saving honeypot resources and preventing reconnaissance. Statistics are tracked in real-time via BPF maps.

- **OS Personality Mutation**  
  Kernel-level OS fingerprint spoofing. Mutates IP TTL and TCP Window Size in real-time to confuse fingerprinting tools. Attackers see inconsistent OS signatures (Windows, Linux, FreeBSD, Solaris) and may use wrong exploits. Implemented at wire-speed using eBPF.

- **Egress Containment (DLP)**  
  Kernel-level Data Loss Prevention. TC eBPF program monitors outbound traffic from honeypot connections. Detects and blocks suspicious data patterns (password files, SSH keys, base64-encoded data, SQL dumps) before they leave the server. Even if an attacker gains access, data never leaves the server.

- **Real-Time Forensics Dashboard**  
  Terminal-based dashboard (TermUI) provides live visualization of:

  - Incoming connections and trap hits
  - Commands executed by attackers
  - Dynamic threat level gauge
  - Statistics for redirected connections, stealth drops, OS mutations, and SPA authentications
  - Connection statistics (honeypot connections, active sessions, total commands)

- **High Performance**  
  Built on eBPF/XDP, all traffic decisions are made in kernel space with minimal overhead, suitable for modern high-throughput environments.

---

## Architecture

### Kernel Space Components

#### XDP Program (`internal/ebpf/programs/phantom.c`)

The XDP (eXpress Data Path) program is attached to a network interface and processes packets at the NIC driver level for wire-speed performance.

**Key Functions:**

- **Single Packet Authorization (SPA)**

  - Listens for UDP packets on port 1337 containing secret token `PHANTOM_GRID_SPA_2025`
  - Validates token and whitelists source IP (LRU map auto-expires entries)
  - SSH port 22 is completely closed unless source IP is whitelisted
  - Maintains statistics: `spa_auth_success`, `spa_auth_failed`

- **Stealth Scan Detection**

  - Detects and drops: Xmas Scan (FIN+URG+PSH), Null Scan, FIN Scan, ACK Scan
  - Statistics tracked in `stealth_drops` map

- **Transparent Redirection**

  - Fake ports (80, 443, 3306, etc.) are passed directly if honeypot binds them
  - Other ports are redirected to honeypot fallback port 9999
  - Connection tracking via `redirect_map` LRU hash map

- **OS Personality Mutation**

  - Mutates IP TTL (Windows=128, Linux=64, FreeBSD=64, Solaris=255)
  - Mutates TCP Window Size (Windows=65535, Linux=29200, FreeBSD=65535)
  - Uses source port hash for consistent fingerprint per connection
  - Statistics tracked in `os_mutations` map

- **Checksum Recalculation**
  - Sets checksum fields to 0 after modification (kernel recalculates in XDP Generic mode)
  - Ensures packets are not dropped by NIC or OS

#### TC Egress Program (`bpf/phantom_egress.c`)

The TC (Traffic Control) eBPF program monitors outbound traffic for data exfiltration.

**Key Functions:**

- **Pattern Detection**
  - Scans payload for suspicious patterns:
    - `/etc/passwd` format (`root:x:0:0:`)
    - SSH private keys (`-----BEGIN`)
    - Base64-encoded data (95% threshold to avoid false positives)
    - SQL dumps (`INSERT INTO`)
  - Statistics tracked in `egress_blocks` and `suspicious_patterns` maps

### User Space Components

#### Main Agent (`cmd/agent/main.go`)

- Loads and attaches XDP and TC eBPF programs using Cilium eBPF library
- Auto-detects or accepts user-specified network interface
- Starts lightweight TCP honeypot on port 9999 and multiple fake ports
- Implements "The Mirage" with randomized service banners:
  - **SSH**: 8 different OpenSSH versions (Ubuntu, Debian, CentOS, RedHat, Arch, FreeBSD)
  - **HTTP**: Multiple web server signatures (nginx, Apache, IIS)
  - **Database**: MySQL, MariaDB, Redis responses
  - **FTP**: Various FTP server implementations
  - **Telnet**: Multiple Linux distribution login prompts
- Provides interactive service emulation (SSH shells, HTTP servers, MySQL, Redis, FTP)
- Exposes TUI dashboard with real-time forensics and statistics
- Logs all attacker interactions to `logs/audit.json`

#### SPA Client (`cmd/spa-client/main.go`)

- Command-line tool to send Magic Packet for SPA authentication
- Validates token length and provides clear feedback
- Usage: `./spa-client <server_ip>`

---

## Tech Stack

- **Kernel Space:** C, eBPF/XDP, TC
- **User Space:** Go (Golang) 1.21+
- **eBPF Runtime:** `github.com/cilium/ebpf`
- **TUI Dashboard:** `github.com/gizak/termui/v3`
- **Build System:** Make, bpf2go

---

## Requirements

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04/22.04, Debian 11+, CentOS 8+, or similar)
- **Kernel Version**: Linux kernel 5.4 or later (required for eBPF/XDP support)
- **Architecture**: x86_64 or ARM64
- **Privileges**: Root/sudo access (required for eBPF program loading)

### Build Dependencies

- **Go**: Version 1.21 or later
- **C Compiler**: `clang` (version 10+)
- **LLVM**: `llvm` (version 10+)
- **eBPF Libraries**: `libbpf-dev`
- **Build Tools**: `make`, `git`

### Install Dependencies

**Ubuntu/Debian:**

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev golang-go make git
```

**CentOS/RHEL:**

```bash
sudo yum install -y clang llvm libbpf-devel golang make git
```

**Arch Linux:**

```bash
sudo pacman -S clang llvm libbpf go make git
```

## Quick Start

### Step 1: Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid
```

### Step 2: Install Go Dependencies

```bash
go mod tidy
```

### Step 3: Build Project

```bash
make build
```

This compiles eBPF programs and builds binaries:

- `bin/phantom-grid` - Main agent
- `bin/spa-client` - SPA authentication client

### Step 4: Run Phantom Grid

**Option A: Auto-detect network interface (testing only):**

```bash
sudo make run
```

**Option B: Specify network interface (recommended for production):**

```bash
# List available interfaces
ip link show

# Run with specific interface
make run-interface INTERFACE=ens33
# or
sudo ./bin/phantom-grid -interface ens33
```

### Step 5: Authenticate with SPA

From another machine, send Magic Packet to whitelist your IP:

```bash
./bin/spa-client SERVER_IP
```

You now have 30 seconds to access protected services (e.g., SSH).

## Installation

### From Source

1. **Clone the repository:**

```bash
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid
```

2. **Install dependencies:**

```bash
# Install system dependencies (see Requirements section)
sudo apt install -y clang llvm libbpf-dev golang-go make git

# Install Go module dependencies
go mod tidy
```

3. **Build:**

```bash
make build
```

Binaries will be in `bin/` directory:

- `bin/phantom-grid` - Main agent binary
- `bin/spa-client` - SPA client tool

4. **Verify installation:**

```bash
./bin/phantom-grid -h
./bin/spa-client -h
```

### Build Options

```bash
# Build everything (default)
make build

# Clean build artifacts
make clean

# Run tests
make test

# Run tests with coverage
make test-coverage

# Format code
make fmt

# Lint code
make lint
```

---

## Docker Deployment

### Prerequisites

- Docker Engine 20.10+ with BuildKit support
- Linux kernel 5.4+ on host (required for eBPF/XDP)
- Host network access (XDP requires host network mode)

### Build Docker Image

```bash
docker build -t phantom-grid:latest .
```

### Run with Docker Compose (Recommended)

```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Run with Docker (Manual)

```bash
# Build image
docker build -t phantom-grid:latest .

# Run container (requires privileged mode and host network)
docker run -d \
  --name phantom-grid \
  --privileged \
  --network host \
  -v $(pwd)/logs:/app/logs \
  phantom-grid:latest

# Or specify network interface
docker run -d \
  --name phantom-grid \
  --privileged \
  --network host \
  -v $(pwd)/logs:/app/logs \
  -e INTERFACE=eth0 \
  phantom-grid:latest

# View logs
docker logs -f phantom-grid

# Stop container
docker stop phantom-grid
docker rm phantom-grid
```

### Development Container

For development with all tools:

```bash
docker build -f Dockerfile.dev -t phantom-grid:dev .
docker run -it --privileged --network host -v $(pwd):/app phantom-grid:dev
```

**Important Notes:**

- **Privileged Mode**: Required for eBPF program loading (`--privileged`)
- **Host Network**: Required for XDP to attach to network interfaces (`--network host`)
- **Capabilities**: Container needs `SYS_ADMIN`, `NET_ADMIN`, and `BPF` capabilities
- **Kernel Version**: Host kernel must be 5.4+ for eBPF/XDP support

---

## Usage

### Running Phantom Grid

#### Basic Usage

```bash
# Show help
sudo ./bin/phantom-grid -h

# Run with auto-detected interface (testing only)
sudo ./bin/phantom-grid

# Run with specific network interface (recommended)
sudo ./bin/phantom-grid -interface INTERFACE_NAME
```

#### Network Interface Selection

**Step 1: List available network interfaces:**

```bash
ip link show
# or
ifconfig -a
```

**Step 2: Identify external interface:**

The external interface is the one with a non-loopback IP address (not 127.0.0.1).

```bash
# Show interfaces with IP addresses
ip addr show

# Find external interface (exclude loopback)
ip addr show | grep -E "^[0-9]+:|inet " | grep -v "127.0.0.1"
```

**Common interface names:**

- **VMware/VirtualBox**: `ens33`, `enp0s3`, `eth0`
- **Physical servers**: `eth0`, `eth1`, `enp*s*`
- **WiFi**: `wlan0`, `wlx*`, `wlp*`
- **USB Ethernet**: `enp0s3`, `enx*`

**Step 3: Run with selected interface:**

```bash
# Using Makefile
make run-interface INTERFACE=ens33

# Direct binary execution
sudo ./bin/phantom-grid -interface ens33
sudo ./bin/phantom-grid -interface eth0
sudo ./bin/phantom-grid -interface wlan0
```

**Important Notes:**

- Always specify the external interface for production deployments
- Auto-detection may select the wrong interface or fallback to loopback
- Loopback interface (lo) only works for local testing
- XDP programs attached to external interfaces do not process localhost traffic

### Single Packet Authorization (SPA)

Phantom Grid uses SPA for zero-trust access control. Protected ports are invisible by default and require authentication via Magic Packet.

#### Step 1: Verify Server is Invisible

From an external machine (attacker perspective):

```bash
# Ping test (ICMP allowed, but SSH protected)
ping SERVER_IP

# Port scan - protected ports appear closed
nmap -p 22 SERVER_IP
# Result: Port 22 is filtered/closed - server appears "dead"
```

#### Step 2: Send Magic Packet

From an authorized machine, send the Magic Packet:

```bash
./bin/spa-client SERVER_IP
```

Expected output:

```
[*] Sending Magic Packet to SERVER_IP:1337...
[+] Magic Packet sent successfully!
[+] Your IP has been whitelisted for 30 seconds
[+] You can now access protected services:
    ssh user@SERVER_IP
```

#### Step 3: Access Protected Services

Within 30 seconds of sending Magic Packet:

```bash
# SSH access (now allowed)
ssh user@SERVER_IP

# Other protected services (databases, admin panels, etc.)
mysql -h SERVER_IP -u user -p
```

#### Step 4: Monitor Dashboard

The Phantom Grid dashboard shows:

- SPA authentication success/failure messages
- Whitelisted IP addresses
- Active connections to protected ports
- Whitelist expiry (automatic after 30 seconds)

**Important:**

- Whitelist expires after 30 seconds
- Each IP must authenticate separately
- Default SPA token: `PHANTOM_GRID_SPA_2025` (change for production)

### Command Line Options

```bash
Usage: ./bin/phantom-grid [OPTIONS]

Options:
  -interface string       Network interface name (required for production)
                          If not specified, auto-detection will be attempted

  -output string          Output mode: 'dashboard', 'elk', or 'both' (default: "dashboard")

  -elk-address string     Elasticsearch address (default: "http://localhost:9200")
                          For multiple addresses: "http://es1:9200,http://es2:9200"

  -elk-index string       Elasticsearch index name (default: "phantom-grid")

  -elk-user string        Elasticsearch username (optional, for basic auth)

  -elk-pass string        Elasticsearch password (optional, for basic auth)

  -elk-tls                Enable TLS for Elasticsearch connections

  -elk-skip-verify        Skip TLS certificate verification (testing only)

  -h, -help               Show help message
```

### Output Modes

Phantom Grid supports three output modes:

**1. Dashboard Only (Default):**

```bash
sudo ./bin/phantom-grid -interface ens33 -output dashboard
```

Shows events in terminal dashboard only.

**2. ELK Only:**

```bash
sudo ./bin/phantom-grid -interface ens33 -output elk \
  -elk-address http://localhost:9200 \
  -elk-index phantom-grid
```

Sends all events to Elasticsearch. No dashboard displayed. Ideal for headless servers.

**3. Both Dashboard and ELK:**

```bash
sudo ./bin/phantom-grid -interface ens33 -output both \
  -elk-address http://localhost:9200 \
  -elk-index phantom-grid
```

Shows events in dashboard AND sends to Elasticsearch. Best for development.

For detailed ELK integration guide, see [`docs/ELK_INTEGRATION.md`](docs/ELK_INTEGRATION.md).

### Dashboard Controls

When Phantom Grid is running, the terminal dashboard supports:

- `j` / `k` - Scroll down/up in log panel
- `g` / `G` - Scroll to top/bottom
- `a` - Toggle auto-scroll
- `SPACE` - Pause/resume log scrolling
- `q` / `Ctrl+C` - Exit application

### Stopping Phantom Grid

```bash
# If running in foreground: Press Ctrl+C

# If running in background: Find PID and kill
ps aux | grep phantom-grid
sudo kill <PID>

# Or use pkill
sudo pkill phantom-grid
```

**Note:** XDP programs are automatically detached when the application exits gracefully.

## Configuration

### Protected Ports

Phantom Grid protects 60+ critical ports by default, including:

- **SSH**: 22
- **Databases**: 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB), 6379 (Redis), 1433 (MSSQL), 1521 (Oracle)
- **Admin Panels**: 8080, 8443, 9000, 9200 (Elasticsearch), 5601 (Kibana), 3000 (Grafana)
- **Remote Access**: 3389 (RDP), 5985/5986 (WinRM)
- **Container Services**: 2375/2376 (Docker)
- **Directory Services**: 389/636 (LDAP)
- **And many more...**

See [`docs/CONFIGURING_PORTS.md`](docs/CONFIGURING_PORTS.md) for:

- Complete list of protected ports
- How to add new ports
- Port configuration best practices
- Troubleshooting guide

### SPA Token Configuration

**Default token:** `PHANTOM_GRID_SPA_2025` (21 bytes)

**For production:** Change the token in `internal/ebpf/programs/phantom.c`:

```c
#define SPA_SECRET_TOKEN "YOUR_SECRET_TOKEN_HERE"
#define SPA_TOKEN_LEN 21  // Update if token length changes
```

Then rebuild:

```bash
make clean
make build
```

**Security Best Practices:**

- Use a strong, random token (21+ bytes recommended)
- Rotate tokens periodically
- Keep tokens secret (never commit to version control)
- Use different tokens for different environments

## Testing

### Basic Functionality Test

1. **Scan from external machine:**

```bash
nmap -p- PHANTOM_IP
```

Expected: Multiple fake ports appear open (80, 443, 3306, 5432, etc.)

2. **Connect to fake port:**

```bash
nc PHANTOM_IP 3306
```

Expected: Randomized service banner (SSH, HTTP, MySQL, Redis, FTP, or Telnet)

3. **Interact with service:**

- **SSH:** Try commands (`whoami`, `ls`, `pwd`, `exit`)
- **HTTP:** Send request (`GET / HTTP/1.1\r\nHost: example.com\r\n\r\n`)
- **MySQL:** Attempt authentication
- **Redis:** Send commands (`PING`, `INFO`)
- **FTP:** Send commands (`USER test`, `PASS test`)

4. **Monitor dashboard:**

- Watch real-time logs of connections and commands
- Check statistics for redirected connections, stealth drops, OS mutations

### Basic Functionality Test

**1. Port Scan Test:**

From an external machine:

```bash
nmap -p- SERVER_IP
```

Expected: Multiple fake ports appear open (80, 443, 3306, 5432, etc.)

**2. Fake Port Connection Test:**

```bash
# Connect to fake MySQL port
nc SERVER_IP 3306

# Expected: Randomized service banner (SSH, HTTP, MySQL, Redis, FTP, or Telnet)
```

**3. Service Interaction Test:**

- **SSH honeypot**: Try commands (`whoami`, `ls`, `pwd`, `exit`)
- **HTTP honeypot**: Send request (`GET / HTTP/1.1\r\nHost: example.com\r\n\r\n`)
- **MySQL honeypot**: Attempt authentication
- **Redis honeypot**: Send commands (`PING`, `INFO`)
- **FTP honeypot**: Send commands (`USER test`, `PASS test`)

**4. Dashboard Monitoring:**

- Watch real-time logs of connections and commands
- Check statistics for redirected connections, stealth drops, OS mutations
- Verify SPA authentication events

### Unit Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# View coverage report
open coverage.html  # macOS
xdg-open coverage.html  # Linux
```

### Integration Testing

**Test SPA Authentication Flow:**

```bash
# Terminal 1: Run Phantom Grid
sudo ./bin/phantom-grid -interface ens33

# Terminal 2: Test from external machine
# 1. Verify SSH is blocked
ssh user@SERVER_IP  # Should timeout

# 2. Send Magic Packet
./bin/spa-client SERVER_IP

# 3. SSH should now work (within 30 seconds)
ssh user@SERVER_IP  # Should connect
```

## Development

### Project Structure

```
phantom-grid/
├── cmd/
│   ├── agent/             # Main Phantom Grid agent
│   │   └── main.go
│   └── spa-client/        # SPA client CLI tool
│       └── main.go
├── internal/
│   ├── agent/             # Agent core logic
│   ├── config/            # Configuration and constants
│   ├── dashboard/         # Terminal UI dashboard
│   ├── ebpf/
│   │   ├── loader.go      # eBPF loader and bindings
│   │   └── programs/      # eBPF C programs
│   │       ├── phantom.c          # XDP program (ingress)
│   │       ├── phantom_egress.c   # TC program (egress DLP)
│   │       └── phantom_spa.c      # SPA module
│   ├── honeypot/          # Honeypot implementation
│   ├── logger/            # Logging utilities
│   ├── mirage/            # Fake service banners
│   ├── network/           # Network interface detection
│   └── spa/               # SPA manager
├── pkg/
│   └── spa/               # Reusable SPA client package
├── assets/                # Static assets (images, etc.)
├── docs/                  # Technical documentation
├── logs/                  # Runtime logs (gitignored)
├── bin/                   # Build output (gitignored)
├── Makefile
├── go.mod
└── README.md
```

### Regenerating eBPF Bindings

If you modify eBPF programs, regenerate Go bindings:

```bash
go generate ./...
```

### Building

```bash
# Build all binaries
make build

# Clean build artifacts
make clean
```

### Development Setup

**1. Clone and setup:**

```bash
git clone https://github.com/YOUR_USERNAME/phantom-grid.git
cd phantom-grid
go mod tidy
```

**2. Development workflow:**

```bash
# Format code
make fmt

# Lint code
make lint

# Run tests
make test

# Build
make build
```

**3. Regenerating eBPF Bindings:**

If you modify eBPF C programs, regenerate Go bindings:

```bash
go generate ./...
# or
make generate
```

**4. Building:**

```bash
# Build all binaries
make build

# Clean build artifacts
make clean
```

### Project Structure

```
phantom-grid/
├── cmd/
│   ├── agent/             # Main Phantom Grid agent
│   │   └── main.go
│   └── spa-client/        # SPA client CLI tool
│       └── main.go
├── internal/
│   ├── agent/             # Agent core logic
│   ├── config/            # Configuration and constants
│   ├── dashboard/         # Terminal UI dashboard
│   ├── ebpf/
│   │   ├── loader.go      # eBPF loader and bindings
│   │   └── programs/      # eBPF C programs
│   │       ├── phantom.c          # XDP program (ingress)
│   │       ├── phantom_egress.c   # TC program (egress DLP)
│   │       └── phantom_spa.c      # SPA module
│   ├── honeypot/          # Honeypot implementation
│   ├── logger/            # Logging utilities
│   ├── mirage/            # Fake service banners
│   ├── network/           # Network interface detection
│   └── spa/               # SPA manager
├── pkg/
│   └── spa/               # Reusable SPA client package
├── assets/                # Static assets (images, etc.)
├── docs/                  # Technical documentation
├── logs/                  # Runtime logs (gitignored)
├── bin/                   # Build output (gitignored)
├── Makefile
├── go.mod
└── README.md
```

## Docker Deployment

### Quick Start with Docker Compose

```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Manual Docker Deployment

```bash
# Build image
docker build -t phantom-grid:latest .

# Run container
docker run -d \
  --name phantom-grid \
  --privileged \
  --network host \
  -v $(pwd)/logs:/app/logs \
  -e INTERFACE=eth0 \
  phantom-grid:latest

# View logs
docker logs -f phantom-grid

# Stop container
docker stop phantom-grid
docker rm phantom-grid
```

### Development Container

```bash
docker build -f Dockerfile.dev -t phantom-grid:dev .
docker run -it --privileged --network host -v $(pwd):/app phantom-grid:dev
```

**Important Notes:**

- **Privileged Mode**: Required for eBPF program loading (`--privileged`)
- **Host Network**: Required for XDP to attach to network interfaces (`--network host`)
- **Kernel Version**: Host kernel must be 5.4+ for eBPF/XDP support

For complete Docker documentation, see [`docs/DOCKER.md`](docs/DOCKER.md).

## Troubleshooting

### Common Issues

**1. XDP attach failed: "device or resource busy"**

Another XDP program is already attached to the interface.

**Solution:**

```bash
# Detach existing XDP program
sudo ip link set dev INTERFACE_NAME xdp off

# Then retry
sudo ./bin/phantom-grid -interface INTERFACE_NAME
```

**2. Port 9999 already in use**

The honeypot fallback port is required and must be available.

**Solution:**

```bash
# Find process using port 9999
sudo lsof -i :9999

# Kill the process
sudo kill -9 <PID>

# Or change HONEYPOT_PORT in internal/ebpf/programs/phantom.c and rebuild
```

**3. eBPF program load failed: "permission denied"**

Missing required capabilities or running without root.

**Solution:**

```bash
# Run with sudo
sudo ./bin/phantom-grid -interface INTERFACE_NAME

# Or ensure user has CAP_BPF, CAP_SYS_ADMIN capabilities
```

**4. Interface not found**

The specified network interface does not exist.

**Solution:**

```bash
# List available interfaces
ip link show

# Use correct interface name
sudo ./bin/phantom-grid -interface <CORRECT_INTERFACE_NAME>
```

**5. TC Egress DLP disabled warning**

TC egress program failed to load (non-critical).

**Solution:**

This is a warning, not an error. Main XDP protection is still active. TC egress DLP requires specific kernel features and may not be available on all systems.

**6. SPA authentication not working**

**Checklist:**

- Verify SPA token matches in both client and server
- Check that UDP port 1337 is not blocked by firewall
- Ensure source IP is correct
- Verify whitelist hasn't expired (30 seconds)

**7. Protected ports still accessible**

**Checklist:**

- Verify XDP program is attached: `ip link show INTERFACE_NAME`
- Check that eBPF program loaded successfully (check logs)
- Ensure traffic is coming from external IP (not localhost)
- Verify port is in protected ports list

### Getting Help

- Check [`docs/`](docs/) directory for detailed documentation
- Review [`CONTRIBUTING.md`](CONTRIBUTING.md) for development guidelines
- Report issues via GitHub Issues
- For security issues, see [`SECURITY.md`](SECURITY.md)

## Contributing

Contributions are welcome! Please read:

- [`CONTRIBUTING.md`](CONTRIBUTING.md) – development workflow, coding style, and PR checklist
- [`SECURITY.md`](SECURITY.md) – how to report vulnerabilities responsibly

For detailed technical documentation, see the [`docs/`](docs/) directory.

### SPA Documentation

- [`docs/DYNAMIC_SPA_USAGE_GUIDE.md`](docs/DYNAMIC_SPA_USAGE_GUIDE.md) - **Complete usage guide for Dynamic Asymmetric SPA** (Vietnamese)
- [`docs/DYNAMIC_SPA.md`](docs/DYNAMIC_SPA.md) - Technical implementation details
- [`docs/MIGRATION_STATIC_TO_DYNAMIC_SPA.md`](docs/MIGRATION_STATIC_TO_DYNAMIC_SPA.md) - Migration guide from static to dynamic SPA

### Configuration Management

Phantom Grid uses a **fully centralized configuration system** - all configuration is managed in Go code, and eBPF C code is automatically generated. This eliminates configuration drift and ensures consistency.

**Configuration Files:**

- `internal/config/config.go` - Core constants (SPA, network ports)
- `internal/config/ports.go` - Port definitions (protected and fake ports)
- `internal/config/constants.go` - eBPF-specific constants (OS fingerprint values)

**No manual C code editing required!** All eBPF constants are auto-generated from Go config.

See [`docs/CONFIGURATION_MANAGEMENT.md`](docs/CONFIGURATION_MANAGEMENT.md) for complete details.

### ELK Integration

Phantom Grid can export security events to Elasticsearch for centralized logging and analysis. See [`docs/ELK_INTEGRATION.md`](docs/ELK_INTEGRATION.md) for:

- Complete setup guide
- Configuration examples
- Kibana dashboard setup
- Performance tuning
- Troubleshooting

---

## Security Considerations

### Production Deployment Checklist

1. **Network Interface Selection**

   - Always specify external interface using `-interface` flag
   - Avoid loopback interface for production
   - Verify interface detection is working correctly

2. **SPA Token Security**

   - Change default token (`PHANTOM_GRID_SPA_2025`) before production
   - Use strong, random token (21+ bytes recommended)
   - Keep token secret (never commit to version control)
   - Rotate tokens periodically

3. **Port Binding**

   - Ports < 1024 require root privileges
   - Run with `sudo` to bind all fake ports
   - Ensure port 9999 (honeypot fallback) is available

4. **Firewall Rules**

   - XDP operates before iptables/firewalld
   - Ensure no conflicting firewall rules
   - ICMP is allowed for network connectivity

5. **Performance**

   - XDP Generic mode is used for VMware/virtual interface compatibility
   - For native XDP performance, ensure driver support
   - Monitor system resources (CPU, memory)

6. **Logging**
   - All attacker interactions logged to `logs/audit.json`
   - Implement log rotation for production
   - Consider integration with SIEM platforms
   - Review logs regularly for security events

### Security Best Practices

- **Change Default SPA Token**: Never use default token in production
- **Monitor Dashboard**: Regularly check for suspicious activity
- **Log Management**: Implement log rotation and archival
- **Network Segmentation**: Deploy on isolated network segments when possible
- **Regular Updates**: Keep system and dependencies updated
- **Access Control**: Limit who can send SPA Magic Packets
- **Audit Trail**: Maintain audit logs for compliance

### Limitations

- XDP programs attached to external interfaces do not process localhost traffic
- TC Egress DLP may require specific netlink APIs (gracefully degrades if unavailable)
- SPA whitelist expiry uses precise TTL (30 seconds exact)
- Some network drivers may not support native XDP (falls back to Generic mode)

---

## License

This project is released under the MIT License. See `LICENSE` for details.

---

## License

This project is released under the MIT License. See [`LICENSE`](LICENSE) for details.

## Author

**Mai Hai Dang – HD24SecurityLabs**

Focus areas: system programming, eBPF, and active defense.

## Acknowledgments

Built with:

- [Cilium eBPF](https://github.com/cilium/ebpf) - eBPF library for Go
- [TermUI](https://github.com/gizak/termui) - Terminal dashboard library

## Disclaimer

**WARNING:** This tool is for authorized security testing and research purposes only. Use responsibly and in compliance with applicable laws and regulations. The authors and contributors are not responsible for any misuse or damage caused by this software.
