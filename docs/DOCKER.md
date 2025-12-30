# Docker Deployment Guide

## Overview

Phantom Grid can be deployed using Docker, but requires special configuration due to eBPF/XDP requirements.

## Requirements

### Host System

- **Linux kernel 5.4+** (required for eBPF/XDP)
- **Docker Engine 20.10+** with BuildKit support
- **Privileged access** (for eBPF program loading)
- **Host network mode** (XDP attaches to physical network interfaces)

### Why Special Configuration?

eBPF/XDP programs need:
1. **Kernel access** - Load programs into kernel space
2. **Network interface access** - Attach XDP to physical NICs
3. **BPF capabilities** - Create and manage BPF maps
4. **Host network** - Access to actual network interfaces (not virtual Docker network)

## Dockerfile Structure

### Production Dockerfile (`Dockerfile`)

Multi-stage build:
- **Builder stage**: Compiles Go code and eBPF programs
- **Runtime stage**: Minimal Debian image with only binaries

### Development Dockerfile (`Dockerfile.dev`)

Full development environment with:
- All build tools (clang, llvm, libbpf-dev)
- Development utilities (vim, curl, tcpdump)
- Interactive shell for debugging

## Usage

### Build Image

```bash
# Production build
docker build -t phantom-grid:latest .

# Development build
docker build -f Dockerfile.dev -t phantom-grid:dev .
```

### Run with Docker Compose

```bash
# Start service
docker-compose up -d

# View logs
docker-compose logs -f phantom-grid

# Stop service
docker-compose down

# Rebuild and restart
docker-compose up -d --build
```

### Run with Docker CLI

```bash
# Basic run
docker run -d \
  --name phantom-grid \
  --privileged \
  --network host \
  -v $(pwd)/logs:/app/logs \
  phantom-grid:latest

# With specific network interface
docker run -d \
  --name phantom-grid \
  --privileged \
  --network host \
  -v $(pwd)/logs:/app/logs \
  -e INTERFACE=eth0 \
  phantom-grid:latest
```

### Development Container

```bash
# Run interactive development container
docker run -it \
  --privileged \
  --network host \
  -v $(pwd):/app \
  phantom-grid:dev

# Inside container:
# make build
# make test
# ./bin/phantom-grid -interface eth0
```

## Configuration

### Environment Variables

- `INTERFACE`: Network interface name (e.g., `eth0`, `ens33`)
  - If not set, auto-detection will be used
  - Example: `-e INTERFACE=eth0`

### Volumes

- `/app/logs`: Log directory (mapped to `./logs` on host)
  - Contains `audit.json` with attack logs

### Network Mode

**Required**: `--network host`

- XDP programs attach to physical network interfaces
- Docker's bridge network doesn't expose physical interfaces
- Host network mode gives container access to host's network stack

### Security Considerations

**Privileged Mode Required**:

- eBPF programs need kernel access
- XDP attachment requires elevated privileges
- BPF map creation needs `CAP_BPF`

**Alternatives** (if privileged mode is not acceptable):

1. Use `--cap-add` instead:
   ```bash
   docker run --cap-add=SYS_ADMIN --cap-add=NET_ADMIN --cap-add=BPF ...
   ```

2. Use `--security-opt apparmor:unconfined`:
   ```bash
   docker run --security-opt apparmor:unconfined ...
   ```

**Note**: Even with capabilities, some eBPF operations may still require privileged mode.

## Troubleshooting

### Container Cannot Attach XDP

**Error**: `failed to attach XDP: operation not permitted`

**Solutions**:
1. Ensure container runs with `--privileged` flag
2. Verify host kernel is 5.4+
3. Check network interface exists: `ip link show`
4. Ensure interface is not already attached to XDP

### Network Interface Not Found

**Error**: `failed to detect interface`

**Solutions**:
1. List available interfaces: `ip link show`
2. Specify interface explicitly: `-e INTERFACE=eth0`
3. Ensure host network mode: `--network host`

### eBPF Program Load Failed

**Error**: `failed to load phantom objects`

**Solutions**:
1. Verify kernel supports eBPF: `ls /sys/fs/bpf`
2. Check kernel version: `uname -r` (must be 5.4+)
3. Ensure BPF filesystem is mounted: `mount | grep bpf`

### Port Binding Failed

**Error**: `Cannot bind port 9999`

**Solutions**:
1. Check if port is in use: `sudo lsof -i :9999`
2. Free the port: `sudo kill -9 <PID>`
3. Or change `HONEYPOT_PORT` in `internal/ebpf/programs/phantom.c` and rebuild

## Production Deployment

### Recommended Setup

1. **Use Docker Compose** for easier management
2. **Mount logs directory** for persistence
3. **Set restart policy**: `restart: unless-stopped`
4. **Monitor logs**: `docker-compose logs -f`
5. **Specify network interface** explicitly (don't rely on auto-detection)

### Example Production docker-compose.yml

```yaml
version: '3.8'

services:
  phantom-grid:
    build: .
    image: phantom-grid:latest
    container_name: phantom-grid
    privileged: true
    network_mode: host
    volumes:
      - /var/log/phantom-grid:/app/logs
    environment:
      - INTERFACE=eth0  # Specify your external interface
    restart: unless-stopped
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN
      - BPF
```

## Limitations

### Docker-Specific Limitations

1. **Host Network Required**: Cannot use Docker bridge networking
2. **Privileged Mode**: Security implications in shared environments
3. **Kernel Dependency**: Host kernel must support eBPF/XDP
4. **Interface Access**: Only works with physical network interfaces

### Alternatives

If Docker doesn't meet your requirements:

1. **Native Installation**: Install directly on host (see README.md)
2. **Kubernetes**: Use DaemonSet with hostNetwork and privileged containers
3. **Systemd Service**: Run as systemd service on host

## References

- [Docker Security](https://docs.docker.com/engine/security/)
- [eBPF/XDP Requirements](https://github.com/cilium/ebpf)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)

