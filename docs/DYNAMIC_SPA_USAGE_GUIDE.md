# Hướng Dẫn Chi Tiết: Dynamic Asymmetric SPA

## Mục Lục

1. [Tổng Quan](#tổng-quan)
2. [Chuẩn Bị](#chuẩn-bị)
3. [Cài Đặt Server](#cài-đặt-server)
4. [Cài Đặt Client](#cài-đặt-client)
5. [Sử Dụng](#sử-dụng)
6. [Kiểm Tra và Debug](#kiểm-tra-và-debug)
7. [Troubleshooting](#troubleshooting)
8. [Ví Dụ Thực Tế](#ví-dụ-thực-tế)

## Tổng Quan

Dynamic Asymmetric SPA sử dụng:
- **TOTP (Time-based One-Time Password)**: Nonce thay đổi theo thời gian
- **Ed25519 Signature**: Mã hóa bất đối xứng
- **Anti-Replay Protection**: Chống tấn công phát lại
- **Packet Obfuscation**: Ẩn gói tin dưới dạng binary

### So Sánh với Static SPA

| Tính Năng | Static SPA | Dynamic Asymmetric SPA |
|-----------|------------|------------------------|
| Token | Cố định, không đổi | Thay đổi theo thời gian (TOTP) |
| Bảo Mật | Token có thể bị lộ | Chữ ký số, không thể giả mạo |
| Replay Attack | Có thể bị tấn công | Được bảo vệ bởi TOTP + replay map |
| Key Management | Shared secret | Public/Private key pair |

## Chuẩn Bị

### Yêu Cầu

- **Server**: Linux với eBPF support (kernel >= 5.8)
- **Client**: Máy có thể chạy Go hoặc sử dụng client binary
- **Network**: Server và client có thể giao tiếp qua UDP port 1337

### Cài Đặt Dependencies

```bash
# Trên server
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev golang-go

# Kiểm tra kernel version
uname -r  # Cần >= 5.8
```

## Cài Đặt Server

### Bước 1: Build Project

```bash
# Clone hoặc vào thư mục project
cd phantom-grid

# Build project
make all

# Kiểm tra binary đã được tạo
ls -lh bin/phantom-grid
```

### Bước 2: Tạo Keys

```bash
# Tạo thư mục cho keys
mkdir -p keys

# Generate Ed25519 key pair
go run ./cmd/spa-keygen -dir ./keys

# Kết quả:
# Keys generated successfully!
# Public key:  ./keys/spa_public.key
# Private key: ./keys/spa_private.key
```

**Quan Trọng**:
- `spa_public.key`: Giữ trên server (32 bytes)
- `spa_private.key`: Phân phối cho clients (64 bytes)
- Đặt quyền file: `chmod 600 keys/spa_private.key`

### Bước 3: Tạo TOTP Secret

```bash
# Generate random TOTP secret (32 bytes)
openssl rand -base64 32 > keys/totp_secret.txt

# Hoặc dùng Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))" > keys/totp_secret.txt

# Xem secret (lưu lại để chia sẻ với clients)
cat keys/totp_secret.txt
```

**Lưu Ý**: Secret này phải giống nhau trên server và tất cả clients.

### Bước 4: Cấu Hình Server

#### Cách 1: Command Line Flags (Khuyến Nghị)

```bash
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys \
  -spa-totp-secret "$(cat keys/totp_secret.txt)"
```

#### Cách 2: Environment Variables

```bash
export SPA_MODE=asymmetric
export SPA_KEY_DIR=./keys
export SPA_TOTP_SECRET="$(cat keys/totp_secret.txt)"

sudo ./bin/phantom-grid -interface ens33
```

#### Cách 3: Systemd Service

Tạo file `/etc/systemd/system/phantom-grid.service`:

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

Enable và start:

```bash
sudo systemctl enable phantom-grid
sudo systemctl start phantom-grid
sudo systemctl status phantom-grid
```

### Bước 5: Kiểm Tra Server Đang Chạy

```bash
# Xem logs
sudo journalctl -u phantom-grid -f

# Hoặc nếu chạy trực tiếp
# Logs sẽ hiển thị trên terminal
```

Bạn sẽ thấy:
```
[SPA] User-space handler started on port 1337
[SPA] Mode: asymmetric
[SYSTEM] XDP attached to interface: ens33
```

## Cài Đặt Client

### Bước 1: Copy Private Key

**Cách An Toàn**: Sử dụng SCP hoặc phương thức mã hóa

```bash
# Từ client machine
scp user@server:/path/to/phantom-grid/keys/spa_private.key ./keys/

# Đặt quyền
chmod 600 keys/spa_private.key
```

**Hoặc**: Copy thủ công qua USB, email mã hóa, etc.

### Bước 2: Copy TOTP Secret

```bash
# Từ server
cat keys/totp_secret.txt

# Copy output và lưu vào file trên client
echo "your-totp-secret-here" > keys/totp_secret.txt
chmod 600 keys/totp_secret.txt
```

### Bước 3: Tạo Client Application

#### Option A: Sử Dụng Go Client

Tạo file `client.go`:

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
	// Đọc server IP từ command line
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

Build và chạy:

```bash
go build -o client client.go
./client 192.168.1.100
```

#### Option B: Sử Dụng Python Client (Nếu có)

```python
#!/usr/bin/env python3
import socket
import struct
import time
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Load keys
with open('keys/spa_private.key', 'rb') as f:
    private_key_data = f.read()

with open('keys/totp_secret.txt', 'r') as f:
    totp_secret = f.read().strip().encode()

# Generate TOTP (simplified)
def generate_totp(secret, time_step=30):
    counter = int(time.time() / time_step)
    mac = hmac.new(secret, struct.pack('>Q', counter), hashlib.sha1)
    hash_bytes = mac.digest()
    offset = hash_bytes[19] & 0x0f
    code = struct.unpack('>I', hash_bytes[offset:offset+4])[0] & 0x7fffffff
    return code % 1000000

# Create packet
version = 1
mode = 2  # Asymmetric
timestamp = int(time.time())
totp = generate_totp(totp_secret)

# Build header
header = struct.pack('BBQ I', version, mode, timestamp, totp)

# Add random padding
import os
padding = os.urandom(32)
packet = header + padding

# Sign packet
private_key = Ed25519PrivateKey.from_private_bytes(private_key_data)
signature = private_key.sign(packet)
packet = packet + signature

# Send packet
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_addr = ('192.168.1.100', 1337)
sock.sendto(packet, server_addr)
print("SPA packet sent!")
```

## Sử Dụng

### Scenario 1: SSH Access

```bash
# 1. Send SPA packet từ client
./client 192.168.1.100

# 2. Đợi 1-2 giây để server xử lý

# 3. SSH vào server (port 22 được bảo vệ)
ssh user@192.168.1.100

# 4. Nếu thành công, bạn đã được whitelist
```

### Scenario 2: Automated Script

Tạo script tự động gửi SPA packet trước khi kết nối:

```bash
#!/bin/bash
# auto-spa.sh

SERVER_IP="192.168.1.100"
CLIENT_BINARY="./client"

# Send SPA packet
$CLIENT_BINARY $SERVER_IP

# Wait for processing
sleep 2

# Now connect
ssh user@$SERVER_IP
```

### Scenario 3: Cron Job (Periodic Whitelisting)

```bash
# Crontab entry để tự động whitelist mỗi 25 giây
# (trước khi 30 giây expire)

*/1 * * * * /path/to/client 192.168.1.100 > /dev/null 2>&1
```

## Kiểm Tra và Debug

### Server Side

#### 1. Kiểm Tra Logs

```bash
# Nếu dùng systemd
sudo journalctl -u phantom-grid -f

# Hoặc xem file logs
tail -f logs/audit.json
```

#### 2. Kiểm Tra BPF Maps

```bash
# Xem whitelist
sudo bpftool map dump name spa_whitelist

# Xem statistics
sudo bpftool map dump name spa_auth_success
sudo bpftool map dump name spa_auth_failed
```

#### 3. Kiểm Tra XDP Program

```bash
# Xem XDP programs đang chạy
ip link show ens33
# Tìm dòng: prog/xdp id XXX

# Xem chi tiết
sudo bpftool prog show
```

### Client Side

#### 1. Test Packet Creation

```go
// test_packet.go
package main

import (
	"fmt"
	"phantom-grid/internal/spa"
	"phantom-grid/internal/config"
)

func main() {
	// Test packet creation
	spaConfig := config.DefaultDynamicSPAConfig()
	// ... setup config ...
	
	packet, err := spa.CreateAsymmetricPacket(...)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Packet created: %d bytes\n", len(packet))
	}
}
```

#### 2. Verify TOTP

```go
// test_totp.go
package main

import (
	"fmt"
	"phantom-grid/internal/spa"
)

func main() {
	secret := []byte("your-secret")
	totp := spa.GenerateTOTP(secret, 30)
	fmt.Printf("Current TOTP: %d\n", totp)
	
	valid := spa.ValidateTOTP(secret, 30, 1, totp)
	fmt.Printf("Valid: %v\n", valid)
}
```

## Troubleshooting

### Lỗi: "Invalid TOTP"

**Nguyên Nhân**:
- Clock không đồng bộ
- TOTP secret khác nhau
- Tolerance window quá nhỏ

**Giải Pháp**:
```bash
# 1. Đồng bộ thời gian
sudo ntpdate -q pool.ntp.org

# 2. Kiểm tra secret
# Trên server
cat keys/totp_secret.txt
# Trên client
cat keys/totp_secret.txt
# Phải giống nhau!

# 3. Tăng tolerance
spaConfig.TOTPTolerance = 2  // Cho phép ±60 giây
```

### Lỗi: "Invalid signature"

**Nguyên Nhân**:
- Public/Private key không khớp
- Key file bị corrupt
- Sai mode (asymmetric vs dynamic)

**Giải Pháp**:
```bash
# 1. Verify key pair
# Trên server: public key
xxd keys/spa_public.key | head

# Trên client: private key (public key được extract từ private)
# Ed25519 private key chứa public key ở 32 bytes cuối

# 2. Regenerate keys nếu cần
go run ./cmd/spa-keygen -dir ./keys -force

# 3. Kiểm tra mode
# Server và client phải cùng mode (asymmetric)
```

### Lỗi: "Replay detected"

**Nguyên Nhân**:
- Gửi packet nhiều lần quá nhanh
- Replay window quá nhỏ

**Giải Pháp**:
```bash
# Đây là tính năng bảo mật, không phải lỗi!
# Nếu cần gửi lại, đợi replay window expire (default 60s)

# Hoặc tăng replay window
spaConfig.ReplayWindowSeconds = 120
```

### Lỗi: "Failed to load keys"

**Nguyên Nhân**:
- File không tồn tại
- Sai đường dẫn
- Quyền file không đúng

**Giải Pháp**:
```bash
# 1. Kiểm tra file tồn tại
ls -lh keys/spa_public.key
ls -lh keys/spa_private.key

# 2. Kiểm tra quyền
chmod 600 keys/spa_private.key
chmod 644 keys/spa_public.key

# 3. Kiểm tra đường dẫn trong code
# Đảm bảo đường dẫn đúng
```

### Lỗi: "Connection refused" hoặc "Port unreachable"

**Nguyên Nhân**:
- Server chưa start
- Firewall block port 1337
- Sai interface

**Giải Pháp**:
```bash
# 1. Kiểm tra server đang chạy
sudo systemctl status phantom-grid

# 2. Kiểm tra port listening
sudo netstat -ulnp | grep 1337

# 3. Kiểm tra firewall
sudo ufw status
sudo ufw allow 1337/udp

# 4. Kiểm tra interface
ip addr show
# Đảm bảo -interface flag đúng
```

## Ví Dụ Thực Tế

### Example 1: Basic Setup

```bash
# Server
cd /opt/phantom-grid
go run ./cmd/spa-keygen -dir ./keys
openssl rand -base64 32 > keys/totp_secret.txt
sudo ./bin/phantom-grid -interface eth0 -spa-mode asymmetric -spa-key-dir ./keys

# Client (từ máy khác)
scp user@server:/opt/phantom-grid/keys/spa_private.key ./keys/
scp user@server:/opt/phantom-grid/keys/totp_secret.txt ./keys/
./client 192.168.1.100
ssh user@192.168.1.100
```

### Example 2: Multiple Clients

```bash
# Server: Chỉ cần 1 public key
# Clients: Mỗi client có private key riêng (hoặc dùng chung)

# Option A: Mỗi client 1 key riêng (khuyến nghị)
# Generate nhiều key pairs
for i in {1..10}; do
  go run ./cmd/spa-keygen -dir ./keys/client$i
done

# Option B: Dùng chung private key (đơn giản hơn, ít bảo mật hơn)
# Copy cùng 1 private key cho tất cả clients
```

### Example 3: Integration với Ansible

```yaml
# playbook.yml
- name: Send SPA packet
  hosts: localhost
  tasks:
    - name: Run SPA client
      command: /opt/phantom-grid/client {{ server_ip }}
      
- name: Connect to server
  hosts: server
  become: yes
  tasks:
    - name: Do something
      command: echo "Connected!"
```

### Example 4: Docker Container Client

```dockerfile
# Dockerfile.client
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o client ./cmd/client

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/client /usr/local/bin/
COPY keys/ /keys/
CMD ["client", "server-ip"]
```

## Best Practices

1. **Key Management**:
   - Rotate keys định kỳ (mỗi 90 ngày)
   - Store keys trong encrypted storage
   - Use key management system (HashiCorp Vault, AWS KMS)

2. **TOTP Secret**:
   - Generate strong random secret
   - Distribute securely
   - Rotate periodically

3. **Monitoring**:
   - Log tất cả authentication attempts
   - Set up alerts cho failed attempts
   - Monitor replay attacks

4. **Network Security**:
   - Use VPN cho key distribution
   - Encrypt TOTP secret transmission
   - Limit access to key files

## Performance Tips

1. **TOTP Time Step**: 
   - 30 giây: Balance giữa security và usability
   - 60 giây: Ít requests hơn, nhưng ít secure hơn

2. **Replay Window**:
   - 60 giây: Default, tốt cho hầu hết cases
   - 120 giây: Cho high latency networks

3. **Packet Size**:
   - Obfuscation padding: 16-64 bytes
   - Larger = more obfuscation nhưng tốn bandwidth

## Tài Liệu Tham Khảo

- [`docs/DYNAMIC_SPA.md`](DYNAMIC_SPA.md) - Technical documentation
- [`docs/MIGRATION_STATIC_TO_DYNAMIC_SPA.md`](MIGRATION_STATIC_TO_DYNAMIC_SPA.md) - Migration guide
- [`internal/spa/`](../internal/spa/) - Source code
- [`pkg/spa/`](../pkg/spa/) - Client library

## Support

Nếu gặp vấn đề:
1. Check logs: `tail -f logs/audit.json`
2. Review troubleshooting section
3. Check GitHub issues
4. Open new issue với logs và error messages

