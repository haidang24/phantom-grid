# Hướng Dẫn Xác Thực SPA Động Với Chữ Ký Số (Ed25519)

## Tổng Quan

Xác thực SPA **Asymmetric Mode** sử dụng **Ed25519** (chữ ký số) kết hợp với **TOTP** để cung cấp bảo mật cao nhất. Đây là chế độ được khuyến nghị cho môi trường production.

---

## Bước 1: Tạo Key Pair (Ed25519)

### Trên Server:

```bash
# Tạo thư mục keys
mkdir -p keys

# Generate Ed25519 key pair
./bin/spa-keygen -dir ./keys

# Hoặc sử dụng Go trực tiếp
go run ./cmd/spa-keygen -dir ./keys
```

**Output:**
- `keys/spa_public.key` - Public key (dùng trên server)
- `keys/spa_private.key` - Private key (dùng trên client)

### Tạo TOTP Secret:

```bash
# Tạo TOTP secret (32 bytes, base64)
openssl rand -base64 32 > keys/totp_secret.txt

# Hoặc sử dụng PowerShell (Windows)
# [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
```

**Lưu ý:**
- TOTP secret phải **giống nhau** trên server và client
- Bảo mật file `spa_private.key` và `totp_secret.txt`

---

## Bước 2: Chạy Server (Agent)

### Lệnh Cơ Bản:

```bash
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys
```

### Lệnh Đầy Đủ (với TOTP secret):

```bash
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys \
  -spa-totp-secret "$(cat keys/totp_secret.txt)"
```

### Với Web Interface:

```bash
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys \
  -output web \
  -web-port 8080
```

### Với Dashboard:

```bash
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys \
  -output dashboard
```

**Giải thích tham số:**
- `-interface ens33`: Interface mạng (thay bằng interface của bạn)
- `-spa-mode asymmetric`: Chế độ xác thực Ed25519
- `-spa-key-dir ./keys`: Thư mục chứa keys
- `-spa-totp-secret`: TOTP secret (nếu không có, sẽ tự load từ `keys/totp_secret.txt`)

---

## Bước 3: Chạy Client (Xác Thực)

### Copy Keys Sang Client:

```bash
# Copy private key và TOTP secret sang client
scp keys/spa_private.key user@client:/path/to/keys/
scp keys/totp_secret.txt user@client:/path/to/keys/
```

**Lưu ý:** Bảo mật khi copy keys qua mạng (sử dụng SSH, VPN, hoặc USB).

### Lệnh Client Cơ Bản:

```bash
./bin/spa-client \
  -server 192.168.1.100 \
  -mode asymmetric
```

### Lệnh Client Đầy Đủ (với custom paths):

```bash
./bin/spa-client \
  -server 192.168.1.100 \
  -mode asymmetric \
  -private-key ./keys/spa_private.key \
  -totp-secret ./keys/totp_secret.txt
```

**Giải thích tham số:**
- `-server 192.168.1.100`: IP của server
- `-mode asymmetric`: Chế độ Ed25519
- `-private-key`: Đường dẫn đến private key (mặc định: `./keys/spa_private.key`)
- `-totp-secret`: Đường dẫn đến TOTP secret (mặc định: `./keys/totp_secret.txt`)

---

## Bước 4: Xác Nhận Xác Thực

### Trên Server:

Sau khi client gửi packet, server sẽ log:

```
[SPA] ✓ Successfully authenticated: 192.168.1.175 | Mode: asymmetric | Whitelisted for 30s
```

### Trên Dashboard/Web:

- SPA Success counter tăng
- IP được whitelist trong 30 giây (mặc định)
- Có thể kết nối SSH, FTP, v.v.

### Test Kết Nối:

```bash
# Sau khi xác thực thành công, kết nối SSH
ssh user@192.168.1.100

# Hoặc test port khác
telnet 192.168.1.100 22
```

---

## Ví Dụ Hoàn Chỉnh

### Server Side:

```bash
# 1. Build project
make build

# 2. Generate keys
./bin/spa-keygen -dir ./keys
openssl rand -base64 32 > keys/totp_secret.txt

# 3. Set permissions
chmod 600 keys/spa_private.key
chmod 600 keys/totp_secret.txt

# 4. Start server
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys \
  -output web \
  -web-port 8080
```

### Client Side:

```bash
# 1. Copy keys từ server
scp user@server:~/phantom-grid/keys/spa_private.key ./keys/
scp user@server:~/phantom-grid/keys/totp_secret.txt ./keys/

# 2. Set permissions
chmod 600 keys/spa_private.key
chmod 600 keys/totp_secret.txt

# 3. Build client (nếu chưa có)
make build-client

# 4. Send SPA packet
./bin/spa-client \
  -server 192.168.174.163 \
  -mode asymmetric

# 5. Kết nối SSH (trong vòng 30 giây)
ssh user@192.168.1.100
```

---

## Sử Dụng Go Trực Tiếp (Không Cần Binary)

### Server:

```bash
sudo go run ./cmd/agent/main.go \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys
```

### Client:

```bash
go run ./cmd/spa-client/main.go \
  -server 192.168.1.100 \
  -mode asymmetric \
  -private-key ./keys/spa_private.key \
  -totp-secret ./keys/totp_secret.txt
```

---

## Troubleshooting

### Lỗi: "Failed to load public key"

```bash
# Kiểm tra file tồn tại
ls -la keys/spa_public.key

# Kiểm tra permissions
chmod 644 keys/spa_public.key

# Generate lại nếu cần
./bin/spa-keygen -dir ./keys
```

### Lỗi: "Invalid Ed25519 signature"

- **Nguyên nhân:** Private key trên client không khớp với public key trên server
- **Giải pháp:** Đảm bảo copy đúng key pair

### Lỗi: "Invalid TOTP"

- **Nguyên nhân:** TOTP secret không khớp hoặc clock skew
- **Giải pháp:**
  ```bash
  # Đồng bộ thời gian
  sudo ntpdate -s time.nist.gov
  
  # Hoặc sử dụng NTP daemon
  sudo systemctl start ntp
  ```

### Lỗi: "timestamp too old/future"

- **Nguyên nhân:** Clock skew > 5 phút
- **Giải pháp:** Đồng bộ thời gian giữa client và server

---

## Bảo Mật

### Best Practices:

1. **Key Management:**
   ```bash
   # Set permissions
   chmod 600 keys/spa_private.key
   chmod 600 keys/totp_secret.txt
   
   # Encrypt keys at rest
   gpg -c keys/spa_private.key
   ```

2. **Key Rotation:**
   - Rotate keys định kỳ (mỗi 3-6 tháng)
   - Rotate TOTP secret định kỳ (mỗi 6-12 tháng)

3. **Distribution:**
   - Sử dụng SSH/SCP để copy keys
   - Hoặc sử dụng USB/encrypted channel
   - Không gửi keys qua email/chat

4. **Monitoring:**
   - Log tất cả authentication attempts
   - Monitor failed attempts
   - Alert khi có suspicious activity

---

## So Sánh Các Chế Độ

| Tính Năng | Static | Dynamic (HMAC) | Asymmetric (Ed25519) |
|-----------|--------|----------------|----------------------|
| **Bảo mật** | ⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Key Management** | Token string | Shared secrets | Key pair |
| **Replay Protection** | ❌ | ✅ | ✅ |
| **Signature** | ❌ | HMAC-SHA256 | Ed25519 |
| **TOTP** | ❌ | ✅ | ✅ |
| **Khuyến nghị** | Testing | Development | Production |

---

## Tài Liệu Tham Khảo

- [SPA Authentication Mechanism](SPA_AUTHENTICATION_MECHANISM.md) - Chi tiết cơ chế
- [Configuration Guide](configuration.md) - Cấu hình đầy đủ
- [Quick Start Guide](quick-start.md) - Hướng dẫn nhanh

---

## Kết Luận

Asymmetric mode với Ed25519 cung cấp:
- ✅ Bảo mật cao nhất
- ✅ Không cần shared secret
- ✅ Chống replay attack
- ✅ Time-based authentication (TOTP)
- ✅ Phù hợp production

**Lưu ý:** Luôn bảo mật private key và TOTP secret!

