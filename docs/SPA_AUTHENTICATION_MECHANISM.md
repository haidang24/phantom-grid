# Cơ Chế Xác Thực SPA (Single Packet Authorization) - Chi Tiết

## Tổng Quan

SPA (Single Packet Authorization) là cơ chế xác thực cho phép client gửi **một gói tin UDP duy nhất** để được whitelist trên server. Hệ thống hỗ trợ 3 chế độ:

1. **Static Mode**: Token tĩnh (đơn giản nhất)
2. **Dynamic Mode**: HMAC-SHA256 + TOTP
3. **Asymmetric Mode**: Ed25519 signature + TOTP

---

## 1. STATIC MODE (Chế Độ Tĩnh)

### Cấu Trúc Packet
```
[Token String] (21 bytes mặc định, có thể tùy chỉnh)
Ví dụ: "PHANTOM_GRID_SPA_2025"
```

### Flow Xử Lý

#### Client Side:
```go
// pkg/spa/client.go
func (c *Client) SendMagicPacket() error {
    tokenBytes := []byte(c.StaticToken)  // "PHANTOM_GRID_SPA_2025"
    conn.Write(tokenBytes)                // Gửi qua UDP port 1337
}
```

#### Server Side (eBPF - Kernel):
```c
// internal/ebpf/programs/phantom.c
if (udp->dest == bpf_htons(1337)) {
    if (verify_magic_packet(payload, data_end)) {
        spa_whitelist_ip(src_ip);  // Whitelist ngay trong kernel
        return XDP_DROP;
    }
}
```

#### Server Side (User-space):
```go
// internal/spa/handler.go
if h.isStaticPacket(packetData) {
    // eBPF đã whitelist, chỉ log lại
    h.mapLoader.WhitelistIP(clientIP, replayWindow)
    return
}
```

### Ưu Điểm:
- ✅ Đơn giản, nhanh
- ✅ Xử lý trong kernel (eBPF) → rất nhanh
- ✅ Không cần key management

### Nhược Điểm:
- ❌ Token tĩnh → dễ bị replay attack
- ❌ Không có timestamp → không chống được replay
- ❌ Không có signature → dễ bị giả mạo

---

## 2. DYNAMIC MODE (Chế Độ Động - HMAC)

### Cấu Trúc Packet

```
┌─────────────────────────────────────────────────────────┐
│ HEADER (14 bytes)                                        │
├─────────────────────────────────────────────────────────┤
│ Version (1 byte)    │ 0x01                            │
│ Mode (1 byte)        │ 0x01 (Dynamic)                  │
│ Timestamp (8 bytes)  │ Unix timestamp (big-endian)      │
│ TOTP (4 bytes)       │ TOTP code (big-endian)           │
├─────────────────────────────────────────────────────────┤
│ RANDOM PADDING (16-64 bytes) - Obfuscation              │
├─────────────────────────────────────────────────────────┤
│ HMAC-SHA256 (32 bytes) - Signature                      │
└─────────────────────────────────────────────────────────┘

Tổng: 62-110 bytes (tùy padding)
```

### Flow Xử Lý Chi Tiết

#### Bước 1: Client Tạo Packet

```go
// internal/spa/packet.go - CreateDynamicPacket()
func CreateDynamicPacket(hmacSecret, totpSecret []byte, timeStep int, enableObfuscation bool) ([]byte, error) {
    // 1. Generate TOTP
    totp := GenerateTOTP(totpSecret, timeStep)  // HMAC-SHA1(TOTP_secret, timestamp/30)
    timestamp := time.Now().Unix()
    
    // 2. Tạo header
    packet := make([]byte, 14)
    packet[0] = 1              // Version 1
    packet[1] = 1              // Mode: Dynamic
    binary.BigEndian.PutUint64(packet[2:10], uint64(timestamp))
    binary.BigEndian.PutUint32(packet[10:14], totp)
    
    // 3. Thêm random padding (16-64 bytes) để obfuscate
    if enableObfuscation {
        padding := make([]byte, randomSize(16-64))
        rand.Read(padding)
        packet = append(packet, padding...)
    }
    
    // 4. Tính HMAC-SHA256
    mac := hmac.New(sha256.New, hmacSecret)
    mac.Write(packet)  // HMAC(header + padding)
    hmacValue := mac.Sum(nil)
    
    // 5. Append HMAC
    packet = append(packet, hmacValue...)
    
    return packet, nil
}
```

#### Bước 2: Client Gửi Packet

```go
// pkg/spa/client_dynamic.go
func (c *DynamicClient) SendMagicPacket() error {
    packetData := spa.CreateDynamicPacket(
        c.HMACSecret,
        c.TOTPSecret,
        c.SPAConfig.TOTPTimeStep,  // 30 seconds
        c.SPAConfig.EnableObfuscation,
    )
    conn.Write(packetData)  // UDP port 1337
}
```

#### Bước 3: Server Nhận Packet (eBPF)

```c
// internal/ebpf/programs/phantom.c
if (udp->dest == bpf_htons(1337)) {
    __u8 first_byte = *((__u8 *)payload);
    if (first_byte == 1) {
        // Dynamic packet → pass to user-space
        return XDP_PASS;
    }
}
```

#### Bước 4: Server Parse Packet (User-space)

```go
// internal/spa/handler.go - processPacket()
func (h *Handler) processPacket(packetData []byte, clientIP net.IP) {
    // Kiểm tra nếu là dynamic packet (first byte == 1)
    if len(packetData) > 0 && packetData[0] == 1 {
        goto parseDynamic
    }
    
parseDynamic:
    // Parse packet structure
    packet, err := ParseSPAPacket(packetData)
    // packet.Version = 1
    // packet.Mode = 1 (Dynamic)
    // packet.Timestamp = ...
    // packet.TOTP = ...
    // packet.Signature = HMAC (32 bytes)
}
```

#### Bước 5: Server Verify Packet

```go
// internal/spa/verifier.go - VerifyPacket()
func (v *Verifier) VerifyPacket(packetData []byte) (bool, error) {
    // 1. Parse packet
    packet, err := ParseSPAPacket(packetData)
    
    // 2. Check version
    if packet.Version != 1 {
        return false, fmt.Errorf("unsupported version")
    }
    
    // 3. Validate timestamp (±5 minutes tolerance)
    timeDiff := abs(time.Now().Unix() - packet.Timestamp)
    if timeDiff > 300 {  // 5 minutes
        return false, fmt.Errorf("timestamp too old/future")
    }
    
    // 4. Validate TOTP (±tolerance steps)
    validTOTP := ValidateTOTP(
        v.spaConfig.TOTPSecret,
        v.spaConfig.TOTPTimeStep,      // 30 seconds
        v.spaConfig.TOTPTolerance,      // ±1 step
        packet.TOTP,
    )
    if !validTOTP {
        return false, fmt.Errorf("invalid TOTP")
    }
    
    // 5. Verify HMAC signature
    valid := VerifyDynamicPacket(
        v.spaConfig.HMACSecret,
        packet,
        packetData,
    )
    if !valid {
        return false, fmt.Errorf("invalid HMAC signature")
    }
    
    return true, nil
}
```

#### Bước 6: TOTP Validation Chi Tiết

```go
// internal/spa/totp.go
func ValidateTOTP(secret []byte, timeStep, tolerance int, receivedTOTP uint32) bool {
    currentTime := time.Now().Unix()
    currentStep := currentTime / int64(timeStep)  // timeStep = 30
    
    // Check current step và ±tolerance steps
    for i := -tolerance; i <= tolerance; i++ {
        step := currentStep + int64(i)
        expectedTOTP := TOTP(secret, timeStep, step*int64(timeStep))
        if expectedTOTP == receivedTOTP {
            return true  // Match!
        }
    }
    return false
}

// TOTP generation (RFC 4226)
func TOTP(secret []byte, timeStep int, timestamp int64) uint32 {
    counter := uint64(timestamp / int64(timeStep))
    
    // HMAC-SHA1
    mac := hmac.New(sha1.New, secret)
    binary.Write(mac, binary.BigEndian, counter)
    hash := mac.Sum(nil)
    
    // Dynamic truncation
    offset := hash[19] & 0x0f
    code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
    
    return code % 1000000  // 6-digit code
}
```

#### Bước 7: HMAC Verification

```go
// internal/spa/packet.go
func VerifyDynamicPacket(hmacSecret []byte, packet *SPAPacket, packetData []byte) bool {
    // Reconstruct signed data (header + padding, WITHOUT signature)
    signedData := packetData[:len(packetData)-32]  // Remove HMAC (32 bytes)
    
    // Compute expected HMAC
    mac := hmac.New(sha256.New, hmacSecret)
    mac.Write(signedData)
    expectedHMAC := mac.Sum(nil)
    
    // Compare (constant-time)
    return hmac.Equal(expectedHMAC, packet.Signature)
}
```

#### Bước 8: Whitelist IP

```go
// internal/spa/handler.go
if valid {
    // Whitelist IP trong eBPF map
    h.mapLoader.WhitelistIP(clientIP, replayWindow)  // 30-300 seconds
    
    // Log success
    log("[SPA] ✓ Successfully authenticated: %s", clientIP)
}
```

### Ưu Điểm:
- ✅ Có timestamp → chống replay attack
- ✅ Có TOTP → time-based authentication
- ✅ Có HMAC signature → chống giả mạo
- ✅ Random padding → obfuscation

### Nhược Điểm:
- ❌ Cần shared secret (HMAC secret + TOTP secret)
- ❌ Phải đồng bộ thời gian (±5 phút)

---

## 3. ASYMMETRIC MODE (Chế Độ Bất Đối Xứng - Ed25519)

### Cấu Trúc Packet

```
┌─────────────────────────────────────────────────────────┐
│ HEADER (14 bytes) - Giống Dynamic Mode                  │
├─────────────────────────────────────────────────────────┤
│ RANDOM PADDING (16-64 bytes)                            │
├─────────────────────────────────────────────────────────┤
│ Ed25519 SIGNATURE (64 bytes)                             │
└─────────────────────────────────────────────────────────┘

Tổng: 94-158 bytes
```

### Flow Xử Lý (Tương Tự Dynamic, Khác Signature)

#### Client Tạo Packet:

```go
// internal/spa/packet.go - CreateAsymmetricPacket()
func CreateAsymmetricPacket(privateKey ed25519.PrivateKey, totpSecret []byte, ...) ([]byte, error) {
    // 1-3. Tạo header + padding (giống Dynamic)
    packet := createHeader(totpSecret, ...)
    packet = append(packet, randomPadding...)
    
    // 4. Sign với Ed25519 private key
    signature := ed25519.Sign(privateKey, packet)  // Sign header + padding
    
    // 5. Append signature (64 bytes)
    packet = append(packet, signature...)
    
    return packet, nil
}
```

#### Server Verify:

```go
// internal/spa/packet.go - VerifyAsymmetricPacket()
func VerifyAsymmetricPacket(publicKey ed25519.PublicKey, packet *SPAPacket, packetData []byte) bool {
    // Reconstruct signed data
    signedData := packetData[:len(packetData)-64]  // Remove signature (64 bytes)
    
    // Verify Ed25519 signature
    return ed25519.Verify(publicKey, signedData, packet.Signature)
}
```

### Ưu Điểm:
- ✅ Public key cryptography → không cần shared secret
- ✅ Chỉ server cần public key → bảo mật hơn
- ✅ Ed25519 → nhanh, an toàn

### Nhược Điểm:
- ❌ Cần quản lý key pair
- ❌ Signature lớn hơn (64 bytes vs 32 bytes)

---

## 4. TỔNG HỢP SO SÁNH

| Tính Năng | Static | Dynamic (HMAC) | Asymmetric (Ed25519) |
|-----------|--------|-----------------|----------------------|
| **Packet Size** | 21 bytes | 62-110 bytes | 94-158 bytes |
| **Timestamp** | ❌ | ✅ | ✅ |
| **TOTP** | ❌ | ✅ | ✅ |
| **Signature** | ❌ | ✅ (HMAC-SHA256) | ✅ (Ed25519) |
| **Replay Protection** | ❌ | ✅ | ✅ |
| **Key Management** | Token string | Shared secrets | Key pair |
| **Performance** | ⚡⚡⚡ (Kernel) | ⚡⚡ (User-space) | ⚡⚡ (User-space) |
| **Security** | ⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |

---

## 5. FLOW TỔNG QUÁT

```
┌─────────────┐
│   CLIENT    │
└──────┬──────┘
       │
       │ 1. Tạo packet (Static/Dynamic/Asymmetric)
       │
       │ 2. Gửi UDP packet → Server:1337
       │
       ▼
┌─────────────────────────────────────┐
│         NETWORK (UDP)               │
└─────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│   SERVER - eBPF (Kernel)            │
│   - Kiểm tra port 1337              │
│   - Static: verify_magic_packet()   │
│   - Dynamic: Pass to user-space     │
└─────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│   SERVER - User-space (Go)          │
│   1. Parse packet                   │
│   2. Validate timestamp (±5 min)   │
│   3. Validate TOTP (±tolerance)     │
│   4. Verify signature (HMAC/Ed25519) │
│   5. Whitelist IP trong eBPF map     │
└─────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│   eBPF MAP (Whitelist)              │
│   - IP được whitelist               │
│   - Thời gian: 30-300 seconds       │
│   - TCP connections được allow      │
└─────────────────────────────────────┘
```

---

## 6. BẢO MẬT

### Các Lớp Bảo Vệ:

1. **Timestamp Validation**: Chống replay attack (packet cũ)
2. **TOTP**: Time-based one-time password → mỗi 30 giây một code mới
3. **Signature**: HMAC hoặc Ed25519 → chống giả mạo
4. **Random Padding**: Obfuscation → khó phân tích packet
5. **Replay Window**: IP chỉ được whitelist trong thời gian giới hạn

### Tấn Công và Phòng Thủ:

| Tấn Công | Phòng Thủ |
|---------|----------|
| Replay attack (gửi lại packet cũ) | ✅ Timestamp validation (±5 phút) |
| Packet forgery (giả mạo packet) | ✅ HMAC/Ed25519 signature |
| Brute force TOTP | ✅ 6-digit code (1M khả năng) + time window |
| Packet analysis | ✅ Random padding obfuscation |
| Long-term replay | ✅ Replay window (30-300s) |

---

## 7. CONFIGURATION

### Static Mode:
```bash
sudo ./bin/phantom-grid -interface ens33 -spa-mode static -spa-static-token "MY_TOKEN"
```

### Dynamic Mode:
```bash
# Server
sudo ./bin/phantom-grid -interface ens33 -spa-mode dynamic \
  -spa-totp-secret "$(cat keys/totp_secret.txt)" \
  -spa-key-dir ./keys

# Client
./bin/spa-client -server 192.168.1.100 -mode dynamic \
  -hmac-secret "$(cat keys/hmac_secret.txt)" \
  -totp-secret "$(cat keys/totp_secret.txt)"
```

### Asymmetric Mode:
```bash
# Server
sudo ./bin/phantom-grid -interface ens33 -spa-mode asymmetric \
  -spa-key-dir ./keys

# Client
./bin/spa-client -server 192.168.1.100 -mode asymmetric \
  -private-key keys/spa_private.key \
  -totp-secret "$(cat keys/totp_secret.txt)"
```

---

## 8. DEBUGGING

### Kiểm Tra Packet:
```bash
# Capture SPA packets
sudo tcpdump -i ens33 -n -X udp port 1337

# Xem eBPF maps
sudo bpftool map show
sudo bpftool map dump id <map_id>
```

### Log Messages:
- `[SPA] ✓ Successfully authenticated` → Success
- `[SPA] ✗ Failed to parse packet` → Parse error
- `[SPA] ✗ Invalid packet` → Verification failed
- `[SPA] ⚠ Token length mismatch` → Wrong token length

---

## Kết Luận

SPA cung cấp cơ chế xác thực mạnh mẽ với 3 mức độ bảo mật:
- **Static**: Đơn giản, nhanh, phù hợp testing
- **Dynamic**: Cân bằng giữa bảo mật và đơn giản
- **Asymmetric**: Bảo mật cao nhất, phù hợp production

Tất cả đều hoạt động với **một gói tin UDP duy nhất**, không cần handshake hay connection setup.

