# Hướng Dẫn Debug SPA Authentication và SSH Connection

## Tổng Quan

Khi gặp vấn đề SSH không hoạt động sau khi SPA authentication thành công, cần debug để tìm nguyên nhân.

---

## Phân Biệt Server và Client

### SERVER (Nơi chạy Phantom Grid Agent)
- **IP**: 192.168.174.163 (ví dụ)
- **Chức năng**:
  - Chạy `phantom-grid` agent
  - Có eBPF/XDP program
  - Nhận và xử lý SPA packets
  - Kiểm tra whitelist cho SSH connections
- **Scripts monitor**: ✅ **CHẠY Ở ĐÂY**

### CLIENT (Nơi gửi SPA và SSH)
- **IP**: 192.168.174.175 (ví dụ)
- **Chức năng**:
  - Gửi SPA packets
  - Kết nối SSH
  - Không có eBPF program
- **Scripts monitor**: ❌ Không cần

---

## Workflow Debug Đúng

### Bước 1: Trên SERVER

**Terminal 1 - Start Agent:**
```bash
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys \
  -output dashboard
```

**Terminal 2 - Monitor Packets:**
```bash
# Monitor đơn giản
./scripts/quick-monitor.sh 192.168.174.175

# Hoặc monitor chi tiết với colors
./scripts/monitor-all-packets.sh 192.168.174.175 ens33
```

**Terminal 3 - Debug SSH Connection:**
```bash
./scripts/debug-ssh-connection.sh 192.168.174.163 192.168.174.175 ens33
```

### Bước 2: Trên CLIENT

**Terminal 1 - Gửi SPA Packet:**
```bash
./bin/spa-client \
  -server 192.168.174.163 \
  -mode asymmetric
```

**Terminal 2 - Test SSH:**
```bash
# SSH với verbose để xem chi tiết
ssh -v user@192.168.174.163

# Hoặc với nhiều verbose hơn
ssh -vvv user@192.168.174.163
```

---

## Phân Tích Kết Quả Monitor

### ✅ Nếu Thấy:

1. **SPA Packet (UDP 1337)**
   ```
   [SPA] UDP 192.168.174.175.xxxxx > 192.168.174.163.1337
   ```
   → Authentication packet được gửi thành công

2. **SSH SYN Packet**
   ```
   [SSH-SYN] TCP 192.168.174.175.xxxxx > 192.168.174.163.22 Flags [S]
   ```
   → Client đang cố kết nối SSH

3. **SSH SYN-ACK Packet**
   ```
   [SSH-SYN-ACK] TCP 192.168.174.163.22 > 192.168.174.175.xxxxx Flags [S.]
   ```
   → ✅ **Server đang respond (OK!)** - Whitelist hoạt động!

4. **SSH RST Packet**
   ```
   [SSH-RST] TCP ... Flags [R]
   ```
   → Connection bị reset (có thể do firewall hoặc SSH service)

### ❌ Nếu KHÔNG Thấy:

1. **Không thấy SSH SYN-ACK**
   - Chỉ thấy SSH SYN từ client
   - Không có response từ server
   - → **Server KHÔNG respond (bị DROP bởi eBPF)**
   - **Nguyên nhân có thể**:
     - Whitelist chưa được update
     - Expiry đã hết hạn
     - Map update có delay
     - Race condition

2. **Không thấy SPA Packet**
   - Client không gửi được SPA packet
   - → Kiểm tra network connectivity

---

## Debug Chi Tiết

### 1. Kiểm Tra Whitelist Entry

**Trên SERVER:**
```bash
# Xem tất cả maps
sudo bpftool map show | grep whitelist

# Dump whitelist map
sudo bpftool map dump name spa_whitelist

# Hoặc tìm map ID và dump
MAP_ID=$(sudo bpftool map show | grep spa_whitelist | awk '{print $1}')
sudo bpftool map dump id $MAP_ID
```

**Kiểm tra IP:**
```bash
python3 << 'EOF'
import struct
import socket

ip_str = "192.168.174.175"
ip_bytes = socket.inet_aton(ip_str)
ip_uint32 = struct.unpack('>I', ip_bytes)[0]

print(f"IP: {ip_str}")
print(f"Key trong map: {ip_uint32}")
print(f"Key (hex): 0x{ip_uint32:08x}")
EOF
```

### 2. Kiểm Tra Expiry Timestamp

```bash
# Đọc expiry từ map
sudo bpftool map dump name spa_whitelist | python3 << 'EOF'
import json
import sys

data = json.load(sys.stdin)
for entry in data:
    key = entry['key']
    value = entry['value']
    
    # Convert key từ uint32 sang IP
    ip_bytes = [(key >> 24) & 0xFF, (key >> 16) & 0xFF, (key >> 8) & 0xFF, key & 0xFF]
    ip_str = ".".join(map(str, ip_bytes))
    
    # Check expiry
    import os
    uptime = float(open('/proc/uptime').read().split()[0])
    current_ns = int(uptime * 1e9)
    expiry_ns = value
    
    print(f"IP: {ip_str}")
    print(f"  Key: {key}")
    print(f"  Expiry: {expiry_ns} ns")
    print(f"  Current: {current_ns} ns")
    print(f"  Diff: {expiry_ns - current_ns} ns ({int((expiry_ns - current_ns) / 1e9)} seconds)")
    
    if expiry_ns > current_ns:
        print(f"  Status: ✓ Valid (còn {int((expiry_ns - current_ns) / 1e9)} seconds)")
    else:
        print(f"  Status: ✗ Expired!")
    print()
EOF
```

### 3. Kiểm Tra eBPF Program

```bash
# Xem XDP program
ip link show ens33 | grep xdp

# Xem eBPF programs
sudo bpftool prog show

# Xem eBPF maps
sudo bpftool map show
```

### 4. Kiểm Tra Logs

**Trên SERVER Dashboard:**
- Xem log "Successfully authenticated"
- Xem log "Failed to whitelist" (nếu có)
- Xem SPA AUTH counter

**Trên SERVER Terminal:**
```bash
# Xem system logs
sudo journalctl -u phantom-grid -f

# Hoặc xem process logs
ps aux | grep phantom-grid
```

---

## Các Vấn Đề Thường Gặp

### Vấn Đề 1: Whitelist Entry Không Tồn Tại

**Triệu chứng:**
- Authentication thành công
- SSH không hoạt động
- Map dump không thấy entry

**Giải pháp:**
- Kiểm tra `WhitelistIP()` có được gọi không
- Kiểm tra error logs
- Thêm logging trong `map_loader.go`

### Vấn Đề 2: Expiry Đã Hết Hạn

**Triệu chứng:**
- Entry có trong map
- Nhưng expiry < current time

**Giải pháp:**
- Kiểm tra cách tính expiry
- Đảm bảo uptime được đọc đúng
- Thêm buffer time

### Vấn Đề 3: Race Condition

**Triệu chứng:**
- Authentication thành công
- SSH packet đến ngay sau đó
- SSH bị DROP

**Giải pháp:**
- Thêm delay sau khi whitelist
- Verify map update thành công
- Retry mechanism

### Vấn Đề 4: Byte Order Mismatch

**Triệu chứng:**
- Entry có trong map
- Nhưng eBPF không tìm thấy

**Giải pháp:**
- Đảm bảo IP được convert đúng (network byte order)
- Verify key trong map match với IP

---

## Scripts Debug

### 1. Quick Monitor
```bash
./scripts/quick-monitor.sh [CLIENT_IP]
```

### 2. Monitor All Packets
```bash
./scripts/monitor-all-packets.sh [CLIENT_IP] [INTERFACE]
```

### 3. Debug SSH Connection
```bash
./scripts/debug-ssh-connection.sh [SERVER_IP] [CLIENT_IP] [INTERFACE]
```

### 4. Debug TOTP
```bash
./scripts/debug-totp.sh
```

### 5. Debug Whitelist
```bash
./scripts/debug-whitelist.sh [CLIENT_IP]
```

---

## Tóm Tắt

1. **Monitor scripts chạy ở SERVER** - để xem packets đến server
2. **Client chỉ gửi SPA và SSH** - không cần monitor
3. **Tất cả debug ở SERVER** - vì eBPF program chạy ở đó
4. **Kiểm tra whitelist entry** - đảm bảo có trong map
5. **Kiểm tra expiry** - đảm bảo chưa hết hạn
6. **Monitor packets** - xem SSH SYN-ACK có được trả về không

---

## Kết Luận

Nếu SSH không hoạt động sau khi authentication thành công:
1. Chạy monitor scripts ở **SERVER**
2. Kiểm tra whitelist entry trong map
3. Kiểm tra expiry timestamp
4. Xem packets flow (SYN → SYN-ACK?)
5. Debug từng bước để tìm nguyên nhân

