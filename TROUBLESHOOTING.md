# Troubleshooting Guide - Phantom Grid

## Vấn đề: Không thể kết nối từ máy khác đến honeypot (port 9999)

### Bước 1: Kiểm tra honeypot đang chạy

```bash
# Kiểm tra process
ps aux | grep phantom-grid

# Kiểm tra port 9999 đang listen
sudo netstat -tlnp | grep 9999
# hoặc
sudo ss -tlnp | grep 9999
```

### Bước 2: Kiểm tra XDP đã attach

```bash
# Kiểm tra XDP programs
sudo bpftool prog list | grep phantom

# Kiểm tra XDP attachment trên interface
ip link show | grep -i xdp
```

### Bước 3: Kiểm tra firewall

```bash
# Kiểm tra iptables rules
sudo iptables -L -n -v | grep 9999

# Nếu có rule chặn, xóa nó:
sudo iptables -D INPUT -p tcp --dport 9999 -j DROP  # (nếu có)
```

### Bước 4: Test local connection

```bash
# Test từ chính máy chủ
nc localhost 9999
# hoặc
telnet localhost 9999
```

Nếu local không được → vấn đề ở honeypot binding
Nếu local được nhưng external không được → vấn đề ở XDP hoặc firewall

### Bước 5: Kiểm tra network interface

```bash
# Xem interface nào đang được sử dụng
ip addr show

# Xem interface nào có XDP attached
ip link show | grep -A 2 xdp
```

**QUAN TRỌNG**: XDP phải attach vào interface **EXTERNAL** (không phải lo/loopback)

### Bước 6: Kiểm tra XDP logic

XDP phải PASS tất cả packets đến port 9999. Kiểm tra trong `bpf/phantom.c`:

```c
// Check này phải ở TRƯỚC connection tracking
if (tcp->dest == bpf_htons(HONEYPOT_PORT)) {
    return XDP_PASS; // PASS tất cả packets đến honeypot
}
```

### Bước 7: Rebuild và restart

```bash
# Rebuild
make clean
make build

# Restart với interface cụ thể
sudo ./phantom-grid -interface ens33
# hoặc
sudo ./phantom-grid -interface wlx00127b2163a6
```

### Bước 8: Debug với tcpdump

```bash
# Capture packets đến port 9999
sudo tcpdump -i any -n 'tcp port 9999' -v

# Từ máy khác, thử kết nối:
# nc <SERVER_IP> 9999
```

Nếu không thấy packets → firewall hoặc routing issue
Nếu thấy packets nhưng không có response → XDP đang drop

### Bước 9: Kiểm tra logs trong dashboard

Dashboard sẽ hiển thị:
- `[SYSTEM] ✅ Honeypot is now ACCEPTING connections on port 9999`
- `[DEBUG] Honeypot accepted connection on port 9999`

Nếu không thấy logs → honeypot không nhận được connections

### Bước 10: Test với nmap từ máy khác

```bash
# Từ máy khác (Kali/Windows)
nmap -p 9999 <SERVER_IP>

# Nếu thấy "open" → OK
# Nếu thấy "filtered" → XDP đang drop hoặc firewall
# Nếu thấy "closed" → Honeypot không bind được port
```

## Common Issues

### Issue 1: "Port 9999 is NOT bound"

**Nguyên nhân**: Port 9999 đã được sử dụng bởi process khác

**Giải pháp**:
```bash
# Tìm process đang dùng port 9999
sudo lsof -i :9999
# hoặc
sudo fuser 9999/tcp

# Kill process
sudo kill -9 <PID>
```

### Issue 2: "XDP attached to wrong interface"

**Nguyên nhân**: XDP attach vào loopback (lo) thay vì external interface

**Giải pháp**:
```bash
# Chỉ định interface cụ thể
sudo ./phantom-grid -interface ens33
```

### Issue 3: "Connection timeout from external machine"

**Nguyên nhân**: XDP đang drop packets hoặc firewall chặn

**Giải pháp**:
1. Kiểm tra XDP logic (xem Bước 6)
2. Kiểm tra firewall (xem Bước 3)
3. Rebuild XDP program (xem Bước 7)

### Issue 4: "Local works but external doesn't"

**Nguyên nhân**: XDP chỉ xử lý INGRESS traffic, nhưng có thể đang drop SYN packets

**Giải pháp**:
- Đảm bảo check port 9999 ở TRƯỚC tất cả logic khác trong XDP
- Rebuild và test lại

## Debug Script

Chạy script debug tự động:

```bash
chmod +x debug_connection.sh
./debug_connection.sh
```

Script sẽ kiểm tra:
- Process đang chạy
- Port 9999 listening
- XDP programs
- XDP attachment
- Firewall rules
- Local connection test

