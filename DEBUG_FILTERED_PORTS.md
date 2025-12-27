# Debug: Tại Sao Ports Vẫn Hiện "Filtered"

## 🔍 Vấn Đề

Khi quét từ external machine, các ports vẫn hiện **"filtered"** thay vì **"open"**, mặc dù đã redirect đến honeypot.

## 🔎 Nguyên Nhân Có Thể

### 1. XDP Không PASS Sau Khi Redirect

**Vấn đề:** Sau khi redirect port, code có thể không return XDP_PASS đúng cách.

**Kiểm tra:**

```c
// SAU KHI REDIRECT, PHẢI RETURN XDP_PASS NGAY
update_csum16(&tcp->check, old_port, new_port);
tcp->dest = new_port;
mutate_os_personality(ip, tcp);
return XDP_PASS; // ← QUAN TRỌNG: Return ngay sau redirect
```

### 2. Checksum Update Không Đúng

**Vấn đề:** Nếu checksum không được update đúng, kernel sẽ drop packet.

**Kiểm tra:**

- `update_csum16()` phải được gọi TRƯỚC khi thay đổi port
- Checksum phải được tính lại cho cả TCP header

### 3. Honeypot Không Bind Port 9999

**Vấn đề:** Nếu honeypot không bind được port 9999, kernel sẽ gửi RST → port hiện "closed" hoặc "filtered".

**Kiểm tra:**

```bash
# Check port 9999 đang listen
sudo netstat -tlnp | grep 9999
# hoặc
sudo ss -tlnp | grep 9999
```

### 4. XDP Generic Mode Không Hoạt Động

**Vấn đề:** Nếu XDP không attach đúng mode, packets có thể không được xử lý.

**Kiểm tra:**

```bash
# Check XDP attachment
ip link show ens33 | grep xdp
# Should show: "xdp" hoặc "xdpgeneric"
```

### 5. Firewall Chặn

**Vấn đề:** iptables hoặc firewall khác có thể chặn packets.

**Kiểm tra:**

```bash
# Check iptables rules
sudo iptables -L -n -v
```

## ✅ Giải Pháp

### Step 1: Đảm Bảo Logic XDP Đúng

```c
// 1. Check SSH → DROP nếu không whitelisted
if (tcp->dest == SSH_PORT) {
    if (!is_spa_whitelisted(src_ip)) return XDP_DROP;
    return XDP_PASS;
}

// 2. Check stealth scan → DROP
if (is_stealth_scan(tcp)) return XDP_DROP;

// 3. Check port 9999 → PASS (QUAN TRỌNG: Check TRƯỚC redirect)
if (tcp->dest == HONEYPOT_PORT) {
    mutate_os_personality(ip, tcp);
    return XDP_PASS;
}

// 4. Redirect tất cả ports khác → 9999
update_csum16(&tcp->check, old_port, new_port);
tcp->dest = HONEYPOT_PORT;
mutate_os_personality(ip, tcp);
return XDP_PASS; // ← QUAN TRỌNG: Return ngay
```

### Step 2: Kiểm Tra Honeypot Binding

```bash
# Check honeypot đang chạy
ps aux | grep phantom-grid

# Check port 9999 listening
sudo netstat -tlnp | grep 9999
```

**Nếu port 9999 không listening:**

- Check logs trong dashboard
- Check error messages: "Cannot bind port 9999"
- Free port 9999: `sudo lsof -i :9999 && sudo kill -9 <PID>`

### Step 3: Kiểm Tra XDP Attachment

```bash
# Check XDP programs
sudo bpftool prog list | grep phantom

# Check XDP mode
ip link show ens33
# Should show: "xdp" or "xdpgeneric"
```

**Nếu không thấy XDP:**

- Rebuild: `make clean && make build`
- Run với sudo: `sudo ./phantom-grid -interface ens33`
- Check logs: "XDP attached to interface"

### Step 4: Test Từ External Machine

```bash
# Từ máy khác (Kali/Windows)
nmap -p 80,443,9999 <SERVER_IP>

# Expected:
# - Port 80: open (redirected to honeypot)
# - Port 443: open (redirected to honeypot)
# - Port 9999: open (honeypot)
```

**Nếu vẫn "filtered":**

- Check XDP statistics trong dashboard
- Check honeypot logs: "TRAP HIT"
- Test với tcpdump: `sudo tcpdump -i ens33 -n 'tcp port 80'`

## 🔧 Debug Commands

```bash
# 1. Check XDP attachment
ip link show ens33 | grep -A 2 xdp

# 2. Check honeypot listening
sudo netstat -tlnp | grep 9999

# 3. Check XDP statistics
sudo bpftool map dump name attack_stats

# 4. Capture packets
sudo tcpdump -i ens33 -n 'tcp port 80' -v

# 5. Test connection
nc <SERVER_IP> 80
# Expected: Honeypot banner

# 6. Check firewall
sudo iptables -L -n -v | grep 9999
```

## 📊 So Sánh "Filtered" vs "Open"

| State        | Nghĩa             | Nguyên Nhân                                    |
| ------------ | ----------------- | ---------------------------------------------- |
| **filtered** | Không có response | XDP DROP, firewall chặn, hoặc không có service |
| **closed**   | RST response      | Service không listening                        |
| **open**     | SYN-ACK response  | Service listening và respond                   |

**Mục tiêu:** Ports phải hiện **"open"** sau khi redirect đến honeypot.

## 🎯 Checklist

- [ ] XDP return XDP_PASS sau khi redirect
- [ ] Checksum được update đúng
- [ ] Honeypot bind port 9999 thành công
- [ ] XDP attach với Generic mode
- [ ] Không có firewall chặn
- [ ] Test từ external machine (không phải localhost)
