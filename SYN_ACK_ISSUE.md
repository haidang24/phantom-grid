# Vấn Đề: SYN-ACK Được Gửi Nhưng Kali Không Gửi ACK

## 🔍 Tình Huống

Từ tcpdump và dashboard:
- ✅ SYN packets từ Kali đến server (XDP detect được)
- ✅ SYN-ACK từ server đến Kali (tcpdump thấy)
- ❌ Kali KHÔNG gửi ACK
- ❌ Honeypot Connections: 0 (không có connection nào được establish)
- ❌ Không thấy "[DEBUG] Honeypot accepted connection"

## 🔎 Nguyên Nhân Có Thể

### 1. Kali Không Nhận Được SYN-ACK

**Vấn đề:** SYN-ACK được gửi từ server nhưng không đến Kali.

**Nguyên nhân có thể:**
- Firewall trên server chặn outbound SYN-ACK
- Routing issue giữa server và Kali
- Network interface issue

**Kiểm tra:**
```bash
# Trên server, check firewall
sudo iptables -L OUTPUT -n -v | grep 9999

# Check routing
ip route get 192.168.174.175

# Test từ Kali, capture packets
sudo tcpdump -i eth0 -n 'tcp port 9999' -v
```

### 2. SYN-ACK Checksum Sai

**Vấn đề:** SYN-ACK có checksum sai, Kali drop packet.

**Nguyên nhân:** XDP có thể đã modify packet và làm checksum sai.

**Kiểm tra:** Tcpdump cho thấy checksum correct, nên không phải vấn đề này.

### 3. Kali Nhận Được Nhưng Không Gửi ACK

**Vấn đề:** Kali nhận được SYN-ACK nhưng không gửi ACK.

**Nguyên nhân có thể:**
- Firewall trên Kali chặn outbound ACK
- Network stack issue trên Kali
- Application issue (nc/telnet)

**Kiểm tra:**
```bash
# Trên Kali
sudo iptables -L -n -v
sudo tcpdump -i eth0 -n 'tcp port 9999' -v
```

### 4. TCP Handshake Timeout

**Vấn đề:** Kali gửi SYN nhưng không nhận được SYN-ACK trong timeout period.

**Nguyên nhân:** SYN-ACK bị drop hoặc delay quá lâu.

## ✅ Giải Pháp

### Solution 1: Kiểm Tra Firewall Trên Server

```bash
# Check OUTPUT rules
sudo iptables -L OUTPUT -n -v

# Nếu có rule chặn, allow:
sudo iptables -I OUTPUT -p tcp --sport 9999 -j ACCEPT
```

### Solution 2: Test Từ Kali Với Tcpdump

```bash
# Trên Kali
sudo tcpdump -i eth0 -n 'tcp port 9999' -v

# Trong terminal khác, thử connect:
nc -v 192.168.174.163 9999

# Xem tcpdump output:
# - Có thấy SYN từ Kali không?
# - Có thấy SYN-ACK từ server không?
# - Có thấy ACK từ Kali không?
```

### Solution 3: Kiểm Tra Network Connectivity

```bash
# Từ Kali, ping server
ping 192.168.174.163

# Từ server, ping Kali
ping 192.168.174.175

# Check ARP table
arp -a | grep 192.168.174
```

### Solution 4: Test Với Raw Socket

```bash
# Trên Kali, thử với raw socket để bypass network stack
sudo nc -v 192.168.174.163 9999
```

## 🧪 Debug Steps

### Step 1: Capture Packets Trên Cả Hai Bên

**Trên Server:**
```bash
sudo tcpdump -i ens33 -n 'tcp port 9999' -v -w server.pcap
```

**Trên Kali:**
```bash
sudo tcpdump -i eth0 -n 'tcp port 9999' -v -w kali.pcap
```

**Sau đó thử connect từ Kali:**
```bash
nc -v 192.168.174.163 9999
```

**Phân tích:**
- Server.pcap: Có thấy SYN-ACK được gửi không?
- Kali.pcap: Có thấy SYN-ACK được nhận không?

### Step 2: Kiểm Tra Firewall

**Trên Server:**
```bash
sudo iptables -L OUTPUT -n -v | grep 9999
sudo iptables -L -n -v | grep -E "DROP|REJECT"
```

**Trên Kali:**
```bash
sudo iptables -L -n -v | grep -E "DROP|REJECT"
```

### Step 3: Kiểm Tra Routing

**Trên Server:**
```bash
ip route get 192.168.174.175
```

**Trên Kali:**
```bash
ip route get 192.168.174.163
```

## 🎯 Root Cause Analysis

**Nếu Kali không nhận được SYN-ACK:**
- Firewall trên server chặn outbound
- Routing issue
- Network interface issue

**Nếu Kali nhận được SYN-ACK nhưng không gửi ACK:**
- Firewall trên Kali chặn outbound
- Network stack issue trên Kali
- Application issue

**Nếu cả hai đều không thấy vấn đề:**
- Có thể là timing issue
- Hoặc có vấn đề với XDP Generic mode và outbound packets

## 📝 Next Steps

1. **Capture packets trên cả hai bên** để xem SYN-ACK có đến Kali không
2. **Check firewall** trên cả server và Kali
3. **Test với raw socket** để bypass network stack
4. **Check routing** giữa server và Kali

