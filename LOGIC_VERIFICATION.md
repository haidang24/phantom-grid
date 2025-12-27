# Logic Verification - Phantom Grid

## ✅ Constants Synchronization

### Ports
- **HONEYPOT_PORT**: `9999` (đồng bộ giữa `bpf/phantom.c`, `bpf/phantom_egress.c`, `cmd/agent/main.go`)
- **SPA_MAGIC_PORT**: `1337` (đồng bộ giữa `bpf/phantom.c`, `cmd/spa-client/main.go`)
- **SSH_PORT**: `22` (đồng bộ giữa `bpf/phantom.c`, `bpf/phantom_spa.c`)

### SPA Token
- **SPA_SECRET_TOKEN**: `"PHANTOM_GRID_SPA_2025"` (21 bytes)
- **SPA_TOKEN_LEN**: `21`
- Đồng bộ giữa: `bpf/phantom.c`, `bpf/phantom_spa.c`, `cmd/spa-client/main.go`

### Fake Ports
- **fakePorts** trong `cmd/agent/main.go` khớp 100% với **is_fake_port()** trong `bpf/phantom.c`
- Danh sách: 80, 443, 3306, 5432, 6379, 27017, 8080, 8443, 9000, 21, 23, 3389, 5900, 1433, 1521, 5433, 11211, 27018, 9200, 5601, 3000, 5000, 8000, 8888
- **LƯU Ý**: 9999 (HONEYPOT_PORT) KHÔNG phải fake port

### Critical Asset Ports
- SSH: 22
- MySQL: 3306
- PostgreSQL: 5432
- MongoDB: 27017
- Redis: 6379
- Admin Panels: 8080, 8443, 9000

## ✅ XDP Logic Flow (bpf/phantom.c)

### Packet Processing Order (QUAN TRỌNG)

1. **Bounds Checking**: Kiểm tra packet boundaries
2. **Ethernet Header**: Chỉ xử lý IPv4 (ETH_P_IP)
3. **ICMP**: PASS tất cả ICMP (ping, etc.)
4. **UDP (SPA)**:
   - Nếu dest_port == 1337 → Verify Magic Packet
   - Valid → Whitelist IP, DROP packet
   - Invalid → DROP packet, update stats
   - Khác → PASS (DNS, DHCP, etc.)
5. **TCP Processing**:
   - **Critical Assets Check**: Nếu dest_port là critical asset → DROP (trừ khi whitelisted)
   - **Stealth Scan Detection**: DROP Xmas, Null, FIN, ACK scans
   - **HONEYPOT_PORT Check (QUAN TRỌNG NHẤT)**: Nếu dest_port == 9999 → PASS ngay lập tức
   - **Connection Tracking**: Nếu connection đã được redirect → Redirect packets đến 9999
   - **THE MIRAGE**: Nếu SYN packet đến fake port → Redirect đến 9999, track connection
   - **Default**: Nếu SYN đến port không phải fake/critical → DROP (ẩn port)
   - **Non-SYN packets**: PASS (outbound, established connections)

### Key Logic Points

1. **Port 9999 Check MUST be FIRST**: Đảm bảo tất cả packets đến honeypot được PASS
2. **Connection Tracking**: Track bằng `(src_ip << 32) | (src_port << 16)` để handle port redirection
3. **Checksum Recalculation**: Sử dụng `update_csum16()` khi modify ports
4. **OS Personality Mutation**: Randomize TTL và Window Size để confuse fingerprinting

## ✅ Connection Tracking Logic

### Redirect Flow
1. **SYN packet đến fake port (80)**:
   - XDP redirects: `dest_port = 80 → 9999`
   - Track connection: `(src_ip, src_port) → original_port (80)`
   - Update checksum
   - PASS packet (now dest_port = 9999)

2. **Subsequent packets (ACK, data, FIN, RST)**:
   - Nếu `dest_port == 9999` → PASS (checked first)
   - Nếu connection tracked và `dest_port == original_port` → Redirect to 9999
   - Cleanup tracking on FIN/RST from client

### Edge Cases Handled
- Packets đến original port sau khi SYN đã redirect (shouldn't happen, but handled gracefully)
- Connection cleanup on FIN/RST
- Multiple connections from same IP (different src_port)

## ✅ Honeypot Logic (cmd/agent/main.go)

### Port Binding Strategy
1. **Try to bind all fake ports**: Loop through `fakePorts` array
2. **If bind fails**: Log warning, XDP will redirect to 9999
3. **Fallback port 9999**: MUST be bound for XDP redirect to work
4. **Alternative fallback**: If 9999 busy, try 9998, 9997, etc. (but XDP still redirects to 9999!)

### Connection Handling
- **Direct bind**: `handleConnection(conn, originalPort)` - knows original port
- **Redirected**: `handleConnection(conn, 9999)` - uses random service (The Mirage effect)
- **Service Selection**: Based on port or random if redirected

### Thread Safety
- **statsMutex**: Protects `honeypotConnections`, `activeSessions`, `totalCommands`
- **logChan**: Buffered channel (100) for async logging
- **WaitGroup**: For goroutine synchronization

## ✅ SPA Logic

### Magic Packet Verification
- **Token**: "PHANTOM_GRID_SPA_2025" (21 bytes, no null terminator)
- **Verification**: Byte-by-byte comparison using `bpf_strncmp` or manual loop
- **Bounds Checking**: Verify payload length before access

### Whitelist Management
- **LRU Hash Map**: Auto-evicts when full (max 100 entries)
- **Expiry**: Handled by LRU map auto-eviction (not time-based in eBPF)
- **User Space**: `manageSPAWhitelist()` monitors stats, logs changes

### Flow
1. **UDP packet to port 1337**: Check if payload matches token
2. **Valid**: Add IP to whitelist, DROP packet, update success stats
3. **Invalid**: DROP packet, update failed stats
4. **TCP to Critical Asset**: Check whitelist, DROP if not whitelisted

## ✅ TC Egress Logic (bpf/phantom_egress.c)

### DLP (Data Loss Prevention)
- **Scope**: Only check packets from HONEYPOT_PORT (9999)
- **Pattern Detection**:
  - `/etc/passwd` content
  - SSH private keys ("-----BEGIN")
  - Base64 encoded data (>95% match, >64 bytes)
  - SQL injection ("INSERT INTO")
- **Action**: Update stats, but PASS packet (Demo Mode)
  - To block: Change `TC_ACT_OK` to `TC_ACT_SHOT`

### Payload Extraction
- **TCP Header Length**: `tcp->doff * 4`
- **Payload Start**: `(char *)tcp_start + tcp_hdr_len`
- **Bounds Checking**: Verify payload within packet boundaries

## ✅ Error Handling

### Critical Errors
- **Port 9999 bind failure**: Log error, try alternatives, warn about XDP mismatch
- **XDP attach failure**: Fatal error (program cannot function)
- **TC Egress failure**: Warning only (XDP still works)

### Non-Critical Errors
- **Fake port bind failure**: Warning, XDP will redirect
- **Connection accept error**: Log and continue
- **Banner send error**: Log and close connection
- **Log file write error**: Silent fail (non-critical)

## ✅ Edge Cases

### Handled
1. **IPv6 addresses**: Parsed correctly (with brackets: `[::1]:9999`)
2. **Nil RemoteAddr**: Checked before use
3. **Port 9999 in fakePorts**: Explicitly excluded
4. **Connection tracking cleanup**: On FIN/RST from client
5. **Multiple listeners**: All handled with WaitGroup
6. **Interface detection**: Prioritizes WiFi (`wlx*`, `wlan*`) and VMware (`ens33`)

### Potential Issues
1. **XDP on wrong interface**: Warning logged if attached to loopback
2. **Port 9999 busy**: Alternative ports tried, but XDP still redirects to 9999
3. **LRU map full**: Old entries auto-evicted (SPA whitelist)
4. **Connection tracking map full**: Old entries auto-evicted (max 10k)

## ✅ Performance Considerations

1. **XDP Performance**: Early returns for non-IP, non-TCP traffic
2. **Connection Tracking**: LRU hash map (O(1) lookup)
3. **Statistics**: Atomic operations (`__sync_fetch_and_add`)
4. **Honeypot**: Goroutines for concurrent connections
5. **Dashboard**: Separate goroutine for UI updates (2s ticker)

## ✅ Security Considerations

1. **SPA Token**: Hardcoded (should be configurable in production)
2. **Whitelist Expiry**: LRU-based (not time-based) - acceptable for demo
3. **DLP**: Detection only (not blocking) - change to `TC_ACT_SHOT` to block
4. **OS Fingerprinting**: Randomized to confuse attackers
5. **Stealth Scans**: Dropped silently (no RST response)

## ✅ Testing Checklist

- [x] Constants synchronized between eBPF and Go
- [x] Fake ports list matches between eBPF and Go
- [x] XDP logic flow correct (port 9999 check first)
- [x] Connection tracking handles redirects correctly
- [x] SPA token verification works
- [x] Honeypot binds ports correctly
- [x] Thread safety (mutex usage)
- [x] Error handling for critical paths
- [x] IPv6 address parsing
- [x] Edge cases handled

## ✅ Known Limitations

1. **SPA Expiry**: LRU-based, not time-based (acceptable for demo)
2. **DLP**: Detection only, not blocking (change to `TC_ACT_SHOT` to block)
3. **IPv6**: Not fully supported (only IPv4 in XDP)
4. **Port 9999 Alternative**: If 9999 busy and alternative used, XDP still redirects to 9999 (mismatch)

## ✅ Recommendations for Production

1. **SPA Token**: Load from config file or environment variable
2. **SPA Expiry**: Implement time-based expiry using `bpf_ktime_get_boot_ns()`
3. **DLP**: Enable blocking (`TC_ACT_SHOT`) for production
4. **IPv6 Support**: Add IPv6 handling in XDP
5. **Port Configuration**: Make HONEYPOT_PORT configurable
6. **Logging**: Add structured logging (JSON) for SIEM integration
7. **Metrics**: Export Prometheus metrics for monitoring

