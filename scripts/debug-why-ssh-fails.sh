#!/bin/bash

# Script debug chi tiết tại sao SSH không hoạt động
# Usage: ./scripts/debug-why-ssh-fails.sh [CLIENT_IP]

set -e

CLIENT_IP="${1:-192.168.174.175}"
SERVER_IP=$(ip -4 addr show ens33 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     DEBUG: TẠI SAO SSH KHÔNG HOẠT ĐỘNG?                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Màu sắc
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}Server IP: ${SERVER_IP}${NC}"
echo -e "${CYAN}Client IP: ${CLIENT_IP}${NC}"
echo ""

# 1. Kiểm tra whitelist entry
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. KIỂM TRA WHITELIST ENTRY TRONG eBPF MAP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

python3 << EOF
import struct
import socket
import os

ip_str = "$CLIENT_IP"
ip_bytes = socket.inet_aton(ip_str)
ip_uint32 = struct.unpack('>I', ip_bytes)[0]

print(f"IP: {ip_str}")
print(f"Key trong map (network byte order): {ip_uint32}")
print(f"Key (hex): 0x{ip_uint32:08x}")
print()
print("Kiểm tra map (cần sudo):")
print("  sudo bpftool map show | grep whitelist")
print("  sudo bpftool map dump name spa_whitelist")
EOF

echo ""
echo "Đang kiểm tra map..."
MAP_OUTPUT=$(sudo bpftool map dump name spa_whitelist 2>/dev/null || echo "MAP_NOT_FOUND")

if echo "$MAP_OUTPUT" | grep -q "MAP_NOT_FOUND"; then
    echo -e "${RED}❌ Không tìm thấy map 'spa_whitelist'${NC}"
    echo "Tìm tất cả maps:"
    sudo bpftool map show | grep -i whitelist || echo "Không có whitelist map"
else
    echo -e "${GREEN}✓ Map tồn tại${NC}"
    echo ""
    echo "Entries trong map:"
    echo "$MAP_OUTPUT" | python3 << 'PYEOF'
import json
import sys
import struct
import socket

try:
    data = json.load(sys.stdin)
    if not data:
        print("  (empty)")
    else:
        for entry in data:
            key = entry['key']
            value = entry['value']
            
            # Convert key từ uint32 sang IP
            ip_bytes = [(key >> 24) & 0xFF, (key >> 16) & 0xFF, (key >> 8) & 0xFF, key & 0xFF]
            ip_str = ".".join(map(str, ip_bytes))
            
            # Check expiry
            uptime = float(open('/proc/uptime').read().split()[0])
            current_ns = int(uptime * 1e9)
            expiry_ns = value
            
            print(f"  IP: {ip_str}")
            print(f"    Key: {key}")
            print(f"    Expiry: {expiry_ns} ns")
            print(f"    Current: {current_ns} ns")
            diff = expiry_ns - current_ns
            print(f"    Diff: {diff} ns ({int(diff / 1e9)} seconds)")
            
            if expiry_ns > current_ns:
                print(f"    Status: ✓ Valid (còn {int(diff / 1e9)} seconds)")
            else:
                print(f"    Status: ✗ Expired!")
            print()
except Exception as e:
    print(f"Error: {e}")
    print(sys.stdin.read())
PYEOF
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. KIỂM TRA eBPF PROGRAM"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

XDP_STATUS=$(ip link show ens33 2>/dev/null | grep -o "xdp.*" || echo "No XDP")
echo "XDP Status: $XDP_STATUS"

if echo "$XDP_STATUS" | grep -q "xdp"; then
    echo -e "${GREEN}✓ XDP program đang chạy${NC}"
else
    echo -e "${RED}❌ XDP program KHÔNG chạy!${NC}"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. KIỂM TRA SSH SERVICE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
    echo -e "${GREEN}✓ SSH service đang chạy${NC}"
else
    echo -e "${YELLOW}⚠ SSH service có thể không chạy${NC}"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. TEST CONNECTIVITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "Test port 22 từ localhost:"
timeout 2 bash -c "echo > /dev/tcp/localhost/22" 2>/dev/null && \
    echo -e "${GREEN}✓ Port 22 is reachable locally${NC}" || \
    echo -e "${RED}✗ Port 22 is NOT reachable locally${NC}"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. HƯỚNG DẪN DEBUG TIẾP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "A. Monitor packets trong real-time:"
echo "   ./scripts/monitor-correct.sh $CLIENT_IP"
echo ""
echo "B. Test SSH với verbose:"
echo "   ssh -vvv user@$SERVER_IP"
echo ""
echo "C. Kiểm tra logs trong dashboard:"
echo "   - Xem có log 'Successfully authenticated' không"
echo "   - Xem có error 'Failed to whitelist' không"
echo ""
echo "D. Kiểm tra whitelist ngay sau khi authenticate:"
echo "   # Gửi SPA packet"
echo "   ./bin/spa-client -server $SERVER_IP -mode asymmetric"
echo "   # Ngay sau đó, kiểm tra map:"
echo "   sudo bpftool map dump name spa_whitelist"
echo ""

