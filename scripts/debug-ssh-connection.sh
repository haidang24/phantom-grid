#!/bin/bash

# Script để debug SSH connection chi tiết
# Usage: ./scripts/debug-ssh-connection.sh [IP]

set -e

IP="${1:-192.168.174.163}"
CLIENT_IP="${2:-192.168.174.175}"
INTERFACE="${3:-ens33}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     DEBUG SSH CONNECTION                                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Màu sắc
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}Server IP: ${IP}${NC}"
echo -e "${CYAN}Client IP: ${CLIENT_IP}${NC}"
echo -e "${CYAN}Interface: ${INTERFACE}${NC}"
echo ""

# 1. Kiểm tra whitelist trong eBPF map
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. KIỂM TRA WHITELIST ENTRY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

python3 << EOF
import struct
import socket

ip_str = "$CLIENT_IP"
ip_bytes = socket.inet_aton(ip_str)
ip_uint32 = struct.unpack('>I', ip_bytes)[0]

print(f"IP: {ip_str}")
print(f"Key trong map (network byte order): {ip_uint32}")
print(f"Key trong map (hex): 0x{ip_uint32:08x}")
EOF

echo ""
echo "Kiểm tra map (cần sudo):"
echo "  sudo bpftool map show | grep whitelist"
echo "  sudo bpftool map dump name spa_whitelist"
echo ""

# 2. Test connectivity
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. TEST CONNECTIVITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "Test port 22:"
timeout 2 bash -c "echo > /dev/tcp/$IP/22" 2>/dev/null && \
    echo -e "${GREEN}✓ Port 22 is reachable${NC}" || \
    echo -e "${RED}✗ Port 22 is NOT reachable${NC}"

echo ""
echo "Test với telnet:"
echo "  telnet $IP 22"
echo ""

# 3. Monitor packets trong real-time
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. MONITOR PACKETS (Real-time)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${YELLOW}Chạy lệnh sau trong terminal khác để monitor:${NC}"
echo ""
echo "  sudo tcpdump -i $INTERFACE -n -v 'tcp port 22 and host $CLIENT_IP'"
echo ""
echo "Hoặc chi tiết hơn:"
echo "  sudo tcpdump -i $INTERFACE -n -X 'tcp port 22 and host $CLIENT_IP'"
echo ""

# 4. Test SSH với verbose
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. TEST SSH VỚI VERBOSE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${YELLOW}Chạy lệnh sau để test SSH với verbose output:${NC}"
echo ""
echo "  ssh -v user@$IP"
echo ""
echo "Hoặc với nhiều verbose hơn:"
echo "  ssh -vvv user@$IP"
echo ""

# 5. Kiểm tra eBPF program
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. KIỂM TRA eBPF PROGRAM"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Kiểm tra XDP program:"
echo "  ip link show $INTERFACE | grep xdp"
echo ""
echo "Kiểm tra eBPF maps:"
echo "  sudo bpftool map show"
echo ""

# 6. Hướng dẫn debug chi tiết
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. HƯỚNG DẪN DEBUG CHI TIẾT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Bước 1: Gửi SPA packet"
echo "  ./bin/spa-client -server $IP -mode asymmetric"
echo ""
echo "Bước 2: Kiểm tra whitelist ngay sau đó"
echo "  sudo bpftool map dump name spa_whitelist"
echo ""
echo "Bước 3: Test SSH ngay"
echo "  ssh -v user@$IP"
echo ""
echo "Bước 4: Xem logs trong dashboard"
echo "  - Kiểm tra xem có log 'Successfully authenticated' không"
echo "  - Kiểm tra xem có error 'Failed to whitelist' không"
echo ""
echo "Bước 5: Nếu vẫn không hoạt động, kiểm tra:"
echo "  - Map có entry không?"
echo "  - Expiry timestamp có hợp lệ không?"
echo "  - eBPF program có check whitelist đúng không?"
echo ""

