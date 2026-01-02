#!/bin/bash

# Script để test whitelist ngay sau khi authenticate
# Usage: ./scripts/test-whitelist-immediately.sh [CLIENT_IP] [SERVER_IP]

set -e

CLIENT_IP="${1:-192.168.174.175}"
SERVER_IP="${2:-192.168.174.163}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     TEST WHITELIST NGAY SAU KHI AUTHENTICATE                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Màu sắc
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}Client IP: ${CLIENT_IP}${NC}"
echo -e "${CYAN}Server IP: ${SERVER_IP}${NC}"
echo ""

# Convert IP to uint32
IP_UINT32=$(python3 << EOF
import struct
import socket
ip_bytes = socket.inet_aton("$CLIENT_IP")
ip_uint32 = struct.unpack('>I', ip_bytes)[0]
print(ip_uint32)
EOF
)

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "BƯỚC 1: GỬI SPA PACKET"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Gửi SPA packet từ client..."
echo "  ./bin/spa-client -server $SERVER_IP -mode asymmetric"
echo ""
echo -e "${YELLOW}⚠ Chạy lệnh trên trong terminal khác, sau đó nhấn Enter để tiếp tục...${NC}"
read

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "BƯỚC 2: KIỂM TRA WHITELIST MAP (NGAY SAU KHI AUTHENTICATE)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check map
MAP_OUTPUT=$(sudo bpftool map dump name spa_whitelist 2>/dev/null || echo "MAP_NOT_FOUND")

if echo "$MAP_OUTPUT" | grep -q "MAP_NOT_FOUND"; then
    echo -e "${RED}❌ Không tìm thấy map 'spa_whitelist'${NC}"
    exit 1
fi

# Parse và tìm entry
FOUND_ENTRY=$(echo "$MAP_OUTPUT" | python3 << PYEOF
import json
import sys
import struct

try:
    data = json.load(sys.stdin)
    target_key = $IP_UINT32
    
    for entry in data:
        key = entry['key']
        value = entry['value']
        
        if key == target_key:
            # Check expiry
            import os
            uptime = float(open('/proc/uptime').read().split()[0])
            current_ns = int(uptime * 1e9)
            expiry_ns = value
            
            diff = expiry_ns - current_ns
            
            print(f"FOUND:{key}:{value}:{current_ns}:{diff}")
            break
    else:
        print("NOT_FOUND")
except Exception as e:
    print(f"ERROR:{e}")
PYEOF
)

if echo "$FOUND_ENTRY" | grep -q "FOUND"; then
    KEY=$(echo "$FOUND_ENTRY" | cut -d: -f2)
    EXPIRY=$(echo "$FOUND_ENTRY" | cut -d: -f3)
    CURRENT=$(echo "$FOUND_ENTRY" | cut -d: -f4)
    DIFF=$(echo "$FOUND_ENTRY" | cut -d: -f5)
    
    echo -e "${GREEN}✓ Whitelist entry TỒN TẠI!${NC}"
    echo "  Key: $KEY"
    echo "  Expiry: $EXPIRY ns"
    echo "  Current: $CURRENT ns"
    echo "  Diff: $DIFF ns ($(echo "scale=1; $DIFF / 1000000000" | bc) seconds)"
    
    if [ "$DIFF" -gt 0 ]; then
        echo -e "${GREEN}  Status: ✓ Valid (chưa hết hạn)${NC}"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "BƯỚC 3: TEST SSH"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo -e "${YELLOW}Test SSH từ client:${NC}"
        echo "  ssh -v user@$SERVER_IP"
        echo ""
        echo "Nếu SSH vẫn không hoạt động, có thể là:"
        echo "  1. Race condition - SSH packet đến trước khi map sync"
        echo "  2. eBPF program không check whitelist đúng"
        echo "  3. Có firewall rule khác block"
    else
        echo -e "${RED}  Status: ✗ Expired!${NC}"
        echo ""
        echo -e "${RED}❌ Whitelist entry đã hết hạn ngay sau khi tạo!${NC}"
        echo "Có vấn đề với cách tính expiry timestamp!"
    fi
else
    echo -e "${RED}❌ Whitelist entry KHÔNG TỒN TẠI!${NC}"
    echo ""
    echo "Có thể:"
    echo "  1. WhitelistIP() failed nhưng không log error"
    echo "  2. Map update có delay"
    echo "  3. Map name không đúng"
    echo ""
    echo "Tất cả entries trong map:"
    echo "$MAP_OUTPUT" | python3 << 'PYEOF'
import json
import sys
import struct

try:
    data = json.load(sys.stdin)
    for entry in data:
        key = entry['key']
        value = entry['value']
        ip_bytes = [(key >> 24) & 0xFF, (key >> 16) & 0xFF, (key >> 8) & 0xFF, key & 0xFF]
        ip_str = ".".join(map(str, ip_bytes))
        print(f"  IP: {ip_str}, Key: {key}, Expiry: {value}")
except:
    print(sys.stdin.read())
PYEOF
fi

echo ""

