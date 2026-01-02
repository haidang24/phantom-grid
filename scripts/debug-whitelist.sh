#!/bin/bash

# Script để debug whitelist issues
# Usage: ./scripts/debug-whitelist.sh [IP]

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     DEBUG WHITELIST ISSUES                                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

IP="${1:-192.168.174.175}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. KIỂM TRA eBPF MAPS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if ! command -v bpftool > /dev/null 2>&1; then
    echo "⚠ bpftool không có sẵn. Cài đặt: sudo apt install linux-tools-generic"
    echo ""
else
    echo "Tìm eBPF maps:"
    bpftool map show | grep -E "(spa_whitelist|spa_auth)" || echo "Không tìm thấy maps"
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. KIỂM TRA THỜI GIAN HỆ THỐNG"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Current time: $(date)"
echo "Unix timestamp: $(date +%s)"
echo "Uptime: $(cat /proc/uptime | awk '{print $1}') seconds"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. KIỂM TRA NETWORK CONNECTIVITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Testing connection to $IP:22"
timeout 2 bash -c "echo > /dev/tcp/$IP/22" 2>/dev/null && echo "✓ Port 22 is reachable" || echo "✗ Port 22 is NOT reachable"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. KIỂM TRA XDP PROGRAM"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if command -v ip > /dev/null 2>&1; then
    INTERFACE=$(ip -o link show | grep -v lo | head -1 | awk -F': ' '{print $2}')
    echo "Interface: $INTERFACE"
    XDP_STATUS=$(ip link show $INTERFACE 2>/dev/null | grep -o "xdp.*" || echo "No XDP")
    echo "XDP Status: $XDP_STATUS"
else
    echo "ip command không có sẵn"
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. HƯỚNG DẪN DEBUG"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Để debug whitelist:"
echo ""
echo "1. Kiểm tra agent đang chạy:"
echo "   ps aux | grep phantom-grid"
echo ""
echo "2. Kiểm tra logs:"
echo "   sudo journalctl -u phantom-grid -f"
echo "   hoặc xem dashboard logs"
echo ""
echo "3. Test SPA authentication:"
echo "   ./bin/spa-client -server $IP -mode asymmetric"
echo ""
echo "4. Test SSH ngay sau khi authenticate:"
echo "   ssh user@$IP"
echo ""
echo "5. Kiểm tra whitelist trong eBPF map (nếu có bpftool):"
echo "   sudo bpftool map dump name spa_whitelist"
echo ""

