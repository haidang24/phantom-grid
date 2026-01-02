#!/bin/bash

# Script để monitor tất cả packets liên quan đến SPA và SSH
# Usage: ./scripts/monitor-all-packets.sh [IP]

set -e

IP="${1:-192.168.174.175}"
INTERFACE="${2:-ens33}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     MONITOR TẤT CẢ PACKETS - SPA VÀ SSH                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Màu sắc
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}Monitoring IP: ${IP}${NC}"
echo -e "${CYAN}Interface: ${INTERFACE}${NC}"
echo ""
echo -e "${YELLOW}⚠ Cần sudo để chạy tcpdump${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Kiểm tra tcpdump
if ! command -v tcpdump > /dev/null 2>&1; then
    echo -e "${RED}❌ tcpdump không có sẵn. Cài đặt: sudo apt install tcpdump${NC}"
    exit 1
fi

# Filter cho tất cả packets liên quan
FILTER="host $IP and (udp port 1337 or tcp port 22)"

echo -e "${GREEN}Starting packet capture...${NC}"
echo -e "${CYAN}Filter: ${FILTER}${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
echo ""

# Capture với output chi tiết
sudo tcpdump -i $INTERFACE -n -v -S -X "$FILTER" 2>&1 | while IFS= read -r line; do
    # Highlight SPA packets
    if echo "$line" | grep -q "1337"; then
        echo -e "${CYAN}[SPA]${NC} $line"
    # Highlight SSH SYN packets
    elif echo "$line" | grep -q "Flags \[S\]"; then
        echo -e "${YELLOW}[SSH-SYN]${NC} $line"
    # Highlight SSH SYN-ACK packets
    elif echo "$line" | grep -q "Flags \[S\.\]"; then
        echo -e "${GREEN}[SSH-SYN-ACK]${NC} $line"
    # Highlight SSH RST packets
    elif echo "$line" | grep -q "Flags \[R\]"; then
        echo -e "${RED}[SSH-RST]${NC} $line"
    # Highlight other SSH packets
    elif echo "$line" | grep -q "22"; then
        echo -e "${YELLOW}[SSH]${NC} $line"
    else
        echo "$line"
    fi
done

