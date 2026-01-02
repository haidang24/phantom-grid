#!/bin/bash

# Script để monitor SPA packets và SSH connections
# Usage: ./scripts/monitor-spa-packets.sh [IP]

set -e

IP="${1:-192.168.174.175}"
INTERFACE="${2:-ens33}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     MONITOR SPA PACKETS VÀ SSH CONNECTIONS                  ║"
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
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Kiểm tra tcpdump
if ! command -v tcpdump > /dev/null 2>&1; then
    echo -e "${RED}❌ tcpdump không có sẵn. Cài đặt: sudo apt install tcpdump${NC}"
    exit 1
fi

# Tạo temp file cho output
TEMP_FILE=$(mktemp)
trap "rm -f $TEMP_FILE" EXIT

echo -e "${GREEN}✓ Starting packet capture...${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
echo ""

# Capture SPA packets (UDP port 1337)
echo -e "${CYAN}[SPA Packets - UDP 1337]${NC}"
sudo tcpdump -i $INTERFACE -n -v \
    "udp port 1337 and host $IP" \
    -c 10 \
    2>&1 | tee -a $TEMP_FILE &
SPA_PID=$!

# Capture SSH packets (TCP port 22)
echo -e "${CYAN}[SSH Packets - TCP 22]${NC}"
sudo tcpdump -i $INTERFACE -n -v \
    "tcp port 22 and host $IP" \
    -c 20 \
    2>&1 | tee -a $TEMP_FILE &
SSH_PID=$!

# Wait for captures
sleep 2

# Analyze captured packets
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${CYAN}PHÂN TÍCH PACKETS:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check SPA packets
SPA_COUNT=$(grep -c "1337" $TEMP_FILE 2>/dev/null || echo "0")
if [ "$SPA_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ SPA packets detected: $SPA_COUNT${NC}"
    grep "1337" $TEMP_FILE | head -3
else
    echo -e "${YELLOW}⚠ No SPA packets detected${NC}"
fi

echo ""

# Check SSH packets
SSH_COUNT=$(grep -c "22.*$IP" $TEMP_FILE 2>/dev/null || echo "0")
if [ "$SSH_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ SSH packets detected: $SSH_COUNT${NC}"
    
    # Check for SYN packets
    SYN_COUNT=$(grep -c "Flags \[S\]" $TEMP_FILE 2>/dev/null || echo "0")
    if [ "$SYN_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}  → SYN packets: $SYN_COUNT${NC}"
    fi
    
    # Check for SYN-ACK packets
    SYNACK_COUNT=$(grep -c "Flags \[S\.\]" $TEMP_FILE 2>/dev/null || echo "0")
    if [ "$SYNACK_COUNT" -gt 0 ]; then
        echo -e "${GREEN}  → SYN-ACK packets: $SYNACK_COUNT (server responding)${NC}"
    else
        echo -e "${RED}  → No SYN-ACK packets (server NOT responding)${NC}"
        echo -e "${RED}  → Có thể bị DROP bởi eBPF!${NC}"
    fi
    
    # Check for RST packets
    RST_COUNT=$(grep -c "Flags \[R\]" $TEMP_FILE 2>/dev/null || echo "0")
    if [ "$RST_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}  → RST packets: $RST_COUNT (connection reset)${NC}"
    fi
    
    echo ""
    echo "Chi tiết SSH packets:"
    grep "22.*$IP" $TEMP_FILE | head -5
else
    echo -e "${YELLOW}⚠ No SSH packets detected${NC}"
fi

# Cleanup
kill $SPA_PID $SSH_PID 2>/dev/null || true
wait 2>/dev/null || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

