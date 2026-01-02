#!/bin/bash

# Script để monitor đúng - tự động detect IP
# Usage: ./scripts/monitor-correct.sh [CLIENT_IP]

set -e

CLIENT_IP="${1:-192.168.174.175}"
INTERFACE="${2:-ens33}"

# Get server IP
SERVER_IP=$(ip -4 addr show $INTERFACE 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

if [ -z "$SERVER_IP" ]; then
    echo "❌ Không tìm thấy IP của server trên interface $INTERFACE"
    echo "Vui lòng chỉ định IP thủ công:"
    echo "  ./scripts/monitor-correct.sh $CLIENT_IP ens33 <SERVER_IP>"
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     MONITOR PACKETS - ĐÚNG CÁCH                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Server IP: $SERVER_IP"
echo "Client IP: $CLIENT_IP"
echo "Interface: $INTERFACE"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "MONITORING:"
echo "  - SPA packets: UDP port 1337 từ $CLIENT_IP → $SERVER_IP"
echo "  - SSH packets: TCP port 22 từ $CLIENT_IP → $SERVER_IP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Filter: packets từ client đến server (SPA và SSH)
FILTER="(udp port 1337 or tcp port 22) and host $CLIENT_IP and host $SERVER_IP"

sudo tcpdump -i $INTERFACE -n -v "$FILTER" 2>&1 | while IFS= read -r line; do
    # Highlight SPA packets
    if echo "$line" | grep -q "1337"; then
        echo -e "\033[0;36m[SPA]\033[0m $line"
    # Highlight SSH SYN packets
    elif echo "$line" | grep -q "Flags \[S\]"; then
        echo -e "\033[1;33m[SSH-SYN]\033[0m $line"
    # Highlight SSH SYN-ACK packets
    elif echo "$line" | grep -q "Flags \[S\.\]"; then
        echo -e "\033[0;32m[SSH-SYN-ACK]\033[0m $line"
    # Highlight SSH RST packets
    elif echo "$line" | grep -q "Flags \[R\]"; then
        echo -e "\033[0;31m[SSH-RST]\033[0m $line"
    # Highlight other SSH packets
    elif echo "$line" | grep -q "22"; then
        echo -e "\033[0;33m[SSH]\033[0m $line"
    else
        echo "$line"
    fi
done

