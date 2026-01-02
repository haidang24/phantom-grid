#!/bin/bash

# Script đơn giản để monitor packets
# Usage: ./scripts/quick-monitor.sh

IP="${1:-192.168.174.175}"
INTERFACE="${2:-ens33}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     QUICK MONITOR - SPA VÀ SSH PACKETS                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Monitoring: $IP on $INTERFACE"
echo "Press Ctrl+C to stop"
echo ""

sudo tcpdump -i $INTERFACE -n \
    "host $IP and (udp port 1337 or tcp port 22)" \
    -c 50 \
    -v

