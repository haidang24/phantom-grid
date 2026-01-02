#!/bin/bash
# Quick Start Script for Phantom Grid

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     PHANTOM GRID - QUICK START                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Detect network interface
INTERFACE=$(ip -o link show | grep -v lo | grep -v docker | grep -v br- | head -1 | awk -F': ' '{print $2}' | awk '{print $1}')

if [ -z "$INTERFACE" ]; then
    INTERFACE="eth0"
fi

echo "📡 Network Interface: $INTERFACE"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Cần quyền sudo để chạy agent"
    echo ""
    echo "Chạy lệnh sau:"
    echo "  sudo ./bin/phantom-grid -interface $INTERFACE"
    echo ""
    echo "Hoặc chạy menu quản lý (không cần sudo):"
    echo "  ./bin/phantom"
    echo ""
    exit 0
fi

echo "✅ Đang khởi động Phantom Grid Agent..."
echo "   Interface: $INTERFACE"
echo "   Mode: Static SPA (mặc định)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run the agent
exec ./bin/phantom-grid -interface "$INTERFACE"

