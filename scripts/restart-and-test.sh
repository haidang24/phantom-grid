#!/bin/bash

# Script để restart server và test SPA authentication
# Usage: ./scripts/restart-and-test.sh

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     RESTART SERVER VÀ TEST SPA AUTHENTICATION               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Màu sắc
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Kiểm tra binary
if [ ! -f "./bin/phantom-grid" ]; then
    echo -e "${RED}❌ Binary không tìm thấy. Chạy 'make build' trước.${NC}"
    exit 1
fi

# Lấy interface
INTERFACE=$(ip -o link show | grep -v lo | grep -v docker | head -1 | awk -F': ' '{print $2}' | awk '{print $1}')
if [ -z "$INTERFACE" ]; then
    INTERFACE="ens33"
fi

echo -e "${GREEN}✓ Interface: $INTERFACE${NC}"

# Dừng server cũ
echo ""
echo "🛑 Dừng server cũ..."
sudo pkill phantom-grid || echo "Không có server cũ đang chạy"
sleep 2

# Kiểm tra keys
if [ ! -f "./keys/spa_public.key" ] || [ ! -f "./keys/totp_secret.txt" ]; then
    echo -e "${YELLOW}⚠ Keys chưa có. Tạo keys? (y/n)${NC}"
    read -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        ./bin/spa-keygen -dir ./keys
        openssl rand -base64 32 | tr -d '\n' > ./keys/totp_secret.txt
        echo -e "${GREEN}✓ Keys đã tạo${NC}"
    fi
fi

# Start server
echo ""
echo "🚀 Starting server..."
echo ""
echo "Command:"
echo "  sudo ./bin/phantom-grid \\"
echo "    -interface $INTERFACE \\"
echo "    -spa-mode asymmetric \\"
echo "    -spa-key-dir ./keys \\"
echo "    -output dashboard"
echo ""
echo -e "${YELLOW}⚠ Server sẽ chạy trong foreground.${NC}"
echo -e "${YELLOW}⚠ Mở terminal khác để test client.${NC}"
echo ""
echo "Press Enter để start server..."
read

# Start server in background
sudo ./bin/phantom-grid \
    -interface $INTERFACE \
    -spa-mode asymmetric \
    -spa-key-dir ./keys \
    -output dashboard &

SERVER_PID=$!
echo ""
echo -e "${GREEN}✓ Server started (PID: $SERVER_PID)${NC}"
echo ""

# Wait a bit for server to start
sleep 3

# Test client
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 TESTING SPA CLIENT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Get server IP
SERVER_IP=$(ip -4 addr show $INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
if [ -z "$SERVER_IP" ]; then
    echo -e "${YELLOW}⚠ Không tìm thấy server IP. Nhập IP thủ công:${NC}"
    read SERVER_IP
fi

echo "Server IP: $SERVER_IP"
echo ""

# Send SPA packet
if [ -f "./bin/spa-client" ]; then
    echo "Gửi SPA packet..."
    ./bin/spa-client \
        -server $SERVER_IP \
        -mode asymmetric
    
    echo ""
    echo -e "${GREEN}✓ SPA packet đã gửi${NC}"
    echo ""
    echo "Bây giờ bạn có thể test SSH:"
    echo "  ssh user@$SERVER_IP"
    echo ""
    echo "Hoặc test với telnet:"
    echo "  telnet $SERVER_IP 22"
else
    echo -e "${RED}❌ spa-client binary không tìm thấy${NC}"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Để xem logs, check dashboard hoặc:"
echo "   sudo journalctl -u phantom-grid -f"
echo ""
echo "🛑 Để dừng server:"
echo "   sudo pkill phantom-grid"
echo ""

