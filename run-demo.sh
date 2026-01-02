#!/bin/bash
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     PHANTOM GRID - CHẠY QUA DÒNG LỆNH                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Kiểm tra binary
if [ ! -f "./bin/phantom-grid" ]; then
    echo "❌ Binary không tìm thấy. Đang build..."
    make build
fi

echo "✅ Binary sẵn sàng"
echo ""

# Lấy interface mạng
INTERFACE=$(ip -o link show | grep -v lo | grep -v docker | grep -v br- | head -1 | awk -F': ' '{print $2}' | awk '{print $1}')
if [ -z "$INTERFACE" ]; then
    INTERFACE="eth0"
fi

echo "📡 Interface mạng: $INTERFACE"
echo ""

# Hiển thị các lệnh có thể chạy
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "CÁC LỆNH CÓ THỂ CHẠY:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Chạy agent với interface $INTERFACE:"
echo "   sudo ./bin/phantom-grid -interface $INTERFACE"
echo ""
echo "2. Chạy với SPA asymmetric mode:"
echo "   sudo ./bin/phantom-grid -interface $INTERFACE -spa-mode asymmetric"
echo ""
echo "3. Chạy menu quản lý:"
echo "   ./bin/phantom"
echo ""
echo "4. Test SPA client (cần server IP):"
echo "   ./bin/spa-client -server <SERVER_IP>"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Chạy test SPA
echo "🧪 Đang chạy SPA tests..."
go test -v -run "TestSPA" ./internal/spa/... ./pkg/spa/... 2>&1 | grep -E "(PASS|FAIL|ok)" | tail -5
echo ""

echo "✅ Sẵn sàng chạy!"
echo ""
echo "💡 Để chạy agent, sử dụng lệnh:"
echo "   sudo ./bin/phantom-grid -interface $INTERFACE"
echo ""

