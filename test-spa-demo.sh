#!/bin/bash
# Demo script để test SPA functionality

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          PHANTOM GRID - SPA DEMO TEST                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Kiểm tra binary
if [ ! -f "./bin/spa-client" ]; then
    echo "❌ Binary không tìm thấy. Chạy 'make build' trước."
    exit 1
fi

echo "✅ Binary đã sẵn sàng"
echo ""

# Test 1: Kiểm tra help
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 1: Kiểm tra SPA Client Help"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
./bin/spa-client --help 2>&1 | head -15
echo ""

# Test 2: Chạy Go tests
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 2: Chạy SPA Integration Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
go test -v -run "TestSPA" ./internal/spa/... ./pkg/spa/... 2>&1 | grep -E "(PASS|FAIL|RUN)" | tail -10
echo ""

echo "✅ Demo test hoàn thành!"
echo ""
echo "📝 Để chạy agent thực tế:"
echo "   sudo ./bin/phantom-grid -interface <INTERFACE>"
echo ""
echo "📝 Để sử dụng menu quản lý:"
echo "   ./bin/phantom"
echo ""

