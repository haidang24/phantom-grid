#!/bin/bash
# Script để chạy Phantom Grid Agent với các tham số

set -e

INTERFACE="${INTERFACE:-ens33}"
SPA_MODE="${SPA_MODE:-static}"
OUTPUT_MODE="${OUTPUT_MODE:-dashboard}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     PHANTOM GRID - CHẠY BẰNG COMMAND                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Kiểm tra quyền sudo
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Cần quyền sudo để chạy agent"
    echo ""
    echo "Sử dụng: sudo $0"
    echo "Hoặc: sudo ./bin/phantom-grid -interface $INTERFACE"
    exit 1
fi

echo "📡 Interface: $INTERFACE"
echo "🔐 SPA Mode: $SPA_MODE"
echo "📊 Output Mode: $OUTPUT_MODE"
echo ""

# Chạy với các tham số
exec ./bin/phantom-grid \
    -interface "$INTERFACE" \
    -spa-mode "$SPA_MODE" \
    -output "$OUTPUT_MODE"

