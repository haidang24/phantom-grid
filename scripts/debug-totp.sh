#!/bin/bash

# Script để debug TOTP issues
# Usage: ./scripts/debug-totp.sh

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     DEBUG TOTP ISSUES                                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Màu sắc
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

TOTP_FILE="./keys/totp_secret.txt"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. KIỂM TRA TOTP SECRET FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ ! -f "$TOTP_FILE" ]; then
    echo -e "${RED}❌ File không tồn tại: $TOTP_FILE${NC}"
    echo ""
    echo "Tạo file mới:"
    echo "  openssl rand -base64 32 > $TOTP_FILE"
    exit 1
fi

echo -e "${GREEN}✓ File tồn tại: $TOTP_FILE${NC}"

# Kiểm tra nội dung
echo ""
echo "Nội dung file (hex):"
hexdump -C "$TOTP_FILE" | head -5

echo ""
echo "Số dòng trong file:"
wc -l "$TOTP_FILE"

echo ""
echo "Kích thước file (bytes):"
wc -c "$TOTP_FILE"

# Kiểm tra newline
echo ""
echo "Kiểm tra newline/whitespace:"
if grep -q $'\r' "$TOTP_FILE"; then
    echo -e "${YELLOW}⚠ Phát hiện CR (\\r) trong file${NC}"
fi

if [ "$(tail -c 1 "$TOTP_FILE" | wc -l)" -gt 0 ]; then
    echo -e "${YELLOW}⚠ File kết thúc bằng newline${NC}"
fi

# Đọc và clean TOTP secret
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. TOTP SECRET (RAW)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat "$TOTP_FILE" | head -1 | cat -A

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. TOTP SECRET (CLEANED - không có newline)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
TOTP_CLEAN=$(cat "$TOTP_FILE" | tr -d '\n\r' | head -c 1000)
echo "$TOTP_CLEAN"
echo ""
echo "Length: ${#TOTP_CLEAN} characters"

# Kiểm tra base64
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. KIỂM TRA BASE64 DECODE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if echo "$TOTP_CLEAN" | base64 -d > /dev/null 2>&1; then
    echo -e "${GREEN}✓ TOTP secret là base64 hợp lệ${NC}"
    DECODED_SIZE=$(echo "$TOTP_CLEAN" | base64 -d | wc -c)
    echo "Decoded size: $DECODED_SIZE bytes"
else
    echo -e "${RED}❌ TOTP secret không phải base64 hợp lệ${NC}"
    echo "Lưu ý: TOTP secret phải là base64 encoded, 32 bytes (44 ký tự base64)"
fi

# Kiểm tra thời gian
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. KIỂM TRA THỜI GIAN HỆ THỐNG"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Thời gian hiện tại:"
date
echo ""
echo "Unix timestamp:"
date +%s
echo ""
echo "NTP sync status:"
if command -v timedatectl > /dev/null 2>&1; then
    timedatectl status | grep -E "(NTP|synchronized)"
else
    echo "timedatectl không có sẵn"
fi

# Tạo file TOTP đã clean
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. TẠO FILE TOTP ĐÃ CLEAN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
CLEAN_FILE="./keys/totp_secret_clean.txt"
echo "$TOTP_CLEAN" > "$CLEAN_FILE"
echo -e "${GREEN}✓ Đã tạo file clean: $CLEAN_FILE${NC}"
echo ""
echo "So sánh:"
echo "  Original: $(wc -c < "$TOTP_FILE") bytes"
echo "  Clean:    $(wc -c < "$CLEAN_FILE") bytes"

# Hướng dẫn sửa
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7. HƯỚNG DẪN SỬA LỖI"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Nếu TOTP secret có vấn đề, sửa bằng cách:"
echo ""
echo "1. Backup file cũ:"
echo "   cp $TOTP_FILE ${TOTP_FILE}.backup"
echo ""
echo "2. Tạo file mới (clean):"
echo "   cat $TOTP_FILE | tr -d '\\n\\r' > ${TOTP_FILE}.tmp"
echo "   mv ${TOTP_FILE}.tmp $TOTP_FILE"
echo ""
echo "3. Hoặc tạo lại TOTP secret:"
echo "   openssl rand -base64 32 | tr -d '\\n' > $TOTP_FILE"
echo ""
echo "4. Đảm bảo file chỉ có 1 dòng, không có newline:"
echo "   echo -n \"\$(cat $TOTP_FILE | tr -d '\\n\\r')\" > $TOTP_FILE"
echo ""
echo "5. Copy file này sang client (phải GIỐNG NHAU):"
echo "   scp $TOTP_FILE user@client:/path/to/keys/totp_secret.txt"
echo ""
echo "6. Đồng bộ thời gian (nếu clock skew):"
echo "   sudo ntpdate -s time.nist.gov"
echo "   # hoặc"
echo "   sudo systemctl start ntp"
echo ""

