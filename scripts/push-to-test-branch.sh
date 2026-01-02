#!/bin/bash

# Script để push code lên branch test trên GitHub
# Usage: ./scripts/push-to-test-branch.sh

set -e  # Exit on error

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     PUSH CODE LÊN GITHUB BRANCH TEST                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Màu sắc
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Kiểm tra xem có phải git repository không
if [ ! -d .git ]; then
    echo -e "${RED}❌ Error: Không phải git repository!${NC}"
    exit 1
fi

# Kiểm tra remote
if ! git remote get-url origin > /dev/null 2>&1; then
    echo -e "${RED}❌ Error: Không tìm thấy remote 'origin'!${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Git repository detected${NC}"
echo -e "${GREEN}✓ Remote: $(git remote get-url origin)${NC}"
echo ""

# Hiển thị trạng thái hiện tại
echo "📊 Trạng thái hiện tại:"
git status --short
echo ""

# Hỏi có muốn commit các thay đổi không
read -p "Bạn có muốn commit các thay đổi hiện tại? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    read -p "Nhập commit message (hoặc Enter để dùng default): " commit_msg
    if [ -z "$commit_msg" ]; then
        commit_msg="feat: Update SPA authentication and web interface"
    fi
    
    echo ""
    echo -e "${YELLOW}📝 Staging files...${NC}"
    git add .
    
    echo -e "${YELLOW}💾 Committing...${NC}"
    git commit -m "$commit_msg"
    echo -e "${GREEN}✓ Committed: $commit_msg${NC}"
    echo ""
fi

# Kiểm tra branch hiện tại
current_branch=$(git branch --show-current)
echo -e "${GREEN}📍 Current branch: $current_branch${NC}"

# Hỏi có muốn tạo branch test mới không
if [ "$current_branch" != "test" ]; then
    read -p "Bạn có muốn tạo/chuyển sang branch 'test'? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Kiểm tra xem branch test đã tồn tại chưa
        if git show-ref --verify --quiet refs/heads/test; then
            echo -e "${YELLOW}🔄 Branch 'test' đã tồn tại, đang chuyển sang...${NC}"
            git checkout test
            # Merge từ branch hiện tại nếu cần
            if [ "$current_branch" != "test" ]; then
                echo -e "${YELLOW}🔄 Merging changes from $current_branch...${NC}"
                git merge "$current_branch" || echo -e "${YELLOW}⚠ Merge conflict hoặc không cần merge${NC}"
            fi
        else
            echo -e "${YELLOW}🆕 Tạo branch 'test' mới từ $current_branch...${NC}"
            git checkout -b test
        fi
        echo -e "${GREEN}✓ Đã chuyển sang branch 'test'${NC}"
        echo ""
    fi
fi

# Kiểm tra lại branch hiện tại
current_branch=$(git branch --show-current)
if [ "$current_branch" != "test" ]; then
    echo -e "${YELLOW}⚠ Bạn đang ở branch '$current_branch', không phải 'test'${NC}"
    read -p "Bạn có muốn tiếp tục push branch '$current_branch'? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}❌ Đã hủy${NC}"
        exit 0
    fi
fi

# Push lên GitHub
echo ""
echo -e "${YELLOW}🚀 Đang push lên GitHub...${NC}"

# Kiểm tra xem đã set upstream chưa
if git rev-parse --abbrev-ref --symbolic-full-name @{u} > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Upstream đã được set${NC}"
    git push origin "$current_branch"
else
    echo -e "${YELLOW}⚠ Setting upstream...${NC}"
    git push -u origin "$current_branch"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     ✅ ĐÃ PUSH THÀNH CÔNG!                                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "📍 Branch: $current_branch"
echo "🌐 GitHub: $(git remote get-url origin | sed 's/\.git$//')/tree/$current_branch"
echo ""
echo "💡 Bạn có thể xem branch trên GitHub:"
echo "   https://github.com/haidang24/phantom-grid/tree/$current_branch"
echo ""

