# Hướng Dẫn Push Lên GitHub Branches

## Cách 1: Tạo Branch Test và Push Lên GitHub

### Bước 1: Commit các thay đổi hiện tại (nếu cần)

```bash
# Xem các file đã thay đổi
git status

# Thêm tất cả các file mới và đã sửa
git add .

# Commit với message
git commit -m "feat: Add SPA authentication improvements and web interface"
```

### Bước 2: Tạo branch test mới

```bash
# Tạo và chuyển sang branch test
git checkout -b test

# Hoặc nếu branch test đã tồn tại
git checkout test
```

### Bước 3: Push branch test lên GitHub

```bash
# Push branch test lên GitHub (lần đầu)
git push -u origin test

# Hoặc nếu đã push rồi, chỉ cần:
git push origin test
```

---

## Cách 2: Push từ Branch Main Hiện Tại

Nếu bạn muốn push các thay đổi từ branch `main` lên branch `test`:

```bash
# 1. Commit các thay đổi trên main (nếu chưa commit)
git add .
git commit -m "feat: Add SPA authentication improvements and web interface"

# 2. Tạo branch test từ main
git checkout -b test

# 3. Push lên GitHub
git push -u origin test
```

---

## Cách 3: Tạo Branch Test và Merge từ Main

```bash
# 1. Đảm bảo main đã commit tất cả thay đổi
git checkout main
git add .
git commit -m "feat: Add SPA authentication improvements and web interface"
git push origin main

# 2. Tạo branch test từ main
git checkout -b test

# 3. Push branch test
git push -u origin test
```

---

## Cách 4: Sử Dụng Script Helper

Sử dụng script `scripts/push-to-test-branch.sh`:

```bash
chmod +x scripts/push-to-test-branch.sh
./scripts/push-to-test-branch.sh
```

---

## Các Lệnh Git Hữu Ích

### Xem tất cả branches (local và remote):
```bash
git branch -a
```

### Xem branches trên GitHub:
```bash
git branch -r
```

### Chuyển đổi giữa các branches:
```bash
git checkout main      # Chuyển về main
git checkout test      # Chuyển về test
```

### Xóa branch local:
```bash
git branch -d test     # Xóa branch test (nếu đã merge)
git branch -D test     # Force delete
```

### Xóa branch trên GitHub:
```bash
git push origin --delete test
```

### Pull branch test từ GitHub:
```bash
git checkout test
git pull origin test
```

### Merge test vào main:
```bash
git checkout main
git merge test
git push origin main
```

---

## Lưu Ý

1. **Luôn commit trước khi tạo branch mới** để tránh mất thay đổi
2. **Kiểm tra remote** trước khi push:
   ```bash
   git remote -v
   ```
3. **Push với `-u` lần đầu** để set upstream:
   ```bash
   git push -u origin test
   ```
4. **Kiểm tra branch trên GitHub** sau khi push:
   - Vào: `https://github.com/haidang24/phantom-grid/branches`
   - Hoặc: `https://github.com/haidang24/phantom-grid/tree/test`

---

## Troubleshooting

### Lỗi: "branch already exists"
```bash
# Xóa branch local và tạo lại
git branch -D test
git checkout -b test
```

### Lỗi: "failed to push some refs"
```bash
# Pull trước khi push
git pull origin test
git push origin test
```

### Lỗi: "authentication failed"
```bash
# Cấu hình lại credentials
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Hoặc sử dụng SSH key thay vì HTTPS
git remote set-url origin git@github.com:haidang24/phantom-grid.git
```

