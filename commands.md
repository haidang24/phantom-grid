# Các Lệnh Chạy Phantom Grid

## Lệnh Cơ Bản

### 1. Chạy với interface tự động
```bash
sudo ./bin/phantom-grid
```

### 2. Chạy với interface cụ thể
```bash
sudo ./bin/phantom-grid -interface ens33
```

## SPA Modes

### Static Mode (Mặc định)
```bash
sudo ./bin/phantom-grid -interface ens33 -spa-mode static
```

### Asymmetric Mode (Khuyến nghị)
```bash
sudo ./bin/phantom-grid -interface ens33 -spa-mode asymmetric -spa-key-dir ./keys
```

### Dynamic Mode
```bash
sudo ./bin/phantom-grid -interface ens33 -spa-mode dynamic -spa-key-dir ./keys
```

## Output Modes

### Dashboard Only (Mặc định)
```bash
sudo ./bin/phantom-grid -interface ens33 -output dashboard
```

### ELK Only
```bash
sudo ./bin/phantom-grid -interface ens33 -output elk -elk-address http://localhost:9200
```

### Both Dashboard và ELK
```bash
sudo ./bin/phantom-grid -interface ens33 -output both -elk-address http://localhost:9200
```

## Ví Dụ Đầy Đủ

### Chạy với Asymmetric SPA và Dashboard
```bash
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys \
  -output dashboard
```

### Chạy với ELK và Authentication
```bash
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode asymmetric \
  -spa-key-dir ./keys \
  -output elk \
  -elk-address http://localhost:9200 \
  -elk-index phantom-grid \
  -elk-user elastic \
  -elk-pass changeme
```

### Chạy với Static Token Tùy Chỉnh
```bash
sudo ./bin/phantom-grid \
  -interface ens33 \
  -spa-mode static \
  -spa-static-token "my-secret-token-12345"
```

## Sử Dụng Script Helper

```bash
# Với biến môi trường
sudo INTERFACE=ens33 SPA_MODE=asymmetric OUTPUT_MODE=dashboard ./run-agent.sh

# Hoặc chỉnh sửa script trực tiếp
sudo ./run-agent.sh
```

## Kiểm Tra Help

```bash
./bin/phantom-grid --help
./bin/phantom-grid -h
```

