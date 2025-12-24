# HỒ SƠ DỰ ÁN CÔNG NGHỆ – PHANTOM GRID

## 1. Thông tin chung

- **Tên dự án**: Phantom Grid  
- **Mô tả ngắn**: Hệ thống phòng thủ chủ động (Active Defense) sử dụng công nghệ eBPF ở tầng Kernel.  
- **Lĩnh vực**: An toàn thông tin (Cybersecurity), Mạng máy tính (Computer Networking)  
- **Phân khúc**: Bảo mật hạ tầng (Infrastructure Security), Zero Trust, Cloud-Native Security  

---

## 2. Tổng quan dự án (Executive Summary)

Trong bối cảnh các cuộc tấn công mạng (APT, Ransomware) ngày càng tinh vi, các giải pháp phòng thủ truyền thống như Tường lửa (Firewall) hay Hệ thống phát hiện xâm nhập (IDS) đang bộc lộ điểm yếu chết người: chúng là **phòng thủ thụ động**.  
“Phe phòng thủ phải đúng 100 lần, hacker chỉ cần đúng 1 lần”.

**Phantom Grid** là một bước đột phá trong tư duy bảo mật: chuyển từ **phòng thủ thụ động** sang **phòng thủ chủ động** (Active Defense).  
Thay vì chỉ cố gắng chặn hacker, Phantom Grid biến hạ tầng mạng nội bộ thành một **“mê cung ảo”**.

Sử dụng công nghệ **eBPF (Extended Berkeley Packet Filter)** hoạt động trực tiếp trong nhân (kernel) Linux, Phantom Grid có khả năng:

1. **Giả lập hàng nghìn máy chủ ảo**: làm nhiễu loạn giai đoạn trinh sát của hacker.  
2. **Dẫn dụ trong suốt (Transparent Redirection)**: hacker tấn công vào IP/port giả sẽ bị chuyển hướng âm thầm vào môi trường bẫy (honeypot) mà không hề nhận ra.  
3. **Đảm bảo hiệu năng cực cao**: xử lý gói tin ở tốc độ đường truyền (wire-speed), không gây chậm hệ thống như các giải pháp truyền thống.  

---

## 3. Vấn đề và thực trạng (Problem Statement)

### 3.1. Nỗi đau của doanh nghiệp (Pain Points)

- **Di chuyển ngang (Lateral Movement)**: phần lớn thiệt hại xảy ra sau khi hacker đã vượt qua lớp phòng thủ biên. Trong mạng nội bộ (LAN/VLAN), hacker có thể thoải mái scan và tấn công các máy chủ quan trọng.  
- **Thời gian phát hiện chậm (Dwell Time)**: trung bình hacker nằm vùng trong hệ thống khoảng **21 ngày** trước khi bị phát hiện.  
- **Quá tải cảnh báo (Alert Fatigue)**: hệ thống giám sát (SOC) ngày nay gửi về hàng nghìn cảnh báo mỗi ngày, khiến đội ngũ vận hành dễ bị “lờn” cảnh báo và bỏ sót sự cố thật.  

### 3.2. Hạn chế của giải pháp hiện tại

- **Firewall / IPS**: phụ thuộc vào tập luật (rules) và chữ ký (signatures). Chỉ cần hacker thay đổi IP hoặc mã hóa payload là có thể vượt qua.  
- **Honeypot truyền thống**: cài đặt phức tạp, tốn tài nguyên (máy ảo thật), độ trễ cao nên dễ bị hacker nhận ra là “bẫy giả”.  

---

## 4. Giải pháp kỹ thuật cốt lõi (Core Technology)

Phantom Grid tạo ra sự khác biệt nhờ làm chủ công nghệ **eBPF** – thường được ví như “JavaScript cho Linux Kernel”, cho phép chèn logic xử lý gói tin động vào nhân hệ điều hành một cách an toàn và hiệu năng cao.

### 4.1. Kiến trúc hệ thống

Hệ thống được thiết kế xoay quanh 3 module chính (mức ý tưởng), được hiện thực một phần trong phiên bản PoC:

1. **Module “The Mirage” (Ảo ảnh mạng) – eBPF XDP Layer**  
   - Hook trực tiếp vào Network Driver (tầng thấp nhất của OS).  
   - Khi phát hiện lưu lượng trinh sát (scan) từ hacker (ví dụ: Nmap SYN Scan), có thể sinh ra phản hồi giả để đánh lạc hướng.  
   - Mục tiêu: từ một IP thực, hacker nhìn thấy một “rừng” port và service, khó phân biệt thật – giả.  

2. **Module “The Portal” (Cổng dịch chuyển) – eBPF Redirect + Honeypot**  
   - Thực hiện cơ chế chuyển hướng (DNAT-like) không trạng thái ở tầng thấp.  
   - Trong PoC hiện tại, mọi kết nối TCP không phải SSH (`22`) và không phải port honeypot (`9999`) sẽ được **chuyển hướng sang port 9999** bằng eBPF XDP.  
   - Về phía hacker, IP đích vẫn giữ nguyên nên rất khó nhận ra mình đã vào môi trường bẫy.  

3. **Module “Shadow Recorder” (Giám sát bóng đêm)**  
   - Bên trong honeypot, toàn bộ lệnh gõ (keystrokes) và tương tác (ví dụ: `ls`, `whoami`, `pwd`, `exit`, lệnh tùy ý) được ghi nhận.  
   - Dữ liệu này được đẩy về **Dashboard dạng TUI** thời gian thực, giúp người vận hành theo dõi chiến thuật và hành vi của kẻ tấn công.  

### 4.2. Ngăn xếp công nghệ (Tech Stack – PoC hiện tại)

- **Kernel Core**: C (viết eBPF/XDP program), Clang/LLVM để biên dịch.  
- **User Space Agent**: Golang, sử dụng thư viện `github.com/cilium/ebpf` để nạp và gắn eBPF program vào interface mạng.  
- **Honeypot Environment**: TCP server giả lập SSH shell, viết bằng Go (có thể mở rộng sang Docker container sau).  
- **Dashboard**: giao diện TUI (Terminal UI) bằng thư viện `github.com/gizak/termui/v3`, hiển thị log, mức độ đe dọa (Threat Level) và số lượng kết nối bị bẫy.  

Trong lộ trình tương lai, kiến trúc có thể mở rộng lên:

- Honeypot chạy trong Docker containers (cô lập tốt hơn, dễ reset).  
- Dashboard web (ReactJS + WebSockets) để hiển thị real-time trên trình duyệt.  

---

## 5. Tính năng nổi bật (Key Features)

| Tính năng                          | Mô tả chi tiết                                                                                          |
|------------------------------------|----------------------------------------------------------------------------------------------------------|
| Ma trận ảo hóa (Ghost Grid)       | Biến một server vật lý thành mạng lưới giả lập với hàng loạt “máy ảo logic” và service giả, làm nhiễu thông tin trinh sát. |
| Bẫy tàng hình (Invisible Trap)    | Hacker không phân biệt được đâu là server thật, đâu là bẫy; quá trình chuyển hướng diễn ra trong suốt. |
| Cách ly tức thì (Instant Isolation)| Khi hacker chạm vào bẫy, IP có thể bị đánh dấu (tag). Từ đây có thể kết nối với cơ chế “kill switch” để cô lập. |
| Hiệu năng vượt trội               | Xử lý ở tầng eBPF/XDP nên chiếm rất ít CPU/RAM, vẫn duy trì hiệu năng gần tốc độ đường truyền.          |

---

## 6. Tính khả thi và tiềm năng thương mại

### 6.1. Khả thi kỹ thuật

- Đã xây dựng thành công phiên bản PoC chạy trên nhân Linux 5.4+.  
- Đã demo khả năng đánh lừa các công cụ scan phổ biến (ý tưởng kiến trúc): Nmap, Masscan, Nessus.  
- PoC hiện tại đã hiện thực:
  - eBPF XDP hook để sửa port đích và dẫn traffic vào honeypot.  
  - Honeypot TCP với fake SSH banner và shell đơn giản.  
  - Dashboard TUI cập nhật real-time log và “Threat Level”.  

### 6.2. Mô hình thương mại (Business Model)

- **Khách hàng mục tiêu**:
  - Khối ngân hàng / tài chính (yêu cầu bảo mật cao).  
  - Khối chính phủ / hạ tầng trọng yếu (phòng chống APT).  
  - Doanh nghiệp cung cấp dịch vụ Cloud / Data Center.  

- **Hình thức sản phẩm**:
  - Phần mềm dạng agent cài trực tiếp lên server.  
  - Phiên bản tích hợp cho Kubernetes / Cloud-Native (DaemonSet hoặc sidecar).  

---

## 7. Lộ trình phát triển (Roadmap)

- **Giai đoạn 1 (Hiện tại – 3 tháng)**  
  - Hoàn thiện core eBPF (XDP redirect), cơ chế honeypot và dashboard giám sát thời gian thực (TUI).  
  - Tối ưu ổn định, độ trễ và khả năng xử lý gói tin.  

- **Giai đoạn 2 (6 tháng tới)**  
  - Tích hợp **Generative AI** vào honeypot để:
    - Tự động sinh dữ liệu giả (fake file, log, cấu trúc thư mục).  
    - Tương tác “thông minh” với hacker nhằm kéo dài thời gian, thu thập thêm TTPs.  

- **Giai đoạn 3 (1 năm tới)**  
  - Đóng gói thành sản phẩm thương mại:
    - Hỗ trợ Kubernetes và môi trường Cloud-Native.  
    - Bổ sung dashboard web, API tích hợp SIEM (ELK, Splunk, OpenSearch).  

---

## 8. Kết luận

Phantom Grid không chỉ là một công cụ bảo mật, mà là sự thay đổi trong **tư duy chiến lược phòng thủ**.  
Dự án chuyển vai trò của người quản trị mạng từ thế bị động sang **chủ động dẫn dắt cuộc chơi**, biến kẻ tấn công thành “nạn nhân” trong một môi trường bẫy được thiết kế cẩn thận.

Nhờ ứng dụng công nghệ **eBPF** – một trong những nền tảng cốt lõi đang định hình tương lai của hạ tầng Linux – Phantom Grid vừa có tính **tiên phong**, vừa đảm bảo **độ khó kỹ thuật cao**, lại giải quyết trực diện bài toán an ninh mạng hiện đại: phát hiện chậm, thiếu visibility và khó kiểm soát di chuyển ngang.

Phantom Grid là ứng cử viên xứng đáng cho các hạng mục **giải pháp an toàn thông tin sáng tạo và xuất sắc**.

---

## 9. Thông tin người thực hiện

- **Họ tên**: Mai Hải Đăng  
- **Vai trò**: Nghiên cứu & phát triển (System/Network Programming, eBPF, Active Defense)  
- **Liên hệ**:  
  - Email: *(điền thêm)*  
  - Số điện thoại: *(điền thêm)*  


