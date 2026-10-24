# Test T05 - Rule Direction Matching

## Mục tiêu

Kiểm tra `->` đúng chiều và `<>` hai chiều bằng Parser và Header Matcher thực tế (PDF Bài 3, mục 7, T05).

## Input/Scenario

- Endpoint A: `192.168.1.10:50000`; B: `10.0.0.20:80`.
- `sample.rules`: 4 rule TCP exact/CIDR và port range, mỗi loại có `->` và `<>`.
- `validate.py` chứa 30 event fixture theo schema Bài 1–2, gồm chiều thuận/ngược, sai IP/port, UDP và trường dữ liệu thiếu hoặc malformed.

## Cách chạy

Chạy từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT3/T05_direction_matching/validate.py
```

## Kết quả mong đợi

- Cả 4 rule được validate; 30 lần gọi Matcher cho đúng 9 MATCH và 21 NO_MATCH.
- `<>` chỉ đảo đồng thời IP và port; CIDR/range match đúng ở hai biên, `->` không match chiều ngược.
- Sai protocol, thiếu/sai IP hoặc port trả NO_MATCH an toàn; input không bị sửa và không tạo Detection Event.

## Kết quả hiện tại

**T05 PASS:** 30 assertion matching, gồm 9 MATCH và 21 NO_MATCH, exit code 0; chạy từ thư mục tạm cũng cho cùng kết quả.
**Regression T01–T04 PASS:** cùng exit code 0, output khớp minh chứng cũ; log lưu trong `result.txt` của T05.

## Minh chứng

`sample.rules`, `validate.py`, `result.txt`.
