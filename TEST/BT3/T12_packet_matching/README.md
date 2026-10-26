# Test T12 - TCP Flags & dsize Matching

## Mục tiêu

Kiểm tra flags và dsize theo normalized event thực tế (PDF Bài 3, mục 3, 4.4 và T12).

## Input/Scenario

- `sample.rules`: 17 rule valid, gồm flags S/SA/A/F/R/P/U/C/E/0, dsize và tổ hợp flags + dsize.
- `validate.py` tạo packet TCP/UDP trong bộ nhớ, serialize rồi gọi Packet Parser Bài 1; có kiểm tra qua toàn bộ pipeline.
- 66 kịch bản gồm binary/UTF-8, biên kích thước, dữ liệu thiếu/malformed và length mâu thuẫn hex.

## Cách chạy

Chạy từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT3/T12_packet_matching/validate.py
```

## Kết quả mong đợi

- Plain flags khớp chính xác tập cờ của packet; S khác SA, thiếu flags không phải flags 0, UDP không match flags TCP.
- dsize dùng transport payload theo byte: N chính xác, <N/>N nghiêm ngặt, N<>M loại cả hai biên.
- Thiếu length chỉ khôi phục khi có hex hợp lệ; dữ liệu lỗi/mâu thuẫn trả NO_MATCH có reason; hai option kết hợp bằng AND.
- IPv4 length, flow counters và decoded text không thay thế flags/payload length; input giữ nguyên.

## Kết quả hiện tại

**T12 PASS:** 66 kịch bản, 132 assertion trạng thái, 25 MATCH/41 NO_MATCH; exit code 0, chạy từ thư mục tạm cũng PASS.
**Regression T01–T08 PASS:** exit code 0, minh chứng cũ giữ nguyên; log lưu trong `result.txt` của T12.
Chỉ kiểm chứng Packet Matcher; chưa tích hợp Content/Evaluation Engine.

## Minh chứng

`sample.rules`, `validate.py`, `result.txt`.
