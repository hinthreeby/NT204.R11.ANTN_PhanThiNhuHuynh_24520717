# Test T13: Flow Statistics

## Mục tiêu

Kiểm tra Flow Tracker cập nhật đúng thống kê của nhiều packet hai chiều trong cùng một TCP flow.

## Input

Một TCP flow gồm 6 packet:

1. SYN forward - 60 bytes
2. SYN/ACK backward - 60 bytes
3. ACK forward - 52 bytes
4. PSH/ACK forward - 100 bytes
5. PSH/ACK backward - 120 bytes
6. FIN/ACK forward - 52 bytes

Giữ nguyên sáu event trong `input.jsonl` và toàn bộ assertion cũ (schema dùng `network.len`).

`validate.py` còn tạo sáu packet IPv4/TCP trong bộ nhớ, serialize rồi đưa qua parser Bài 1 và toàn bộ pipeline. Các packet dùng `network.total_length` do `parse_ipv4()` sinh ra, không có `network.len`:

1. SYN forward - 40 bytes, không payload.
2. SYN/ACK backward - 40 bytes, không payload.
3. ACK forward - 40 bytes, không payload.
4. PSH/ACK forward - 88 bytes, gồm 48 bytes payload.
5. PSH/ACK backward - 108 bytes, gồm 68 bytes payload.
6. FIN/ACK forward - 40 bytes, không payload.

Không tạo thêm file PCAP hay thay thế dữ liệu test cũ.

## Cách chạy

Chạy từ thư mục gốc repository.

```bash
python main.py --input TEST/BaiTap2/T13_flow_statistics/input.jsonl --output TEST/BaiTap2/T13_flow_statistics/events.jsonl
python TEST/BaiTap2/T13_flow_statistics/validate.py
```

## Kết quả mong đợi
- packet_count = 6
- byte_count = 444
- forward_packet_count = 4
- forward_byte_count = 264
- backward_packet_count = 2
- backward_byte_count = 180
- SYN_count = 2
- ACK_count = 5
- FIN_count = 1
- RST_count = 0
- duration = 5.0
- Trạng thái cuối là CLOSING.

Với sáu packet đi qua parser Bài 1:

- Byte count tích lũy: 40, 80, 120, 208, 316, 356.
- Tổng forward = 208 bytes; backward = 148 bytes.
- Packet count, direction, TCP state, flag counters và duration giữ cùng kết quả như flow cũ.
- SYN không payload vẫn đóng góp 40 bytes; packet có payload chỉ tính IPv4 total length một lần.

Kiểm tra thêm thứ tự ưu tiên `total_length` → `len` → `length` → `packet_length` → `payload_length`. Chỉ dùng fallback khi field trước thiếu hoặc không hợp lệ; kiểm tra `None`, chuỗi lỗi, số âm, số thực không nguyên, boolean và giá trị không hữu hạn. Chuỗi số nguyên hợp lệ được chấp nhận; độ dài 0 không kích hoạt fallback.

## Kết quả thực tế
- Trạng thái: PASS
- Tất cả packet/byte/direction/flag counters đều đúng.
- Duration được tính đúng.
- Validator trả về T13 PASS.
- Đã chạy lại cả fixture cũ và kiểm tra schema parser Bài 1; kết quả được ghi trong `result.txt`.
- Bộ assertion mở rộng phát hiện lỗi ở implementation cũ và PASS sau khi sửa.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, Flow Tracker duy trì đúng statistics của một bidirectional TCP flow.
