# Test T09: TCP Close and Reset

## Mục tiêu

Kiểm tra Flow/Connection Tracker có cập nhật đúng trạng thái TCP khi connection đóng bình thường bằng FIN/ACK hoặc bị reset bằng RST hay không.

## Input

Test gồm hai TCP flow độc lập.

Giữ nguyên 9 packet đầu và các assertion của hai flow cũ. Thêm 8 packet để kiểm tra hai lần tái sử dụng cùng 5-tuple, tổng cộng 17 packet trong `input.jsonl`.

### Flow 1 - Normal close

1. SYN
2. SYN/ACK
3. ACK
4. FIN/ACK từ client
5. FIN/ACK từ server

### Flow 2 - Reset

1. SYN
2. SYN/ACK
3. ACK
4. RST/ACK

### Flow 3 - Tái sử dụng sau RESET

Packet 10–12: SYN → SYN/ACK → ACK trên cùng 5-tuple với Flow 2, tại các timestamp 1790000720–1790000722. Mỗi packet có `network.total_length = 40`.

### Flow 4 - Tái sử dụng sau CLOSED

Packet 13–17: SYN → SYN/ACK → ACK → FIN/ACK → FIN/ACK trên cùng 5-tuple với Flow 1. SYN mới xuất phát từ endpoint vốn là server để kiểm tra lại direction; timestamp 1790000730–1790000734, mỗi packet 40 bytes.

Validator còn chạy các chuỗi trong bộ nhớ: SYN → RST → SYN, SYN truyền lại, packet ACK/SYN-ACK đến muộn, SYN kèm FIN/RST, và tái sử dụng 5-tuple khi timestamp của SYN mới trùng SYN cũ. Không tạo file test phụ.

## Cách chạy

Chạy từ thư mục gốc repository.

```bash
python main.py --input TEST/BaiTap2/T09_tcp_close_reset/input.jsonl --output TEST/BaiTap2/T09_tcp_close_reset/events.jsonl
python TEST/BaiTap2/T09_tcp_close_reset/validate.py
```
## Kết quả mong đợi
Flow đóng bình thường:
- Handshake hoàn tất → ESTABLISHED
- FIN đầu tiên → CLOSING
- FIN chiều còn lại → CLOSED
Flow reset:
- Handshake hoàn tất → ESTABLISHED
- RST → RESET
Hai connection phải có flow_id khác nhau.

Tái sử dụng connection:

- Cả bốn connection có `flow_id` riêng, ổn định qua các packet hai chiều.
- SYN sau CLOSED/RESET tạo object mới và trạng thái HANDSHAKE; FIN/RST và counter của flow cũ được giữ nguyên.
- Flow 3: 3 packet, 120 bytes (forward 80, backward 40), duration 2 giây, trạng thái ESTABLISHED.
- Flow 4: 5 packet, 200 bytes (forward 120, backward 80), duration 4 giây, trạng thái CLOSED.
- Khi SYN mở connection mới thay thế flow cũ, `expired_flows` chứa summary của flow cũ với `close_reason = tcp_reset` hoặc `tcp_closed`; giữ nguyên schema hiện có.
- Flow terminal được giữ để ghi nhận packet đến muộn, nhưng không thể đổi CLOSED thành RESET vì RST muộn. Khi loại khỏi bảng sau timeout, lý do vẫn là TCP close/reset. Flow còn hoạt động hết hạn mới mang lý do `idle_timeout`.
- SYN truyền lại trong connection đang hoạt động không tạo instance mới; SYN/ACK hoặc SYN kèm FIN/RST không được coi là SYN mở connection mới.

## Kết quả thực tế
- Trạng thái: PASS
- Flow thứ nhất chuyển ESTABLISHED → CLOSING → CLOSED.
- Flow thứ hai chuyển ESTABLISHED → RESET.
- Hai connection được giữ thành hai flow riêng.
- Validator trả về T09 PASS.
- Đã chạy pipeline với đủ 17 packet, 0 packet bị bỏ qua; kiểm chứng counter, direction, duration, object độc lập và lý do kết thúc trong `validate.py`.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, Flow Tracker xử lý đúng TCP connection close và reset.
