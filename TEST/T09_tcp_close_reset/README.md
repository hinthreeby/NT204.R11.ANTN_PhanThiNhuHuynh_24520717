# Test T09: TCP Close and Reset

## Mục tiêu

Kiểm tra Flow/Connection Tracker có cập nhật đúng trạng thái TCP khi
connection đóng bình thường bằng FIN/ACK hoặc bị reset bằng RST hay không.

## Input

Test gồm hai TCP flow độc lập.

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

## Cách chạy

```bash
python main.py --input TEST/T09_tcp_close_reset/input.jsonl --output TEST/T09_tcp_close_reset/events.jsonl
python TEST/T09_tcp_close_reset/validate.py
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

## Kết quả thực tế
- Trạng thái: PASS
- Flow thứ nhất chuyển ESTABLISHED → CLOSING → CLOSED.
- Flow thứ hai chuyển ESTABLISHED → RESET.
- Hai connection được giữ thành hai flow riêng.
- Validator trả về T09 PASS.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, Flow Tracker xử lý đúng TCP connection close
và reset.