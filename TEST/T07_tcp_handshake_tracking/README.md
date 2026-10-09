# Test T07: TCP Handshake Tracking

## Mục tiêu

Kiểm tra Flow/Connection Tracker có theo dõi đúng quá trình TCP
three-way handshake và chuyển flow sang trạng thái ESTABLISHED hay không.

## Input

Ba TCP event cùng một bidirectional flow:

1. Client → Server: SYN
2. Server → Client: SYN/ACK
3. Client → Server: ACK

Cả ba packet có `payload_length = 0`.

## Cách chạy

```bash
python main.py --input TEST/T07_tcp_handshake_tracking/input.jsonl --output TEST/T07_tcp_handshake_tracking/events.jsonl
python TEST/T07_tcp_handshake_tracking/validate.py
```

## Kết quả mong đợi
- Cả ba packet có cùng flow_id.
- SYN có direction = forward.
- SYN/ACK có direction = backward.
- ACK cuối có direction = forward.
- SYN đưa flow sang HANDSHAKE.
- SYN/ACK giữ flow ở HANDSHAKE.
- ACK cuối đưa flow sang ESTABLISHED.
- TCP packet không có payload vẫn được xử lý bình thường.

## Kết quả thực tế
- Trạng thái: PASS
- Ba packet được gắn vào cùng một flow.
- Direction được xác định đúng.
- Trạng thái cuối của flow là ESTABLISHED.
- Validator trả về T07 PASS.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, TCP three-way handshake được theo dõi đúng
và connection chuyển sang trạng thái ESTABLISHED.