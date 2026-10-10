# Test T10: UDP DNS Flow

## Mục tiêu

Kiểm tra Flow Tracker có gom DNS query/response UDP hai chiều vào cùng
một flow và cập nhật đúng packet/byte statistics hay không.

## Input

Hai event:

1. DNS query:
   `192.168.1.10:53000 → 8.8.8.8:53`, 60 bytes.
2. DNS response:
   `8.8.8.8:53 → 192.168.1.10:53000`, 90 bytes.

## Cách chạy

```bash
python main.py --input TEST/T10_udp_dns_flow/input.jsonl --output TEST/T10_udp_dns_flow/events.jsonl
python TEST/T10_udp_dns_flow/validate.py
```
## Kết quả mong đợi
- Hai packet có cùng flow_id.
- Query có direction = forward.
- Response có direction = backward.
- packet_count = 2.
- byte_count = 150.
- Forward: 1 packet / 60 bytes.
- Backward: 1 packet / 90 bytes.
- duration = 0.5.
- UDP không có TCP state.

## Kết quả thực tế
- Trạng thái: PASS
- Query và response thuộc cùng UDP flow.
- Các packet/byte counter đúng.
- Validator trả về T10 PASS.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, UDP bidirectional flow và statistics hoạt động đúng.