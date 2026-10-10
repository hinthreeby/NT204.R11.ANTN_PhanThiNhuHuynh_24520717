# Test T13: Flow Statistics

## Mục tiêu

Kiểm tra Flow Tracker cập nhật đúng thống kê của nhiều packet hai chiều
trong cùng một TCP flow.

## Input

Một TCP flow gồm 6 packet:

1. SYN forward - 60 bytes
2. SYN/ACK backward - 60 bytes
3. ACK forward - 52 bytes
4. PSH/ACK forward - 100 bytes
5. PSH/ACK backward - 120 bytes
6. FIN/ACK forward - 52 bytes

## Cách chạy

```bash
python main.py --input TEST/T13_flow_statistics/input.jsonl --output TEST/T13_flow_statistics/events.jsonl
python TEST/T13_flow_statistics/validate.py
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

## Kết quả thực tế
- Trạng thái: PASS
- Tất cả packet/byte/direction/flag counters đều đúng.
- Duration được tính đúng.
- Validator trả về T13 PASS.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, Flow Tracker duy trì đúng statistics của một
bidirectional TCP flow.