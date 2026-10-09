# Test T08: Bidirectional Flow

## Mục tiêu

Kiểm tra Flow Tracker có gom packet A→B và B→A của cùng
bidirectional 5-tuple vào cùng một flow và xác định đúng direction hay không.

## Input

Hai TCP event:

1. `192.168.1.10:50000 → 192.168.1.20:80`
2. `192.168.1.20:80 → 192.168.1.10:50000`

Event thứ hai là chiều đảo ngược của event thứ nhất.

## Cách chạy

```bash
python main.py --input TEST/T08_bidirectional_flow/input.jsonl --output TEST/T08_bidirectional_flow/events.jsonl
python TEST/T08_bidirectional_flow/validate.py
```

## Kết quả mong đợi
- Cả hai event được track.
- Hai event có cùng flow_id.
- Event A→B có direction = forward.
- Event B→A có direction = backward.
- Endpoint A/B được giữ ổn định trong flow.

## Kết quả thực tế
- Trạng thái: PASS
- Hai chiều được gắn cùng flow_id.
- Direction được xác định đúng.
- Validator trả về T08 PASS.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, Flow Tracker nhận diện đúng một flow hai chiều
và xác định đúng hướng packet.