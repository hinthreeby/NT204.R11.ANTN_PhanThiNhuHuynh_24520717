# Test T11: Concurrent Flows

## Mục tiêu

Kiểm tra Flow Tracker có quản lý đồng thời nhiều flow và không gộp
nhầm các connection có endpoint/port khác nhau hay không.

## Input

Test sử dụng hai TCP flow:

Flow 1:

`192.168.1.10:50000 ↔ 192.168.1.20:80`

Flow 2:

`192.168.1.10:50001 ↔ 192.168.1.20:80`

Mỗi flow có một packet forward và một packet backward.

## Cách chạy

```bash
python main.py --input TEST/T11_concurrent_flows/input.jsonl --output TEST/T11_concurrent_flows/events.jsonl
python TEST/T11_concurrent_flows/validate.py
```
## Kết quả mong đợi
- Có đúng 2 flow_id khác nhau.
- Packet forward/backward của Flow 1 có cùng flow_id.
- Packet forward/backward của Flow 2 có cùng flow_id.
- Hai flow không bị gộp nhầm.
- Direction của từng packet được xác định đúng.

## Kết quả thực tế
- Trạng thái: PASS
- Bốn event được phân thành đúng hai flow.
- Hai flow có flow_id khác nhau.
- Reverse traffic được gắn lại đúng flow.
- Validator trả về T11 PASS.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, active-flow table quản lý đồng thời nhiều flow
và phân biệt đúng connection dựa trên bidirectional 5-tuple.