# Test T12: Idle Timeout

## Mục tiêu

Kiểm tra idle timeout cho cả UDP và TCP, việc xuất thông tin flow hết
hạn và loại flow khỏi active-flow table.

## Input

Cấu hình mặc định:

- UDP idle timeout: 60 giây.
- TCP idle timeout: 300 giây.

Test tạo một UDP flow và một TCP flow, sau đó tạo các event có timestamp
vượt quá timeout tương ứng.

## Cách chạy

```bash
python main.py --input TEST/T12_idle_timeout/input.jsonl --output TEST/T12_idle_timeout/events.jsonl
python TEST/T12_idle_timeout/validate.py
```

## Kết quả mong đợi
- UDP flow hết hạn sau hơn 60 giây không hoạt động.
- TCP flow hết hạn sau hơn 300 giây không hoạt động.
- Flow hết hạn xuất hiện trong expired_flows.
- Flow hết hạn bị loại khỏi active-flow table.
- Khi cùng 5-tuple xuất hiện lại, một flow_id mới được tạo.

## Kết quả thực tế
- Trạng thái: PASS
- UDP và TCP flow đều hết hạn đúng timeout.
- Flow summary được xuất trước khi loại khỏi active table.
- Khi traffic xuất hiện lại, cả hai tạo flow mới.
- Validator trả về T12 PASS.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, idle timeout và flow expiration hoạt động đúng
cho cả TCP và UDP.