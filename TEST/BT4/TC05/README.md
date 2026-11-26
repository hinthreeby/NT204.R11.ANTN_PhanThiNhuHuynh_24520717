# TC05 - SID Suppression

## Mục tiêu

Kiểm tra suppression theo SID cấu hình, độc lập với Core Engine.

## Input/Scenario

- Fixture trong `validate.py`: SID có/không trong danh sách, danh sách rỗng/trùng/sai kiểu và event tiếp theo.
- SID tiếp tục theo contract Ngày 1: integer dương; chuỗi số và Boolean bị reject, không tự ép kiểu.
- Suppression được ưu tiên hơn severity và allowlist; config được snapshot thành frozenset.

## Cách chạy

Từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT4/TC05/validate.py
```

## Kết quả mong đợi

SID bị suppress trả `suppressed`, alert=None, reason rõ và không sinh UUID; SID khác vẫn được xử lý bình thường, input không đổi.

## Kết quả hiện tại

PASS: 27 kịch bản, 62 assertion, exit code 0; đúng precedence và không rò trạng thái sang event sau.

## Minh chứng

`validate.py`, `result.txt`.
