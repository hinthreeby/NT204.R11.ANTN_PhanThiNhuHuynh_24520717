# Test T06: Missing Field

## Mục tiêu

Kiểm tra Preprocessor có xử lý an toàn event thiếu field không bắt buộc
và tạo representation nhất quán hay không.

## Input

Event hợp lệ ở network/transport nhưng không có:

- `application`
- `errors`

## Cách chạy

```bash
python main.py --input TEST/T06_missing_field/input.jsonl --output TEST/T06_missing_field/events.jsonl
python TEST/T06_missing_field/validate.py
```
## Kết quả mong đợi
- Không phát sinh exception.
- application.protocol = UNKNOWN
- errors = []
- preprocess_status = partial
- processing_action = continue
- Có reason giải thích dữ liệu thiếu.

## Kết quả thực tế
- Trạng thái: PASS
- Missing field được bổ sung bằng representation nhất quán.
- Validator trả về T06 PASS.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, Preprocessor xử lý missing optional fields an toàn.