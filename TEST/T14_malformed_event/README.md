# Test T14: Malformed Event

## Mục tiêu

Kiểm tra Preprocessor có xử lý an toàn event malformed/unsupported,
đánh dấu trạng thái và cung cấp lý do thay vì làm chương trình crash.

## Input

Event cố tình chứa:

- Timestamp không hợp lệ.
- Source IPv4 không hợp lệ.
- Source port lớn hơn 65535.
- Destination port âm.
- Application protocol không hỗ trợ.
- `errors` không phải list.

## Cách chạy

```bash
python main.py --input TEST/T14_malformed_event/input.jsonl --output TEST/T14_malformed_event/events.jsonl
python TEST/T14_malformed_event/validate.py
```
## Kết quả mong đợi
- Chương trình không crash.
- preprocess_status = invalid
- processing_action = continue với cấu hình mặc định.
- Có reason giải thích lỗi.
- Field không hợp lệ được chuyển về representation an toàn.
- Unsupported application protocol được chuyển thành UNKNOWN.

## Kết quả thực tế
- Trạng thái: PASS
- Event được xử lý an toàn và đánh dấu invalid.
- Validator trả về T14 PASS.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, malformed event không làm pipeline dừng và metadata
preprocessing phản ánh đúng trạng thái lỗi.