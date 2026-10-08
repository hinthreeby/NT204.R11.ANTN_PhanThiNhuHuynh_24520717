# Test - Invalid SMTP Base64

## Mục tiêu

Kiểm tra SMTP/MIME Decoder xử lý Base64 malformed mà không crash.

## Input/Scenario

`input.jsonl` chứa SMTP data với `Content-Transfer-Encoding: base64` nhưng body `THIS-IS-NOT-VALID-BASE64!!!`.

## Cách chạy

```powershell
python main.py --input TEST\smtp_invalid_base64\input.jsonl --output TEST\smtp_invalid_base64\events.jsonl
```

## Kết quả mong đợi

- Không uncaught exception.
- `decode_status = partial` và có `decode_reason`.

## Kết quả hiện tại

- `events.jsonl` có 1 SMTP data event.
- `decode_status = partial`; `decode_reason = Error: Non-base64 digit found`.
- `result.txt` ghi 1 event được xử lý, 0 event bị bỏ qua.

**Trạng thái: PASS**

## Minh chứng hiện có

- `input.jsonl`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
