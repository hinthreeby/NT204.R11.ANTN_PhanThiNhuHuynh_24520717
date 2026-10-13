# Test T02 - HTML Entity Decode

## Mục tiêu

Kiểm tra Decoder giải mã HTML entity trong nội dung HTTP text.

## Input/Scenario

`input.jsonl` chứa HTTP response `text/html` với body `&lt;script&gt;alert(1)&lt;/script&gt;`.

## Cách chạy

```powershell
python main.py --input TEST\T02_html_entity\input.jsonl --output TEST\T02_html_entity\events.jsonl
```

## Kết quả mong đợi

- Giữ body gốc.
- Giải mã thành `<script>alert(1)</script>`.
- Không phát sinh exception.

## Kết quả hiện tại

- `events.jsonl` có 1 HTTP response status 200.
- `raw_body` giữ nguyên HTML entity và `decoded_text` là `<script>alert(1)</script>`.
- `decode_status = success`; `result.txt` ghi xử lý 1 event, bỏ qua 0 event.

**Trạng thái: PASS**

## Minh chứng hiện có

- `input.jsonl`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
