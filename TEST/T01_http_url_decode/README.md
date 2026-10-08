# Test T01 - HTTP URL/Percent Decode

## Mục tiêu

Kiểm tra Decoder giải mã URI có percent-encoding nhưng vẫn giữ nguyên giá trị URI ban đầu để phục vụ đối chiếu và phát hiện sau này.

## Input/Scenario

`input.jsonl` chứa HTTP GET tới `/login?id=%27%20OR%201%3D1`.

## Cách chạy

```powershell
python main.py --input TEST\T01_http_url_decode\input.jsonl --output TEST\T01_http_url_decode\events.jsonl
```

## Kết quả mong đợi

- Giữ `raw_uri = /login?id=%27%20OR%201%3D1`.
- Sinh `decoded_uri = /login?id=' OR 1=1`.
- `decode_status = success` và chương trình không crash.

## Kết quả hiện tại

- `events.jsonl` có 1 event HTTP request.
- `raw_uri` được giữ nguyên và `decoded_uri` được giải mã thành `/login?id=' OR 1=1`.
- `decoder.status = success`; `result.txt` ghi 1 event được xử lý, 0 event bị bỏ qua.

**Trạng thái: PASS**

## Minh chứng hiện có

- `input.jsonl`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
