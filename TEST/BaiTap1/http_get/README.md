# Test - HTTP GET Request

## Mục tiêu

Kiểm tra detector/parser nhận diện và phân tích HTTP GET request.

## Input/Scenario

`input.pcap` chứa HTTP GET request.

## Cách chạy

```powershell
python main.py --pcap TEST\http_get\input.pcap --output TEST\http_get\events.jsonl
```

## Kết quả mong đợi

- Nhận diện HTTP request.
- Trích xuất method, URI, version và headers.

## Kết quả hiện tại

- `events.jsonl` có HTTP request với `method = GET`, `uri = /index.html`, `version = HTTP/1.1`.
- Headers gồm `Host: example.com` và `User-Agent: Day3-Test`.
- `result.txt` ghi xử lý 1 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
