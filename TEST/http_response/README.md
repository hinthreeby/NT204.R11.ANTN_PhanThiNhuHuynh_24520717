# Test - HTTP Response

## Mục tiêu

Kiểm tra parser phân tích HTTP response status, headers và body.

## Input/Scenario

`input.pcap` chứa HTTP/1.1 response.

## Cách chạy

```powershell
python main.py --pcap TEST\http_response\input.pcap --output TEST\http_response\events.jsonl
```

## Kết quả mong đợi

- Nhận diện response HTTP.
- Trích xuất status code, reason, headers và body.

## Kết quả hiện tại

- `events.jsonl` có HTTP/1.1 response `200 OK`.
- Headers gồm Content-Type, Content-Length và Server; body là `Hello`.
- `result.txt` ghi xử lý 1 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
