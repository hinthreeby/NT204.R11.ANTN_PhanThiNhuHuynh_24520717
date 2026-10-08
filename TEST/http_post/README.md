# Test - HTTP POST Request

## Mục tiêu

Kiểm tra parser phân tích HTTP POST request và body.

## Input/Scenario

`input.pcap` chứa HTTP POST `/login` với form body.

## Cách chạy

```powershell
python main.py --pcap TEST\http_post\input.pcap --output TEST\http_post\events.jsonl
```

## Kết quả mong đợi

- Nhận diện method POST.
- Trích xuất URI, headers và body.

## Kết quả hiện tại

- `events.jsonl` có HTTP POST `/login`.
- Body là `username=admin&password=123`; Content-Type là `application/x-www-form-urlencoded`.
- `result.txt` ghi xử lý 1 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
