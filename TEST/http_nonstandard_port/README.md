# Test - HTTP trên Non-standard Port

## Mục tiêu

Kiểm tra detector nhận diện HTTP dựa trên payload khi traffic không đi qua port HTTP chuẩn.

## Input/Scenario

`input.pcap` chứa HTTP GET từ port client 51000 tới server port 8888.

## Cách chạy

```powershell
python main.py --pcap TEST\http_nonstandard_port\input.pcap --output TEST\http_nonstandard_port\events.jsonl
```

## Kết quả mong đợi

- Port 8888 vẫn được nhận diện là HTTP.
- GET request được parse đúng.

## Kết quả hiện tại

- `events.jsonl` nhận diện `application.protocol = HTTP` trên destination port 8888.
- Request có `GET /admin HTTP/1.1`, Host `bonus.example.com`.
- `result.txt` ghi xử lý 1 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
