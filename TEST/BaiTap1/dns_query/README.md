# Test - DNS Query

## Mục tiêu

Kiểm tra parser trích xuất đúng thông tin DNS query.

## Input/Scenario

`input.pcap` chứa UDP DNS query tới port 53.

## Cách chạy

```powershell
python main.py --pcap TEST\dns_query\input.pcap --output TEST\dns_query\events.jsonl
```

## Kết quả mong đợi

- Nhận diện `application.protocol = DNS`, type `query`.
- Trích xuất domain và query type chính xác.

## Kết quả hiện tại

- `events.jsonl` có 1 DNS query.
- Domain là `example.com`, `query_type = A`, transaction ID 4660.
- `result.txt` ghi xử lý 1 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
