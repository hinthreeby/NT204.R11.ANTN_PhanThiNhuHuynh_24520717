# Test - DNS Response

## Mục tiêu

Kiểm tra parser trích xuất DNS response và ít nhất một answer record.

## Input/Scenario

`input.pcap` chứa DNS response từ port 53.

## Cách chạy

```powershell
python main.py --pcap TEST\dns_response\input.pcap --output TEST\dns_response\events.jsonl
```

## Kết quả mong đợi

- Nhận diện type `response`.
- Có answer record với name/type/TTL/data.

## Kết quả hiện tại

- `events.jsonl` có 1 DNS response, `response_code = 0`.
- Answer: `example.com`, type A, TTL 300, data `93.184.216.34`.
- `result.txt` ghi xử lý 1 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
