# Test - DNS trên Non-standard Port

## Mục tiêu

Kiểm tra detector nhận diện DNS dựa trên cấu trúc payload ngay cả khi không sử dụng port 53.

## Input/Scenario

`input.pcap` có DNS query/response hai chiều qua port 5300.

## Cách chạy

```powershell
python main.py --pcap TEST\dns_nonstandard_port\input.pcap --output TEST\dns_nonstandard_port\events.jsonl
```

## Kết quả mong đợi

- Cả query và response được nhận diện là DNS.
- Query và response dùng port 5300 vẫn được parse đúng.

## Kết quả hiện tại

- `events.jsonl` có 2 packet DNS: query từ port 54000 tới 5300 và response từ 5300 về 54000.
- Query là `example.com` type A; response trả `93.184.216.34`.
- `result.txt` ghi xử lý đủ 2 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
