# Test - Unknown/Unsupported Protocol

## Mục tiêu

Kiểm tra pipeline không crash khi gặp IPv4 packet không có TCP/UDP layer hỗ trợ.

## Input/Scenario

`input.pcap` chứa IPv4/ICMP packet.

## Cách chạy

```powershell
python main.py --pcap TEST\unknown_protocol\input.pcap --output TEST\unknown_protocol\events.jsonl
```

## Kết quả mong đợi

- Transport/application được đánh dấu UNKNOWN.
- Có error/reason phù hợp nhưng chương trình tiếp tục chạy.

## Kết quả hiện tại

- `events.jsonl` có `transport.protocol = UNKNOWN` và `application.protocol = UNKNOWN`.
- `errors` ghi `Unsupported or missing TCP/UDP layer`.
- `result.txt` ghi xử lý 1 packet, không uncaught exception.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
