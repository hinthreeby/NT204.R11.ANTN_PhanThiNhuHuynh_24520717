# Test - TCP Three-way Handshake

## Mục tiêu

Kiểm tra TCP parser nhận đúng ba packet của quá trình SYN → SYN/ACK → ACK.

## Input/Scenario

`input.pcap` chứa 3 TCP packet mô phỏng three-way handshake.

## Cách chạy

```powershell
python main.py --pcap TEST\tcp_handshake\input.pcap --output TEST\tcp_handshake\events.jsonl
```

## Kết quả mong đợi

- Packet 1 có SYN.
- Packet 2 có SYN và ACK.
- Packet 3 có ACK; tất cả được xử lý không lỗi.

## Kết quả hiện tại

- `events.jsonl` có đúng 3 event với flags lần lượt `SYN`, `SYN+ACK`, `ACK`.
- Các packet không có payload và application là UNKNOWN như mong đợi ở bước parser.
- `result.txt` ghi xử lý đủ 3 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
