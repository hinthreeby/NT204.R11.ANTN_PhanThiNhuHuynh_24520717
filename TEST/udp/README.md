# Test - UDP Packet

## Mục tiêu

Kiểm tra UDP parser trích xuất đúng thông tin transport và payload length.

## Input/Scenario

`input.pcap` chứa UDP packet từ port 50000 tới 9999 với payload `Hello from UDP`.

## Cách chạy

```powershell
python main.py --pcap TEST\udp\input.pcap --output TEST\udp\events.jsonl
```

## Kết quả mong đợi

- Nhận diện UDP.
- Parse đúng source/destination port, length và payload length.

## Kết quả hiện tại

- `events.jsonl` có 1 UDP event từ 50000 tới 9999.
- `payload_length = 14`; application là UNKNOWN và không bị nhận nhầm là DNS.
- `result.txt` ghi xử lý 1 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
