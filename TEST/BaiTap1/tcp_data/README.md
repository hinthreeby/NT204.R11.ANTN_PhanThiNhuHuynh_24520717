# Test - TCP Data Payload

## Mục tiêu

Kiểm tra TCP parser xử lý packet có payload và thống kê đúng độ dài payload.

## Input/Scenario

`input.pcap` chứa TCP PSH/ACK với payload `Hello from TCP`.

## Cách chạy

```powershell
python main.py --pcap TEST\tcp_data\input.pcap --output TEST\tcp_data\events.jsonl
```

## Kết quả mong đợi

- Nhận diện transport TCP.
- Flags và `payload_length` được parse đúng.

## Kết quả hiện tại

- `events.jsonl` có 1 TCP packet với flags `PSH, ACK`.
- `payload_length = 14`; application là UNKNOWN vì payload không phải HTTP/DNS/SMTP.
- `result.txt` ghi xử lý 1 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
