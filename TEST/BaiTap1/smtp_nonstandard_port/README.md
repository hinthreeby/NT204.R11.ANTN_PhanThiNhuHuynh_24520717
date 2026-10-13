# Test - SMTP trên Non-standard Port

## Mục tiêu

Kiểm tra detector nhận diện SMTP dựa trên payload khi traffic đi qua port không chuẩn.

## Input/Scenario

`input.pcap` có SMTP command/response qua port 2525.

## Cách chạy

```powershell
python main.py --pcap TEST\smtp_nonstandard_port\input.pcap --output TEST\smtp_nonstandard_port\events.jsonl
```

## Kết quả mong đợi

- Nhận diện SMTP trên port 2525.
- Command và response đều được parse đúng.

## Kết quả hiện tại

- `events.jsonl` có 2 event SMTP trên port 2525: `EHLO client.example.com` và response `250 OK`.
- `result.txt` ghi xử lý đủ 2 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
