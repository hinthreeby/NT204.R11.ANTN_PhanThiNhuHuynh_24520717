# Test - SMTP Command

## Mục tiêu

Kiểm tra parser nhận diện và trích xuất các SMTP command bắt buộc.

## Input/Scenario

`input.pcap` có 3 SMTP command trên TCP port 25.

## Cách chạy

```powershell
python main.py --pcap TEST\smtp_command\input.pcap --output TEST\smtp_command\events.jsonl
```

## Kết quả mong đợi

- Nhận diện SMTP command.
- Parse được EHLO và ít nhất MAIL FROM hoặc RCPT TO.

## Kết quả hiện tại

- `events.jsonl` có 3 SMTP command: `EHLO client.example.com`, `MAIL FROM <alice@example.com>`, `RCPT TO <bob@example.com>`.
- `result.txt` ghi xử lý đủ 3 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
