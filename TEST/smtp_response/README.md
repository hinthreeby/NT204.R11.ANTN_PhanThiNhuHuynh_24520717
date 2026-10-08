# Test - SMTP Response

## Mục tiêu

Kiểm tra parser trích xuất SMTP response status code và message.

## Input/Scenario

`input.pcap` chứa response SMTP từ port 25.

## Cách chạy

```powershell
python main.py --pcap TEST\smtp_response\input.pcap --output TEST\smtp_response\events.jsonl
```

## Kết quả mong đợi

- Nhận diện SMTP response.
- Parse được status code và message.

## Kết quả hiện tại

- `events.jsonl` có SMTP response `status_code = 250`, message `OK`.
- `result.txt` ghi xử lý 1 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
