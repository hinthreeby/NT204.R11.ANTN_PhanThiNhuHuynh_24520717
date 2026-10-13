# Test - Live Capture

## Mục tiêu

Kiểm tra chế độ bắt gói trực tiếp từ network interface và ghi event ra JSONL.

## Input/Scenario

Traffic được bắt trực tiếp từ interface; thư mục hiện lưu `events.jsonl` làm minh chứng.

## Cách chạy

```powershell
python main.py --interface "<interface>" --output TEST\live_capture\events.jsonl
```

## Kết quả mong đợi

- Bắt được IPv4 packet trực tiếp.
- Mỗi packet có timestamp và được xử lý qua pipeline chung.
- Output được ghi dạng JSONL.

## Kết quả hiện tại

- `events.jsonl` hiện có 204 event hợp lệ.
- Các event có timestamp, thông tin IPv4/TCP và được ghi theo từng dòng JSON.
- Nhiều packet là TCP/443 nên application protocol hiện là UNKNOWN, phù hợp vì bài không yêu cầu giải mã TLS.

**Trạng thái: PASS (theo events.jsonl)**

## Minh chứng hiện có

- `events.jsonl`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
