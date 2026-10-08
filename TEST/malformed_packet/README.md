# Test - Malformed Packet

## Mục tiêu

Kiểm tra parser không crash khi nhận UDP payload malformed/không đủ dữ liệu để parse application protocol.

## Input/Scenario

`input.pcap` được tạo bởi `generate.py`, chứa UDP packet tới port 53 với payload không hợp lệ.

## Cách chạy

```powershell
python main.py --pcap TEST\malformed_packet\input.pcap --output TEST\malformed_packet\events.jsonl
```

## Kết quả mong đợi

- Chương trình tiếp tục chạy, không uncaught exception.
- Application được đánh dấu UNKNOWN nếu không thể nhận diện an toàn.

## Kết quả hiện tại

- `events.jsonl` có 1 UDP event; transport được parse bình thường và application là `UNKNOWN`.
- Không có uncaught traceback trong `result.txt`; chương trình ghi đã xử lý 1 packet.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
