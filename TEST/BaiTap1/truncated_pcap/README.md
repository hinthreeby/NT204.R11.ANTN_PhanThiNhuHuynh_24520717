# Test - Truncated PCAP

## Mục tiêu

Kiểm tra chương trình xử lý PCAP bị cắt/truncated mà không làm toàn bộ chương trình dừng bất thường.

## Input/Scenario

`valid.pcap` là mẫu gốc; `generate.py` tạo `input.pcap` bị truncate.

## Cách chạy

```powershell
python main.py --pcap TEST\truncated_pcap\input.pcap --output TEST\truncated_pcap\events.jsonl
```

## Kết quả mong đợi

- Không có uncaught traceback.
- Nếu vẫn đọc được phần dữ liệu hợp lệ thì xuất event tương ứng; dữ liệu bị cắt không được làm chương trình crash.

## Kết quả hiện tại

- `events.jsonl` hiện có 1 TCP/HTTP event được đọc từ phần dữ liệu còn lại.
- `result.txt` ghi chương trình xử lý 1 packet và kết thúc bình thường.
- HTTP version trong event bị cắt thành `HT`, cho thấy dữ liệu thực tế đã bị truncate nhưng parser vẫn không crash.

**Trạng thái: PASS**

## Minh chứng hiện có

- `generate.py`
- `valid.pcap`
- `input.pcap`
- `events.jsonl`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
