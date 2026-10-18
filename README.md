# NT204.R11.ANTN - IDS/IPS Processing Pipeline

Repository bài tập môn **Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập (IDS/IPS)**.

Project được tổ chức theo **các module liên kết trong cùng một hệ thống**, không tách thành thư mục Bài 1/Bài 2:

```text
Packet Capture
    ↓
Packet Parser
    ↓
Decoder
    ↓
Preprocessor
    ↓
Flow/Connection Tracker
    ↓
Feature Extractor / Detection Engine (các phần tiếp theo)
```

## Cấu trúc module

- `capture/`: đọc PCAP và live capture.
- `parsers/`: parser IPv4, TCP, UDP, HTTP, DNS và SMTP.
- `detectors/`: nhận diện application protocol dựa trên port và payload.
- `decoder/`: HTTP URL/form/HTML decoding, character decoding và SMTP/MIME decoding.
- `preprocessor/`: validation, normalization, xử lý missing/unsupported data và bổ sung preprocessing metadata.
- `flow/`: bidirectional Flow/Connection Tracker, stable `flow_id`,
  endpoint A/B, direction, active-flow table và TCP connection state tracking.
- `output/`: ghi JSON Lines.
- `TEST/`: input, output, script và báo cáo ngắn của từng testcase.

## Cài đặt

```powershell
python -m pip install -r requirements.txt
```

## Cách chạy

Chạy các lệnh dưới đây từ thư mục gốc repository. Đường dẫn dùng dấu `/` tương thích Windows, Linux và macOS; dùng `python3` thay `python` nếu hệ thống yêu cầu.

### Đọc PCAP

```powershell
python main.py --pcap TEST/BaiTap1/tcp_handshake/input.pcap --output output/events.jsonl
```

### Live Capture

```powershell
python main.py --interface "<interface>" --output output/events.jsonl
```

### Xử lý normalized event từ JSONL

```powershell
python main.py --input TEST/BaiTap2/T01_http_url_decode/input.jsonl --output output/events.jsonl
```

`main.py` khởi tạo `IDSPipeline`; raw packet được parse trước khi tiếp tục qua Decoder → Preprocessor → Flow Tracker. Các testcase dùng JSONL có thể đưa normalized event trực tiếp vào phần sau của pipeline để kiểm thử module độc lập.

### Kiểm thử Bài tập 2 (T01–T14)

Với mỗi thư mục `TEST/BaiTap2/Txx_<ten_test>` có `input.jsonl`, chạy pipeline trước rồi chạy `validate.py` để kiểm tra output vừa sinh. Ví dụ T01:

```powershell
python main.py --input TEST/BaiTap2/T01_http_url_decode/input.jsonl --output TEST/BaiTap2/T01_http_url_decode/events.jsonl
python TEST/BaiTap2/T01_http_url_decode/validate.py
```

T04 tạo byte lỗi trực tiếp trong Python, chạy riêng:

```powershell
python -X utf8 -m TEST.BaiTap2.T04_invalid_bytes.test
```

Lệnh cụ thể và expected result của từng testcase nằm trong README tương ứng. Các validator xác định `events.jsonl` từ vị trí file script, nên không phụ thuộc thư mục làm việc. T04 cũng có thể chạy trực tiếp bằng đường dẫn tới `test.py` với `python -X utf8`.

## Sử dụng AI

- **Công cụ:** ChatGPT.
- **Mục đích:** hỗ trợ phân tích yêu cầu, tham khảo hướng triển khai, giải thích kỹ thuật, kiểm tra lỗi và xây dựng testcase/tài liệu.
- **Phạm vi:** một số phần trong quá trình thiết kế kiến trúc module, xử lý packet/event, decoder, kiểm thử, debugging và tài liệu được thực hiện với sự hỗ trợ tham khảo từ AI.
