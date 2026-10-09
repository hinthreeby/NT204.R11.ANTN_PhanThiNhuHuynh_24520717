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
- `flow/`: Flow/Connection Tracker; sẽ tiếp tục được hoàn thiện ở các bước sau.
- `output/`: ghi JSON Lines.
- `TEST/`: input, output, script và báo cáo ngắn của từng testcase.

## Cài đặt

```powershell
python -m pip install -r requirements.txt
```

## Cách chạy

### Đọc PCAP

```powershell
python main.py --pcap TEST\tcp_handshake\input.pcap --output output\events.jsonl
```

### Live Capture

```powershell
python main.py --interface "<interface>" --output output\events.jsonl
```

### Xử lý normalized event từ JSONL

```powershell
python main.py --input TEST\T01_http_url_decode\input.jsonl --output output\events.jsonl
```

`main.py` khởi tạo `IDSPipeline`; raw packet được parse trước khi tiếp tục qua Decoder → Preprocessor → Flow Tracker. Các testcase dùng JSONL có thể đưa normalized event trực tiếp vào phần sau của pipeline để kiểm thử module độc lập.

## Sử dụng AI

- **Công cụ:** ChatGPT.
- **Mục đích:** hỗ trợ phân tích yêu cầu, tham khảo hướng triển khai, giải thích kỹ thuật, kiểm tra lỗi và xây dựng testcase/tài liệu.
- **Phạm vi:** một số phần trong quá trình thiết kế kiến trúc module, xử lý packet/event, decoder, kiểm thử, debugging và tài liệu được thực hiện với sự hỗ trợ tham khảo từ AI.
