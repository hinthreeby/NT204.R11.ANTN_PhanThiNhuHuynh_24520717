# NT204.R11.ANTN - IDS/IPS Processing Pipeline
Repository bài tập môn **Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập (IDS/IPS)**.

```text
Packet Capture / JSONL Input
    ↓
Packet Parser
    ↓
Decoder
    ↓
Preprocessor
    ↓
Flow/Connection Tracker
    ↓
Core Engine (Rule Loader/Parser/Indexer → Matching → Evaluation)
    ↓
Detection Event Generator → JSONL Output
```

## Cấu trúc module

- `capture/`: đọc PCAP và live capture.
- `parsers/`: parser IPv4, TCP, UDP, HTTP, DNS và SMTP.
- `detectors/`: nhận diện application protocol dựa trên port và payload.
- `decoder/`: HTTP URL/form/HTML decoding, character decoding và SMTP/MIME decoding.
- `preprocessor/`: validation, normalization, xử lý missing/unsupported data và bổ sung preprocessing metadata.
- `flow/`: bidirectional Flow/Connection Tracker, stable `flow_id`, endpoint A/B, direction, active-flow table và TCP connection state tracking.
- `core_engine/`: nạp, parse, validate, index Snort rules; so khớp header/flow/packet/content; đánh giá nhiều rule và sinh Detection Event.
- `output/`: ghi JSON Lines cho normalized events và detections.
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

### Bật Core Engine (Bài tập 3)

```powershell
python main.py --pcap TEST/BaiTap1/http_get/input.pcap --output output/events.jsonl --enable-core-engine --rules TEST/BT3/T14_detection_event/sample.rules --detection-output output/detections.jsonl
```

Ví dụ sử dụng bộ Snort rules của testcase T14 tại `TEST/BT3/T14_detection_event/sample.rules`. Core Engine sử dụng normalized event và flow context để đánh giá các rule; một event có thể tạo nhiều Detection Event. Kết quả được ghi riêng trong `detections.jsonl`. Khi không bật `--enable-core-engine`, pipeline giữ cách chạy cũ.

## Kiểm thử

### Bài tập 2 (T01–T14)

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

### Bài tập 3 (T01–T14)

Các testcase Snort rule matching, Rule Evaluation và Detection Event nằm trong `TEST/BT3/`. Chạy từ thư mục gốc repository, ví dụ:

```powershell
python -B TEST/BT3/T13_multiple_rule_evaluation/validate.py
python -B TEST/BT3/T14_detection_event/validate.py
```

Lệnh chạy, input, expected result và minh chứng của từng testcase nằm trong README/result tương ứng.

## Sử dụng AI

- **Công cụ:** ChatGPT.
- **Mục đích:** Phân tích yêu cầu, tham khảo thiết kế, giải thích kỹ thuật, hỗ trợ triển khai/kiểm tra mã nguồn, xây dựng testcase, debugging
- **Phạm vi:** một số module xử lý packet/event (`capture/`, `parsers/`, `decoder/`, `preprocessor/`, `flow/`), Core Engine (`core_engine/`), tích hợp pipeline, testcase trong `TEST/` với sự hỗ trợ của AI.
