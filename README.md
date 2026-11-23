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

### Bài tập 4 - Ngày 1: Alert Manager & Severity

`alert/` nhận dictionary Detection Event từ BT3, validate rồi tạo `Alert` có UUID4.
Module độc lập với Core Engine; không thay đổi CLI hoặc output BT1–BT3.

```python
from alert import AlertManager, SeverityConfig

manager = AlertManager(SeverityConfig())
result = manager.process(detection_event)
if result.status == "created":
    record = result.alert.to_dict()
else:
    print(result.reason)
```

- Input theo contract dictionary BT3: timestamp, sid, rev, msg, src/dst IP/port, protocol, application_protocol, flow_id và match_information.
- Timestamp là số giây hữu hạn không âm; SID/rev/port phải là integer, không nhận Boolean hoặc port thập phân. IP hỗ trợ IPv4; protocol TCP/UDP, application HTTP/DNS/SMTP/UNKNOWN.
- `flow_id` được null và giữ nguyên giá trị nguồn; priority/classtype được thiếu hoặc null. Thiếu dữ liệu bắt buộc trả `AlertResult(status="rejected", alert=None, reason=...)`; không thay bằng thông tin giả.
- Alert giữ rev, priority/classtype và match evidence; `msg` được chuẩn hóa thành `message`, timestamp thành float, protocol viết hoa và bỏ khoảng trắng thừa ở message/IP. `to_dict()` trả bản sao JSON-compatible.
- Severity là chính sách project, không phải mapping bắt buộc của PDF: 1→CRITICAL, 2→HIGH, 3→MEDIUM, >=4→LOW; missing/null→MEDIUM. `SeverityConfig(priority_mapping=..., missing_severity=..., unmapped_severity=...)` cho phép thay đổi; priority sai bị reject.
- Mỗi event hợp lệ tạo một Alert riêng; `first_seen = last_seen = timestamp`, `count = 1`. Ngày 1 chưa thực hiện filtering, aggregation, storage hoặc report.

Hook tích hợp đã có: `IDSPipeline(config, detection_sink=callback)` gọi callback với dictionary Detection Event. Callback có thể gọi `manager.process(detection)` rồi nhận kết quả; TC01 kiểm chứng đường này bằng implementation thật. Chưa bật Alert Module tự động trong CLI.

Chạy các testcase độc lập từ repository root:

```powershell
python -B TEST/BT4/TC01/validate.py
python -B TEST/BT4/TC02/validate.py
python -B TEST/BT4/TC03/validate.py
```

Expected result và output thực chạy nằm trong README/result.txt của từng thư mục `TEST/BT4/`.

## Sử dụng AI

- **Công cụ:** ChatGPT.
- **Mục đích:** Phân tích yêu cầu, tham khảo thiết kế, giải thích kỹ thuật, hỗ trợ triển khai/kiểm tra mã nguồn, xây dựng testcase, debugging
- **Phạm vi:** một số module xử lý packet/event (`capture/`, `parsers/`, `decoder/`, `preprocessor/`, `flow/`), Core Engine (`core_engine/`), tích hợp pipeline, testcase trong `TEST/` với sự hỗ trợ của AI.
- **BT4 Ngày 1:** ChatGPT/Codex hỗ trợ thiết kế và triển khai `alert/` (model, validation, UUID, severity, manager), xây dựng `TEST/BT4/TC01–TC03`, kiểm tra regression và cập nhật hướng dẫn này. Sinh viên cần đọc hiểu và giải thích các quyết định validation/severity.
