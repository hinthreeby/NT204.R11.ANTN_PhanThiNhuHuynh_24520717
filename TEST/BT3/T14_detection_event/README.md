# Test T14 - Detection Event

## Mục tiêu

Kiểm tra Detection Event đầy đủ theo PDF Bài 3, mục 4.6, 5 và T14.

## Input/Scenario

- `sample.rules`: sáu rule kiểm tra content, classification, sai port, flow-only, flags/dsize và positional content.
- `input.jsonl`: TCP 192.0.2.10:53000 → 198.51.100.20:80, HTTP, payload `GET /admin` đúng 10 byte.
- Test trực tiếp dùng flow fixture; CLI và kịch bản SYN lấy flow ID/context từ pipeline thật.
- Kiểm tra dữ liệu thiếu/malformed, flow ID mâu thuẫn và input không bị thay đổi.

## Cách chạy

Chạy từ thư mục gốc repository, không dùng `-O`; thêm `--write-output` để tạo lại riêng `result.jsonl` sau khi kiểm tra đạt:

```powershell
python -B TEST/BT3/T14_detection_event/validate.py
```

## Kết quả mong đợi

- Event chính sinh đúng hai detection SID 101401/101402; rule port 443 không sinh detection.
- Đúng giá trị/kiểu của rule, timestamp, 5-tuple, protocol, application protocol, flow ID và `match_information`.
- Giữ spans theo byte; optional không khai báo là null; JSONL chỉ chứa object JSON, normalized output không bị trộn detection.

## Kết quả hiện tại

**T14 PASS:** 19 kịch bản, 568 assertion, exit code 0; JSONL và tích hợp CLI/pipeline thật PASS.
**Regression T01–T13 PASS:** minh chứng cũ giữ nguyên; `result.jsonl` chứa hai detection thực tế từ CLI.

## Minh chứng

`sample.rules`, `input.jsonl`, `validate.py`, `result.jsonl`, `result.txt`.
