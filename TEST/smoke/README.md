# Test: IDS Pipeline Smoke Test

## Mục tiêu

Kiểm tra nhanh pipeline IDS có thể nhận một normalized event từ Packet Parser, đưa event qua các module xử lý tiếp theo và ghi kết quả ra JSONL mà không làm thay đổi hoặc làm mất dữ liệu cơ bản.

Pipeline được kiểm tra:

```text
Normalized Event
      ↓
Decoder
      ↓
Preprocessor
      ↓
Flow/Connection Tracker
      ↓
JSONL Output
```

## Input

`input.jsonl` chứa một TCP SYN event:

- Source: `192.168.1.10:50000`
- Destination: `192.168.1.20:80`
- Transport protocol: `TCP`
- Flag: `SYN`
- Application protocol: `UNKNOWN`
- Payload length: `0`

`invalid.jsonl` chứa dữ liệu không phải JSON:

```text
this-is-not-json
```

để dùng kiểm tra khả năng xử lý input lỗi.

## Cách chạy

Event hợp lệ:

```bash
python main.py --input TEST/smoke/input.jsonl --output TEST/smoke/events.jsonl
```

Có thể kiểm tra input lỗi riêng bằng:

```bash
python main.py --input TEST/smoke/invalid.jsonl --output TEST/smoke/invalid-events.jsonl
```

## Kết quả mong đợi

Với `input.jsonl`:

- Hệ thống xử lý được 1 event.
- Không có event bị skip.
- Event đi qua pipeline và được ghi ra JSONL.
- Các thông tin network/transport ban đầu vẫn được giữ.
- Vì application protocol là `UNKNOWN`, Decoder không cần biến đổi application data.

Với `invalid.jsonl`:

- Hệ thống phải nhận diện dòng JSON không hợp lệ.
- Không được làm toàn bộ chương trình crash.

## Kết quả thực tế

`result.txt` ghi nhận:

```text
[IDS] Processed events: 1
[IDS] Skipped events: 0
```

`events.jsonl` chứa đúng 1 event và giữ nguyên các dữ liệu chính:

- `network.protocol = "IPv4"`
- `src_ip = "192.168.1.10"`
- `dst_ip = "192.168.1.20"`
- `transport.protocol = "TCP"`
- `src_port = 50000`
- `dst_port = 80`
- `flags = ["SYN"]`
- `application.protocol = "UNKNOWN"`
- `decoder.status = "unchanged"`
- `errors = []`

## Trạng thái

**PASS**

Pipeline xử lý thành công một normalized event, không skip và tạo output JSONL đúng định dạng.

## Minh chứng

- `input.jsonl`: normalized TCP SYN event đầu vào.
- `invalid.jsonl`: input JSON không hợp lệ để kiểm tra robustness.
- `events.jsonl`: output sau khi đi qua pipeline.
- `result.txt`: log xác nhận `Processed events: 1`, `Skipped events: 0`.

## Kết luận

Smoke test PASS. Pipeline IDS hiện tại có thể nhận normalized event và đưa qua các module liên kết mà không làm mất dữ liệu cơ bản hoặc phát sinh lỗi với input hợp lệ.
