# Test T08 - Flow/Connection State Matching

## Mục tiêu

Kiểm tra `flow:to_server,established` và các flow term bắt buộc (PDF Bài 3, mục 3, 4.4 và T08).

## Input/Scenario

- `sample.rules`: 8 rule valid, gồm A/B/C theo yêu cầu, chiều to_client/not_established và các term đơn.
- `input.jsonl`: SYN → SYN/ACK → ACK → data hai chiều; client `192.168.1.10:50000`, server `192.168.1.20:80`.
- Input không gắn vai trò; pipeline/Flow Tracker thật cấp context, adapter suy ra client từ SYN thuần đã quan sát.
- Thêm context thiếu/malformed/UNKNOWN, capture từ SYN/ACK và giữa phiên; unit check các trạng thái kết thúc.

## Cách chạy

Chạy từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT3/T08_flow_matching/validate.py
```

## Kết quả mong đợi

- A match data client → server đã ESTABLISHED; B match chiều ngược; C match SYN HANDSHAKE hướng server.
- Thiếu bằng chứng vai trò không match direction; thiếu state không tự trở thành not_established; flow ID/endpoints ổn định.
- Chính sách kỹ thuật: ESTABLISHED match established; NEW/HANDSHAKE match not_established; CLOSING/CLOSED/RESET không match cả hai.

## Kết quả hiện tại

**T08 PASS:** 29 kịch bản, 232 assertion MATCH/NO_MATCH, exit code 0; chạy từ thư mục tạm cũng PASS.
**Regression T01–T07 PASS:** output khớp minh chứng cũ; log lưu trong `result.txt` của T08.
Đã kiểm chứng tích hợp pipeline/Tracker → adapter → FlowMatcher; chưa tích hợp Evaluation Engine vào production pipeline.

## Minh chứng

`sample.rules`, `input.jsonl`, `validate.py`, `result.txt`.
