# Test T13 - Multiple Rule Evaluation

## Mục tiêu

Kiểm tra một event trả đầy đủ MATCH cho ít nhất hai rule theo PDF Bài 3, mục 7, T13.

## Input/Scenario

- `sample.rules`: bốn rule GET, /admin, secret trên port 80 và GET trên port 443.
- `input.jsonl`: TCP từ 192.0.2.10:53000 đến 198.51.100.20:80, payload `GET /admin` đúng 10 byte.
- Flow context là fixture theo schema hiện có; không kiểm chứng Flow Tracker hoặc suy diễn client/server.
- Script kiểm tra thêm GET /public, payload rỗng, port 443 và lặp lại event chính.

## Cách chạy

Chạy từ thư mục gốc repository, không dùng `-O`:

```powershell
python -B TEST/BT3/T13_multiple_rule_evaluation/validate.py
```

## Kết quả mong đợi

- Event chính chỉ MATCH SID 108301 và 108302; SID 108303/108304 không xuất hiện trong kết quả.
- Đúng rev, msg, field information và byte spans GET [0,3), /admin [4,10); không trùng kết quả.
- Đánh giá đủ candidate qua các module thật; counter mỗi event và tích lũy chính xác, input giữ nguyên.

## Kết quả hiện tại

**T13 PASS:** 5 kịch bản, 135 assertion, exit code 0; tổng 5 event, 13 candidate và 6 MATCH.
**Regression T01–T12 PASS:** exit code 0; minh chứng cũ giữ nguyên. Chưa sinh Detection Event.

## Minh chứng

`sample.rules`, `input.jsonl`, `validate.py`, `result.txt`.
