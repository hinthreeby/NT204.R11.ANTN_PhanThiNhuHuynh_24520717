# TC06 - Independent Alerts

## Mục tiêu

Kiểm tra các event được phép tạo Alert riêng, chưa aggregation.

## Input/Scenario

- Bảy cặp event: khác SID/IP/time/rev/flow/evidence hoặc giống hệt nhưng vẫn độc lập.
- Luồng 100 event xen kẽ created/filtered/suppressed/rejected; kiểm tra ID, timestamp và match evidence.
- Kiểm tra thêm optional IPv4 exact/protocol allowlists; normalize trước so sánh, config snapshot độc lập.

## Cách chạy

Từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT4/TC06/validate.py
```

## Kết quả mong đợi

UUID4 khác nhau, count=1, first_seen=last_seen=timestamp nguồn; input/evidence độc lập. Allowlist None không giới hạn; tập rỗng chặn tất cả.

## Kết quả hiện tại

PASS: 130 kịch bản, 1.083 assertion, exit code 0; luồng 100 event tạo đúng 40 Alert và 40 UUID.

## Minh chứng

`validate.py`, `result.txt`.
