# TC10 - Alert Repository Query

## Mục tiêu

Kiểm tra truy vấn đúng theo thời gian và các tiêu chí severity, SID, source/destination IP.

## Input/Scenario

- Fixture trong `validate.py`: 10 Alert, tổng count=13, nhiều timestamp/severity/SID/IP và nullable fields; dùng SQLite tạm ngoài repository.
- Thử filter đơn/kết hợp AND, boundary, empty result, invalid input, SQL injection, IPv4/IPv6 và deterministic ordering.
- Kiểm tra query sau reopen, nhóm aggregated/finalized, kết quả lặp và database không đổi qua snapshot SQL, SHA-256, data_version.

## Cách chạy

Từ repository root:

```powershell
python -B TEST/BT4/TC10/validate.py
```

## Kết quả mong đợi

Trả đúng IDs và số bản ghi; filter kết hợp AND. Time query dùng `alerts.timestamp` trong khoảng `[from_time, to_time)`, sắp theo timestamp rồi alert_id tăng dần. Không có dữ liệu trả []; input sai hoặc IPv6 báo lỗi rõ, database không bị thay đổi.

## Kết quả hiện tại

PASS: 35 kịch bản, 14.609 assertion, exit code 0; exact IDs, ordering và tính chỉ đọc của query được xác nhận.

## Minh chứng

`validate.py`, `result.txt`.
