# TC11 - Severity Statistics

## Mục tiêu

Kiểm tra số Alert Object, tổng Detection Events sau aggregation và thống kê severity từ Repository.

## Input/Scenario

- Fixture trong `validate.py`: 8 Alert, tổng count=19, đủ CRITICAL/HIGH/MEDIUM/LOW; dùng SQLite tạm ngoài repository.
- Kiểm tra aggregation thật rồi insert/update, dữ liệu rỗng, time range/boundary, Alert cùng SID/IP và tổng count lớn.
- Kiểm tra sau reopen và xác nhận report không thay đổi dữ liệu, metadata hoặc nội dung database.

## Cách chạy

Từ repository root:

```powershell
python -B TEST/BT4/TC11/validate.py
```

## Kết quả mong đợi

Total alerts=8, total count=19. Severity theo `(số Alert, tổng count)`: CRITICAL=(2,4), HIGH=(3,11), MEDIUM=(2,3), LOW=(1,1). Query dùng opening `timestamp` UTC trong khoảng `[from_time, to_time)`, không dùng `last_seen`. Dữ liệu rỗng trả tổng bằng 0 và đủ bốn severity bằng 0.

## Kết quả hiện tại

PASS: 17 kịch bản, 86 assertion, exit code 0. Runner ghi thời điểm chạy, kết quả từng scenario và lỗi thực tế vào `result.txt`.

## Minh chứng

`validate.py`, `result.txt`.
