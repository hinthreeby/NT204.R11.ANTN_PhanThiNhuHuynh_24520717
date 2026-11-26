# TC09 - Repository Persistence

## Mục tiêu

Kiểm tra lưu và đọc lại Alert không mất trường bắt buộc.

## Input/Scenario

- Fixture trong `validate.py`; dùng SQLite thật trong thư mục tạm ngoài repository, đối chiếu đủ 19 field của Alert.
- Thử nhiều Alert, Unicode, nullable fields, metadata lồng nhau, close/reopen và đọc bằng Python process mới.
- Kiểm tra aggregation update/finalized groups, duplicate ID, invalid path, lỗi ghi bằng SQLite trigger, rollback và input immutability.

## Cách chạy

Từ repository root:

```powershell
python -B TEST/BT4/TC09/validate.py
```

## Kết quả mong đợi

Đọc lại đúng ID, giá trị/kiểu dữ liệu, timestamp, count và evidence, kể cả sau reopen. Duplicate ID không ghi đè; lỗi transaction rollback toàn bộ. Input không đổi và finalized summaries vẫn tồn tại sau lưu trữ.

## Kết quả hiện tại

PASS: 24 kịch bản, 4.694 assertion, exit code 0; dữ liệu được giữ sau restart và rollback không để lại thay đổi dở dang.

## Minh chứng

`validate.py`, `result.txt`.
