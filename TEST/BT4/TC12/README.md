# TC12 - Top SID/IP Statistics

## Mục tiêu

Kiểm tra Top-N SID, classtype, source IP và destination IP từ Repository.

## Input/Scenario

- Fixture trong `validate.py`: 8 Alert, tổng count=21, nhiều SID/IP/classtype; có Unicode, null và chuỗi "null" riêng biệt; dùng SQLite tạm ngoài repository.
- Kiểm tra exact rankings/counts, tie-breaking, top_n=1/3/100, invalid top_n, count sau aggregation thật, empty data và time range/boundary.
- Kiểm tra thứ tự insert, reopen, kết quả lặp và report/formatter không thay đổi thống kê hoặc database.

## Cách chạy

Từ repository root:

```powershell
python -B TEST/BT4/TC12/validate.py
```

## Kết quả mong đợi

Ranking theo tổng count giảm dần; bằng điểm thì SID tăng theo số, IP/classtype tăng theo chuỗi, null đứng trước chuỗi. Fixture đầy đủ có SID đứng đầu là 10 (2 Alert, count=6); classtype "z", source 192.0.2.2 và destination 198.51.100.2 cùng đứng đầu với 3 Alert, count=7. Time range dùng opening `timestamp` UTC, `[from_time, to_time)`. Empty data trả ranking rỗng; top_n không làm thay đổi tổng số liệu.

## Kết quả hiện tại

PASS: 18 kịch bản, 110 assertion, exit code 0. Runner ghi thời điểm chạy, kết quả từng scenario và lỗi thực tế vào `result.txt`.

## Minh chứng

`validate.py`, `result.txt`.
