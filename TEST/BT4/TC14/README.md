# TC14 - Report Output

## Mục tiêu

Kiểm tra report text/console/file và JSON đầy đủ, nhất quán với dữ liệu đã lưu trong Repository.

## Input/Scenario

- Fixture trong `validate.py`: 4 Alert, tổng count=11, đủ severity, nhiều SID/IP/protocol, classtype Unicode chứa dấu nháy/newline và nullable fields; dùng SQLite tạm ngoài repository.
- Kiểm tra tiêu đề, period, totals, severity, SID/classtype, Top IP, protocol, bucket giờ/phút, empty report và JSON parseable.
- Đối chiếu riêng từng section text/JSON với expected values; cập nhật record thật để xác nhận output thay đổi theo dữ liệu.
- Kiểm tra console, file UTF-8 trong thư mục tạm, lỗi ghi file, reopen, input immutability và không tự sinh report artifacts.

## Cách chạy

Từ repository root:

```powershell
python -B TEST/BT4/TC14/validate.py
```

## Kết quả mong đợi

Text có tiêu đề `IDS SECURITY REPORT`; total alerts=4, total count=11 và các section thống kê đầy đủ. JSON giữ đủ thống kê, Unicode, kiểu SID và null; số liệu trùng text. Period dùng UTC Unix seconds, text có thêm ISO 8601; query `[from_time, to_time)`. Cập nhật dữ liệu làm thay đổi output, report rỗng vẫn hợp lệ. Chỉ ghi file khi truyền output path cụ thể.

## Kết quả hiện tại

PASS: 22 kịch bản, 186 assertion, exit code 0. Runner chỉ giữ `result.txt` trong repository; database và report files tạm được dọn sau từng scenario.

## Minh chứng

`validate.py`, `result.txt`.
