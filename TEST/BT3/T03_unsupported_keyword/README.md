# Test T03 - Unsupported Keyword

## Mục tiêu

Kiểm tra keyword ngoài phạm vi được đánh dấu unsupported, có lý do và không dừng xử lý (PDF Bài 3, mục 3, 4.2 và T03).

## Input/Scenario

- `unsupported.rules`: 13 rule, gồm 5 unsupported, 4 valid và 4 đối chứng invalid.
- Thử `pcre`, `byte_test`, `byte_jump`, `future_keyword`; có rule trộn nhiều keyword và tên keyword nằm trong quoted content.
- Rule đối chứng valid dùng đủ keyword bắt buộc, gồm content/nocase; không thực hiện matching.

## Cách chạy

Chạy từ repository root bằng `python -B`, không dùng `-O`:

```powershell
python -B TEST/BT3/T03_unsupported_keyword/validate.py
python -B TEST/BT3/T01_rule_loader/validate.py
python -B TEST/BT3/T02_invalid_rule/validate.py
```

## Kết quả mong đợi

- Unsupported có reason nêu đúng các keyword lạ, không được đưa vào tập rule valid của testcase; rule valid tiếp theo vẫn được chấp nhận.
- Không nhầm tên keyword trong quoted content; keyword bắt buộc vẫn valid dù chưa triển khai matching.
- Trong đối chứng cùng có `pcre` và SID/quote/rev lỗi: ưu tiên invalid, kể cả khi đổi thứ tự SID và `pcre`.

## Kết quả hiện tại

**T03 PASS:** 13 trường hợp đúng status/reason, exit code 0; chạy từ thư mục tạm cũng cho cùng kết quả.
**Regression PASS:** T01 (6 nhóm assertion), T02 (13 trường hợp), cùng exit code 0; chi tiết lưu trong `result.txt` của T03.

## Minh chứng

`unsupported.rules`, `validate.py`, `result.txt`.
