# Test T01 - Rule Loader

## Mục tiêu

Kiểm tra Loader lọc comment/dòng trống và chuyển rule sang Validator, theo PDF Bài 3, trang 3, mục 7, T01.

## Input/Scenario

- `sample.rules`: 3 rule hợp lệ, comment và dòng trống; có khoảng trắng đầu dòng, dấu `#` và `;` trong `msg`.
- `additional.rules`: 2 rule hợp lệ, xen giữa là 1 rule có SID sai kiểu.

## Cách chạy

Chạy từ thư mục gốc repository, không dùng `-O`:

```powershell
python -B TEST/BT3/T01_rule_loader/validate.py
```

## Kết quả mong đợi

- Bỏ comment/dòng trống, giữ nguyên nội dung, thứ tự, filename và line number của rule.
- Hai file cho 6 candidate: Validator chấp nhận 5 rule, từ chối 1 rule lỗi có lý do và tiếp tục xử lý.
- Bật/tắt file và SID đúng cấu hình; tắt SID 100002 còn 4 rule được chấp nhận sau validation.

## Kết quả hiện tại

Theo `result.txt`: **PASS**, 6 nhóm assertion, exit code 0 (Python 3.10.5, Windows).
Chạy từ thư mục tạm ngoài repository cũng cho cùng kết quả; script không tự ghi đè `result.txt`.

## Minh chứng

`sample.rules`, `additional.rules`, `validate.py`, `result.txt`.
