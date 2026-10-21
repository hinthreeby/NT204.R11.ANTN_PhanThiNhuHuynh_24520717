# Test T02 - Invalid Rule Syntax

## Mục tiêu

Kiểm tra rule sai cú pháp được đánh dấu invalid, có lý do và không làm dừng xử lý các rule tiếp theo (PDF Bài 3, mục 7, T02).

## Input/Scenario

- `invalid.rules`: 13 rule, gồm 9 invalid nằm giữa 2 rule hợp lệ và 2 trường hợp đối chứng unsupported.
- Lỗi gồm thiếu header/ngoặc options, protocol sai cú pháp, port vượt giới hạn, IPv4 sai, SID/rev lỗi và quoted string chưa đóng.
- Protocol `t@cp` là invalid; `icmp` và keyword `pcre` ngoài phạm vi là unsupported.

## Cách chạy

Chạy từ thư mục gốc repository, không dùng `-O`:

```powershell
python -B TEST/BT3/T02_invalid_rule/validate.py
python -B TEST/BT3/T01_rule_loader/validate.py
```

## Kết quả mong đợi

- Đúng 9 invalid có reason cụ thể, không được đưa vào tập rule hợp lệ; 2 đối chứng giữ status unsupported.
- Hai rule SID 200001 và 200014 vẫn được chấp nhận, không có unhandled exception.
- Giữ chính xác filename, line number và nội dung input; T01 regression vẫn PASS.

## Kết quả hiện tại

**T02 PASS:** đủ 13 trường hợp đúng expected status/reason, exit code 0; chạy từ thư mục tạm cũng cho cùng kết quả.
**T01 regression PASS:** cả 6 nhóm assertion, exit code 0; output được lưu trong `result.txt` của T02.

## Minh chứng

`invalid.rules`, `validate.py`, `result.txt`.
