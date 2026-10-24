# Test T04 - Rule Header Parsing

## Mục tiêu

Kiểm tra header được chuyển đúng thành Internal Rule Object theo PDF Bài 3, trang 4, mục 7, T04.

## Input/Scenario

- `sample.rules`: 7 TCP và 1 UDP hợp lệ; bao gồm IPv4/any/CIDR, port any/single/range, `->` và `<>`.
- Có biên port 0/65535, CIDR /0 và /32; thêm 5 header invalid về IPv4, CIDR, port, range đảo và direction.

## Cách chạy

Chạy từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT3/T04_rule_header/validate.py
```

## Kết quả mong đợi

- Cả 8 rule valid khớp chính xác giá trị/kiểu của 7 field header và `sid`, `rev`, `msg`.
- Selector IP/port giữ dạng string như input, kể cả CIDR có host bits; `sid`/`rev` là integer.
- Cả 5 header sai trả invalid, có reason cụ thể và không tạo Internal Rule Object hợp lệ; nguồn và input giữ nguyên.

## Kết quả hiện tại

**T04 PASS:** 13 trường hợp, 80 assertion field, exit code 0; chạy từ thư mục tạm cũng cho cùng kết quả.
**Regression T01–T03 PASS:** cùng exit code 0, output khớp minh chứng cũ; log lưu trong `result.txt` của T04.

## Minh chứng

`sample.rules`, `validate.py`, `result.txt`.
