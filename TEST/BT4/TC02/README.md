# TC02 - Priority to Severity

## Mục tiêu

Kiểm tra severity theo cấu hình tập trung và chính sách priority thiếu/sai.

## Input/Scenario

- Detection fixture nằm trong `validate.py`; dùng Alert Manager thật.
- Thử priority 1–5, 999, missing/null, cấu hình riêng và dữ liệu/config sai.
- Mapping mặc định là lựa chọn project: 1 CRITICAL, 2 HIGH, 3 MEDIUM, >=4 LOW.

## Cách chạy

Chạy từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT4/TC02/validate.py
```

## Kết quả mong đợi

Missing/null dùng MEDIUM; priority sai bị reject. Mapping/fallback tùy chỉnh có hiệu lực và không bị sửa qua dictionary nguồn.

## Kết quả hiện tại

PASS: 30 kịch bản, 70 assertion, exit code 0; không tự tạo priority thay cho giá trị thiếu.

## Minh chứng

`validate.py`, `result.txt`.
