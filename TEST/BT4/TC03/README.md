# TC03 - Missing or Invalid Fields

## Mục tiêu

Kiểm tra input sai được reject có reason, không crash và không ảnh hưởng event hợp lệ tiếp theo.

## Input/Scenario

- Fixture trong `validate.py`: 109 ca lỗi và 4 ca hợp lệ về null/biên/non-content evidence.
- Bao gồm thiếu field, SID/rev/port sai kiểu, IPv4 lỗi, timestamp âm/NaN/Infinity và evidence không nhất quán.
- Theo contract BT3, `flow_id` phải có key nhưng được null; priority/classtype được thiếu hoặc null.

## Cách chạy

Chạy từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT4/TC03/validate.py
```

## Kết quả mong đợi

Input sai trả `rejected`, alert = null, reason chỉ rõ field; input giữ nguyên và event hợp lệ sau đó vẫn tạo alert.

## Kết quả hiện tại

PASS: 113 kịch bản, 561 assertion, exit code 0; null được phép và biên port/timestamp xử lý đúng.

## Minh chứng

`validate.py`, `result.txt`.
