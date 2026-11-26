# TC04 - Severity Filtering

## Mục tiêu

Kiểm tra minimum severity sau mapping, trước khi tạo Alert.

## Input/Scenario

- Detection fixture trong `validate.py`; gọi Alert Manager và severity mapper thật.
- Thử đủ bốn severity với threshold None/LOW/MEDIUM/HIGH/CRITICAL, priority thiếu/null và custom mapping.
- Config sai báo lỗi rõ; UUID spy chỉ quan sát sinh ID, không giả kết quả filtering.

## Cách chạy

Từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT4/TC04/validate.py
```

## Kết quả mong đợi

Giữ severity bằng hoặc cao hơn threshold. None tắt lọc; event bị lọc trả `filtered`, alert=None, có reason và không tạo UUID.

## Kết quả hiện tại

PASS: 39 kịch bản, 194 assertion, exit code 0; source và mapping Ngày 1 giữ nguyên.

## Minh chứng

`validate.py`, `result.txt`.
