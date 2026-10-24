# Test T07 - Header Filtering

## Mục tiêu

Kiểm tra rule sai header bị loại trước bước xử lý content (PDF Bài 3, mục 7, T07).

## Input/Scenario

- `sample.rules`: 4 rule valid TCP/UDP, exact/CIDR/range và `->`/`<>`, đều có `content:"admin"`.
- 29 kịch bản trong `validate.py`; payload luôn chứa `admin`, kể cả khi header sai hoặc thiếu field.
- Spy trong test chỉ ghi nhận rule được chuyển tiếp sau Header Filtering, không đánh giá content.

## Cách chạy

Chạy từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT3/T07_header_filtering/validate.py
```

## Kết quả mong đợi

- Tập SID sau filtering đúng expected và baseline Header Matcher, không trùng hoặc có false positive.
- Sai protocol/IP/port/CIDR/range/direction hoặc thiếu field: rule bị loại, không được gọi spy.
- Header hợp lệ được chuyển tiếp; `<>` đảo đồng thời IP và port đúng, input giữ nguyên.

## Kết quả hiện tại

**T07 PASS ở cấp Header Filtering:** 29 kịch bản; 20 kịch bản bị loại có 0 lần gọi spy; exit code 0.
**Regression T01–T06 PASS:** exit code 0, minh chứng cũ giữ nguyên; chạy T07 từ thư mục tạm cũng PASS.
Chưa kiểm chứng end-to-end với Content Matcher/Evaluation Engine vì các thành phần này chưa triển khai.

## Minh chứng

`sample.rules`, `validate.py`, `result.txt`.
