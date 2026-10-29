# Test T11 - Relative Content Matching

## Mục tiêu

Kiểm tra distance/within và chuỗi content hợp lệ theo PDF Bài 3, mục 7, T11.

## Input/Scenario

- `sample.rules`: 21 rule valid, gồm distance, within, tổ hợp hai modifier, nocase, binary và đối chứng không relative.
- `validate.py` chứa 39 normalized TCP event fixture với expected spans xác định trước.
- Có occurrence thay thế, ba content, nhánh không tương thích, distance âm, empty và payload thiếu/malformed.

## Cách chạy

Chạy từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT3/T11_distance_within/validate.py
```

## Kết quả mong đợi

- Start = previous_end + distance (mặc định 0); có within thì end = start + within, cắt theo buffer; [tham chiếu Snort](https://docs.snort.org/rules/options/payload/oddw).
- Toàn bộ pattern nằm trong window, end-exclusive; theo chính sách project, within ngắn hơn pattern vẫn valid về cú pháp nhưng NO_MATCH.
- Xét occurrence thay thế, chỉ giữ chuỗi thành công; không ghép nhánh sai, không rò cursor giữa event, input giữ nguyên.

## Kết quả hiện tại

**T11 PASS:** 39 kịch bản, 78 assertion trạng thái, 39 assertion span; 21 MATCH/18 NO_MATCH, exit code 0.
**Regression T09/T10, T01–T08 và T12 PASS:** output khớp minh chứng cũ; chạy T11 từ thư mục tạm cũng PASS.
Chỉ xác nhận content conditions; chưa tích hợp Evaluation Engine hoặc Detection Event.

## Minh chứng

`sample.rules`, `validate.py`, `result.txt`.
