# Test T09 - Content and Nocase Matching

## Mục tiêu

Kiểm tra content phân biệt hoa/thường và nocase theo PDF Bài 3, mục 7, T09.

## Input/Scenario

- `sample.rules`: 8 rule valid, gồm 5 rule theo yêu cầu và các đối chứng mixed hex, escape, chồng lấn.
- `validate.py` chứa 34 normalized TCP event fixture theo schema Bài 1–2, có raw hex và byte length.
- Payload gồm admin/ADMIN/AdMiN, GET/get, binary 0x00/0xFF, empty, UTF-8 và dữ liệu thiếu/malformed.

## Cách chạy

Chạy từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT3/T09_content_matching/validate.py
```

## Kết quả mong đợi

- Parser trả valid, compiler tạo đúng bytes; content mặc định phân biệt hoa/thường, nocase chỉ fold ASCII cho content tương ứng.
- Nhiều content kết hợp AND, không áp đặt thứ tự xuất hiện; giữ mọi occurrence kể cả chồng lấn.
- Offsets theo byte, end-exclusive; option_index và matched_hex đúng payload gốc; thiếu/lỗi raw hex không false MATCH.
- Không dùng decoded body hoặc tự URL-decode để thay thế raw payload; input giữ nguyên.

## Kết quả hiện tại

**T09 PASS:** 34 kịch bản, 68 assertion trạng thái và 34 assertion offsets; 17 MATCH/17 NO_MATCH, exit code 0.
**Regression T01–T08 và T12 PASS:** output khớp minh chứng cũ; chạy T09 từ thư mục tạm cũng PASS.
Chỉ xác nhận content conditions, chưa phải toàn bộ Snort rule; chưa tích hợp positional/Evaluation Engine.

## Minh chứng

`sample.rules`, `validate.py`, `result.txt`.
