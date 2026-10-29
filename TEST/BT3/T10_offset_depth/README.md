# Test T10 - Offset/Depth Matching

## Mục tiêu

Kiểm tra content chỉ match trong vùng offset/depth theo PDF Bài 3, mục 7, T10.

## Input/Scenario

- `sample.rules`: 16 rule valid cho offset, depth, tổ hợp hai modifier, nocase, binary và đối chứng không modifier.
- `validate.py` chứa 29 normalized TCP event fixture, chủ yếu dùng payload `XXABCYYABC`.
- Có biên trái/phải, occurrence thứ hai, UTF-8, empty và raw payload thiếu/malformed; không tạo file PCAP.

## Cách chạy

Chạy từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT3/T10_offset_depth/validate.py
```

## Kết quả mong đợi

- Cửa sổ `[offset, min(payload_length, offset + depth))`; thiếu offset dùng 0, thiếu depth tìm đến cuối buffer.
- Pattern nằm trọn cửa sổ; offset bằng/vượt cuối buffer hoặc pattern vượt biên trả NO_MATCH. Depth ngắn hơn pattern vẫn valid nhưng không match.
- Byte spans end-exclusive đúng, giữ mọi occurrence hợp lệ; modifier chỉ áp dụng content tương ứng, raw bytes/input không đổi.

## Kết quả hiện tại

**T10 PASS:** 29 kịch bản, 58 assertion trạng thái, 29 assertion span; 14 MATCH/15 NO_MATCH, exit code 0.
**Regression T09, T01–T08 và T12 PASS:** output khớp minh chứng cũ; chạy T10 từ thư mục tạm cũng PASS.
Chỉ xác nhận absolute content windows; chưa có distance/within hoặc Evaluation Engine.

## Minh chứng

`sample.rules`, `validate.py`, `result.txt`.
