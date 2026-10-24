# Test T06 - Rule Indexer

## Mục tiêu

Kiểm tra tập candidate và Header Filtering theo PDF Bài 3, mục 4.3 và mục 7, T06.

## Input/Scenario

- `sample.rules`: 11 rule, gồm 8 active, 1 valid bị tắt theo SID, 1 invalid và 1 unsupported.
- Protocol TCP/UDP; IP exact/CIDR/any, port single/range/any, direction `->` và `<>`.
- 26 event fixture trong `validate.py`, gồm hai chiều, biên range, sai endpoint và dữ liệu thiếu/sai.
- Hiểu IP/any trong T06 là selector; không mở rộng protocol `ip`/`any` ngoài mục 3 của đề.

## Cách chạy

Chạy từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT3/T06_rule_indexer/validate.py
```

## Kết quả mong đợi

- Tập SID candidate đúng theo index protocol/port đơn; port any/range được giữ để kiểm tra header sau.
- Tập SID header-matched đúng expected và baseline Header Matcher trên toàn bộ active rules; không có false negative.
- Không trùng SID hoặc nhận rule inactive; đảo thứ tự input không đổi tập kết quả, tập active rỗng xử lý an toàn.

## Kết quả hiện tại

**T06 PASS:** 26 kịch bản, 52 assertion tập SID và 26 đối chiếu baseline; exit code 0, chạy từ thư mục tạm cũng PASS.
**Regression T01–T05 PASS:** exit code 0, output khớp minh chứng cũ; log lưu trong `result.txt` của T06.

## Minh chứng

`sample.rules`, `validate.py`, `result.txt`.
