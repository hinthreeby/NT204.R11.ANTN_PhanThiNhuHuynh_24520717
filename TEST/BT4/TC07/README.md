# TC07 - Duplicate Events Within Window

## Mục tiêu

Kiểm tra event lặp trong cửa sổ được aggregate đúng key, count và thời gian.

## Input/Scenario

- Detection fixture trong `validate.py`; dùng Alert Manager và Aggregation Engine thật với key `(sid, src_ip, dst_ip)`.
- Thử event cùng/khác key, timestamp trùng/đúng boundary/out-of-order, custom window và aggregation disabled.
- Kiểm tra filtering/suppression/rejection, input/evidence độc lập và metadata từng event; stress 2.000 event trên 4 key.

## Cách chạy

Từ repository root:

```powershell
python -B TEST/BT4/TC07/validate.py
```

## Kết quả mong đợi

Cùng key trong window giữ UUID nhóm, tăng count, giữ first_seen và cập nhật last_seen lớn nhất. Boundary được gộp; khác key tạo nhóm riêng. Event bị chặn không aggregate; input và metadata được bảo toàn.

## Kết quả hiện tại

PASS: 20 kịch bản, 154.839 assertion, exit code 0; stress tạo 4 nhóm, mỗi nhóm count=500.

## Minh chứng

`validate.py`, `result.txt`.
