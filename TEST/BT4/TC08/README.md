# TC08 - Events Outside Aggregation Window

## Mục tiêu

Kiểm tra event ngoài cửa sổ tạo nhóm mới và nhóm cũ không bị mất.

## Input/Scenario

- Fixture trong `validate.py`; dùng Alert Manager thật, kiểm tra ngoài window, ngay sau boundary và đúng boundary.
- Thử nhiều window/key, out-of-order, event trước first_seen, custom window, flush và snapshot đã finalize.
- Kiểm tra policy không ảnh hưởng state; stress 3.000 event qua 1.500 nhóm.

## Cách chạy

Từ repository root:

```powershell
python -B TEST/BT4/TC08/validate.py
```

## Kết quả mong đợi

Ngoài fixed window tạo UUID mới, count=1, first_seen=last_seen=timestamp mới; đúng boundary vẫn gộp. Nhóm cũ được trả qua finalized/flush đúng một lần. Event muộn chỉ gộp vào nhóm còn mở phù hợp, nếu không trở thành singleton đã finalized; không mở lại nhóm đóng.

## Kết quả hiện tại

PASS: 20 kịch bản, 294.356 assertion, exit code 0; stress giữ đủ 3.000 event trong 1.500 nhóm.

## Minh chứng

`validate.py`, `result.txt`.
