# TC01 - Valid Detection Event

## Mục tiêu

Kiểm tra Detection Event hợp lệ tạo Alert đúng field, UUID riêng và giữ nguyên input.

## Input/Scenario

- Dùng rules/input T14 BT3 qua pipeline, Flow Tracker và Detection Event Generator thật.
- Hai detection được nhận qua `detection_sink` và chuyển sang Alert Manager.
- Kiểm tra chuẩn hóa, match evidence, JSON serialization và 2.002 UUID không trùng.

## Cách chạy

Chạy từ repository root, không dùng `-O`:

```powershell
python -B TEST/BT4/TC01/validate.py
```

## Kết quả mong đợi

Hai Alert đúng SID/message/severity/endpoints; giữ flow ID, byte spans và input; count = 1.

## Kết quả hiện tại

PASS: 4 kịch bản, 67 assertion, exit code 0; không thay đổi minh chứng BT3.

## Minh chứng

`validate.py`, `result.txt`; fixture nguồn tại `TEST/BT3/T14_detection_event/`.
