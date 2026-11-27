# TC13 - Protocol/Time Statistics

## Mục tiêu

Kiểm tra thống kê transport/application protocol và số Alert/count theo giờ hoặc phút từ Repository.

## Input/Scenario

- Fixture trong `validate.py`: 7 Alert, tổng count=18, TCP/UDP và HTTP/DNS/SMTP/UNKNOWN; dùng SQLite tạm ngoài repository.
- Kiểm tra nhiều bucket, timestamp UTC/UTC+07 cùng thời điểm, ngay trước/đúng/sau boundary, time range, epoch zero và dữ liệu rỗng.
- Kiểm tra aggregation thật qua boundary, opening timestamp khác last_seen, sparse buckets, reopen và database không bị thay đổi.
- ICMP chưa được Repository/schema hiện tại hỗ trợ: kiểm tra insert bị từ chối rõ ràng và dữ liệu không đổi; không kiểm chứng thống kê ICMP thành công.

## Cách chạy

Từ repository root:

```powershell
python -B TEST/BT4/TC13/validate.py
```

## Kết quả mong đợi

Theo `(số Alert, tổng count)`: TCP=(4,12), UDP=(3,6); DNS=(2,4), HTTP=(2,3), SMTP=(1,4), UNKNOWN=(2,7). Bucket dùng UTC epoch, `[start, end)`, chỉ hiện bucket có dữ liệu; toàn bộ count của nhóm thuộc opening `timestamp`. Query dùng `[from_time, to_time)`, không dùng `last_seen`. ICMP báo ValueError theo giới hạn hiện tại.

## Kết quả hiện tại

PASS: 16 kịch bản, 84 assertion, exit code 0. Phần ICMP là kiểm thử từ chối, chưa có positive coverage cho ICMP. Thời điểm chạy và kết quả từng scenario nằm trong `result.txt`.

## Minh chứng

`validate.py`, `result.txt`.
