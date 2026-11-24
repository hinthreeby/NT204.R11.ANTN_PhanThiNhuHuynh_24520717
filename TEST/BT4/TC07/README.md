# TC07 - Event lặp trong cửa sổ aggregation

## Mục tiêu và phạm vi

Kiểm tra Detection Event đi qua AlertManager thật: validation -> severity mapping ->
filtering/suppression -> aggregation -> AlertResult. Không mock kết quả engine,
không sửa TC01–TC06 và không triển khai TC08 hoặc Repository.

Key là `(sid, src_ip, dst_ip)` sau chuẩn hóa. Window mặc định trong test là 60 giây,
cố định từ `first_seen`, bao gồm hai biên. `timestamp` summary giữ thời gian event mở
nhóm; `last_seen` là timestamp lớn nhất đã được gộp. Các event trong fixture độc lập
với wall-clock; thời gian thực chỉ dùng để ghi thời điểm và thời lượng chạy test.

## Kịch bản và expected results

| ID | Kịch bản | Kết quả mong đợi |
|---|---|---|
| S01 | Hai event cùng key ở 1000 và 1010 | created -> aggregated; một ID; count=2 |
| S02 | Ba event cùng key | count=3; giữ timestamp/first_seen mở nhóm |
| S03 | 100 event liên tiếp trong window | Mỗi lần tăng count đúng một; cuối cùng count=100 |
| S04 | Tám event có timestamp trùng nhau | Một nhóm count=8; first_seen=last_seen=1000 |
| S05 | Timestamp đúng 1060 với first_seen=1000, window=60 | Vẫn aggregated; không finalize sớm |
| S06 | Khác SID | Hai nhóm, hai UUID; merge tiếp không lẫn count/members |
| S07 | Khác source IP | Hai nhóm độc lập |
| S08 | Khác destination IP | Hai nhóm độc lập |
| S09 | 12 event cùng key | Kiểm tra count ở từng bước 1..12 |
| S10 | Nhiều timestamp tới đúng biên | first_seen và timestamp summary luôn là 5000 |
| S11 | Timestamp trong window đến theo thứ tự 1000,1040,1010,1030,1040 | last_seen luôn là max; cuối cùng 1040 |
| S12 | 30 event có UUID nguồn riêng | UUID nhóm luôn bằng UUID member đầu, khác UUID member cuối |
| S13 | Aggregation mặc định tắt và tắt tường minh | Hai created độc lập, count=1; không giữ group/state |
| S14 | Event bị severity filtering có timestamp xa trong tương lai | filtered; không tăng count, không expire hoặc đẩy watermark |
| S15 | Event thuộc SID bị suppression | suppressed; không tạo nhóm và không ảnh hưởng nhóm hợp lệ |
| S16 | Event priority=0 | rejected có reason; không ảnh hưởng count/window |
| S17 | Chuẩn hóa input, sửa evidence input/output sau process | Input không bị Manager mutate; sửa bản ngoài không đổi state |
| S18 | Thay flow_id, rev, port, protocol, message, severity, classtype, evidence | Summary giữ metadata mở nhóm; members giữ đủ dữ liệu từng event, kể cả flow_id=None |
| S19 | Custom window=2; timestamp 0,1,2 | Ba event cùng nhóm, count=3; biên 2 được nhận |
| S20 | 2.000 event hợp lệ xen kẽ trên 4 key | Mỗi nhóm count=500; 4 UUID khác nhau; giữ đủ 2.000 members |

Các helper kiểm tra status, reason, UUID4 và độ ổn định ID, key, count,
timestamp/first_seen/last_seen, metadata summary, metadata member, JSON round trip,
input không đổi, output finalize và flush không trùng. Với rejected/filtered/suppressed,
assert alert/group=None rồi kiểm tra nhóm hợp lệ trước và sau event bị chặn.

Stress test không đặt ngưỡng tốc độ: 500 members/nhóm nằm trong giới hạn 1.000 của
engine hiện tại. Tổng event được bảo toàn qua count và members; runner không chỉ
kiểm tra việc không crash. Những trường hợp ngoài window thuộc phạm vi TC08.

## Cách chạy

Từ repository root:

```powershell
python -B TEST/BT4/TC07/validate.py
```

Runner in output ra console và tự ghi cùng output UTF-8 vào `result.txt` trong thư
mục TC07, ghi đè kết quả lần chạy trước. Không cần chuyển hướng console thủ công.

Output gồm Python version, working directory, thời điểm chạy UTC+07:00
(Asia/Saigon), PASS/FAIL của từng scenario, tổng scenarios, tổng assertions,
traceback khi có lỗi, thời lượng và exit code. Assertion dùng kiểm tra tường minh,
không bị loại bỏ bởi Python optimization. Exit code 0 khi cả 20 scenarios PASS;
exit code 1 khi bất kỳ scenario nào FAIL. Exception ngoài assertion cũng làm scenario
FAIL và có traceback; assertion total chỉ đếm các kiểm tra đã thực sự được thực thi.

## Minh chứng thực tế

Xem `result.txt` được sinh bởi lần chạy validator. README không ghi sẵn kết quả PASS.
