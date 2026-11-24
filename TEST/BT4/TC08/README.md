# TC08 - Event ngoài cửa sổ tạo Alert/nhóm mới

## Mục tiêu và semantics hiện tại

Chạy qua AlertManager và Aggregation Engine thật, không mock kết quả. Test không
import runner TC07, không ghi vào TC01–TC07 và không triển khai Repository.

Key là `(sid, src_ip, dst_ip)`. Window cố định theo `first_seen`, bao gồm boundary;
`last_seen` không kéo dài deadline. Event sau deadline tạo nhóm `created` có UUID
mới, count=1, timestamp/first_seen/last_seen bằng timestamp mới. Nhóm cũ được trả
qua `result.finalized`; caller thu thập output này và output `manager.flush()`.

Watermark là timestamp lớn nhất của event hợp lệ đã qua policy. Nó có thể làm
hết hạn nhóm trên các key khác. Out-of-order còn trong nhóm mở được `aggregated`,
giữ first_seen và lấy last_seen lớn nhất. Event muộn không thuộc nhóm mở thành
singleton `finalized`, xuất ngay trong `result.finalized`; không mở lại nhóm đã đóng.
Không cộng nhóm đó lần nữa chỉ vì nó cũng xuất hiện ở `result.group`.

Flush đóng/xóa nhóm đang mở, không trả lại nhóm đã xuất và vẫn giữ watermark.
Engine không có lịch sử bền vững; việc giữ finalized groups trong test thuộc caller.
Snapshot không tự đổi khi engine xử lý event tiếp theo; dict evidence vẫn có thể
được caller chỉnh sửa nhưng không được alias state hoặc các snapshot khác.

## Scenarios và expected results

| ID | Kịch bản | Expected results |
|---|---|---|
| S01 | Cùng key tại 1000 và 1061, window=60 | Hai created, UUID khác nhau; nhóm đầu finalized |
| S02 | `math.nextafter(1060.0, +inf)` sau anchor=1000 | Giá trị float nhỏ nhất ngay sau boundary phải mở nhóm mới |
| S03 | Đúng boundary 1060 | aggregated, count=2; không finalize sớm |
| S04 | Hai window liên tiếp cùng key, mỗi window hai event | Hai nhóm count=2; ID ổn định trong từng nhóm |
| S05 | Mười window liên tiếp cùng key | Thu đủ 10 nhóm, mỗi nhóm 2 members; không mất output |
| S06 | Ba nhóm kế tiếp | Ba UUID4 khác nhau |
| S07 | Nhóm đầu count=3, nhóm sau thêm hai event | Nhóm mới reset count=1 rồi tăng lên 2 |
| S08 | Timestamp phần lẻ 1234.5, 1300.25, 1301.5 | Nhóm mới first_seen=1300.25, last_seen=1301.5 |
| S09 | Event cách rất xa nhau | Mọi nhóm cũ truy xuất được qua finalized và flush |
| S10 | Tiếp tục xử lý sau finalize; sửa evidence output | Nhóm đóng không tự đổi; không alias snapshot khác/live state; count frozen |
| S11 | Reorder trong window mở rồi gửi event thuộc window đã đóng | Gộp đúng nhóm mở; late singleton; không reopen nhóm cũ |
| S12 | Event trước first_seen | Hai late singleton được xuất ngay; nhóm mở giữ count chính xác |
| S13 | Key khác SID, source IP và destination IP | Hết hạn độc lập theo anchor; giữ đủ 7 nhóm qua lifecycle |
| S14 | Window nhỏ 1 giây | Biên 1 được gộp; 1.25 tạo nhóm mới |
| S15 | Window lớn 86.400 giây | Biên 87400 được gộp với anchor=1000; 87400.5 tạo nhóm mới |
| S16 | Flush nhiều nhóm, flush lại, tiếp tục xử lý | Không xuất trùng; timestamp cũ vẫn là late sau flush |
| S17 | Xen kẽ event sai thứ tự, trùng timestamp và late | 10 event được giữ trong 5 nhóm; không tăng/giảm nhầm count |
| S18 | Filtered/suppressed/rejected có timestamp tương lai | Không đẩy watermark hoặc làm expire nhóm; event hợp lệ mới điều khiển window |
| S19 | 1000,1059,1061 với window=60 | Event cuối tạo nhóm mới dù gần last_seen; không dùng sliding window |
| S20 | 500 chu kỳ, 3 key, 2 event/key/chu kỳ | 3.000 event, 1.500 nhóm finalized, mỗi nhóm count=2; tối đa 3 nhóm chưa finalized |

Oracle dùng label nhóm, status và danh sách nhóm finalized được khai báo tường
minh trong từng scenario, không chạy lại thuật toán window để đoán expected output.
Mỗi bước kiểm tra status, UUID4/ID nhóm, count, timestamp/first_seen/last_seen,
key, metadata summary và từng member (flow ID, revision, message, priority,
severity, port/protocol, classtype, evidence), cùng input không bị mutate.
Sau flush kiểm tra tổng nhóm, tổng count/members, UUID thành viên không trùng và
mọi nhóm đã mở đều được thu về đúng một lần.

Stress test kiểm tra tính đúng, không đặt ngưỡng tốc độ hoặc khẳng định benchmark
bộ nhớ. Số nhóm chưa finalized được suy ra từ output public API; test không đọc
private state. Nhóm đóng được caller của test giữ lại để kiểm kê dữ liệu.

## Cách chạy và minh chứng

Từ repository root:

```powershell
python -B TEST/BT4/TC08/validate.py
```

Runner tự ghi output console vào `TEST/BT4/TC08/result.txt` bằng UTF-8, ghi đè lần
chạy trước. File ghi command, Python version, working directory, thời điểm chạy
UTC+07:00 (Asia/Saigon), PASS/FAIL từng scenario, tổng scenarios/assertions,
traceback lỗi, thời lượng và exit code. Thời gian thực chỉ phục vụ báo cáo;
window dùng timestamp fixture. Không cần thư viện ngoài Python standard library.

Exit code 0 nếu cả 20 scenarios PASS, 1 nếu có scenario FAIL. Assertion dùng kiểm
tra tường minh, không bị bỏ bởi optimization. Tổng assertions đếm các kiểm tra
đã thực thi; exception cũng làm scenario FAIL và được ghi traceback. Kết quả
thực tế nằm trong `result.txt`, README không ghi sẵn báo cáo PASS.
