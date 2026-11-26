# TC09 - Repository Persistence

## Mục tiêu và phạm vi

Kiểm tra yêu cầu TC09: lưu và đọc lại Alert không mất trường bắt buộc. Validator
sử dụng AlertRepository/AlertPersistenceAdapter và SQLite thật; không mock kết quả
ghi/đọc. Tất cả database, trigger và fixture lỗi được tạo trong TemporaryDirectory
ngoài repository rồi dọn sau từng scenario. Chỉ result.txt được ghi trong thư mục TC09.

Đối chiếu đủ 19 field: alert_id, timestamp, sid, rev, message, severity, src_ip,
src_port, dst_ip, dst_port, protocol, application_protocol, flow_id, first_seen,
last_seen, priority, classtype, count, match_information. Kiểm tra cả giá trị, kiểu
dữ liệu và JSON round trip; metadata lồng nhau được kiểm tra kiểu đệ quy.

## Scenarios và expected results

| ID | Scenario | Expected results |
|---|---|---|
| S01 | Insert Alert hợp lệ | Database/parent được tạo khi mở Repository; commit đúng một row, đủ 19 field |
| S02 | Read bằng ID | Trả Alert tương ứng; ID không tồn tại trả None |
| S03 | 30 Alert độc lập | Đọc đủ từng ID, không mất hoặc ghi đè row |
| S04 | UUID preservation | Giữ nguyên 8 UUID4 khác nhau sau lưu/đọc |
| S05 | SID preservation | Giữ int dương, kể cả SID vượt 64-bit |
| S06 | Severity preservation | CRITICAL/HIGH/MEDIUM/LOW giữ nguyên |
| S07 | Source/destination IP và port | Hai IP cùng port biên 0/65535 không đổi |
| S08 | Protocol preservation | TCP/UDP và HTTP/DNS/SMTP/UNKNOWN không đổi |
| S09 | Timestamp preservation | UTC epoch seconds gồm 0, phần lẻ và timestamp lớn đọc lại chính xác |
| S10 | first_seen/last_seen preservation | Timestamp, first_seen và last_seen khác nhau vẫn được giữ riêng |
| S11 | Count preservation | Count 1/2/1000/tối đa signed 64-bit giữ nguyên; reject 0/âm/bool/float/overflow |
| S12 | Unicode message | Giữ tiếng Việt, emoji, tiếng Nhật, dấu nháy và newline |
| S13 | Nullable flow_id | flow_id/priority/classtype=None đọc lại thành None |
| S14 | Metadata/match evidence | Giữ spans, matched_hex, option_index, nested dict/list, bool/null/Unicode/int lớn; không alias output |
| S15 | Close và reopen | Close lặp lại an toàn; thao tác trên connection đóng báo lỗi; mở mới đọc được row |
| S16 | Persistence sau restart | Python process mới đọc cùng database, giữ đủ dữ liệu của 5 Alert |
| S17 | Aggregation count update | created -> aggregated; một ID, count 1..3, first_seen cố định, last_seen đúng; update/flush lặp không tăng count |
| S18 | Duplicate alert ID | sqlite3.IntegrityError; không ghi đè row cũ; connection còn dùng được |
| S19 | Invalid database path | Reject config không hợp lệ, directory thay file hoặc parent là file; không phá fixture |
| S20 | Database write failure | Trigger BEFORE INSERT gây lỗi SQLite thật; không trả thành công giả hoặc lưu row; bỏ trigger trong DB tạm rồi ghi được |
| S21 | Transaction rollback | Hai insert rồi update lỗi phải rollback toàn bộ, kể cả side effect của trigger và sau reopen |
| S22 | Empty database | Không tự sinh dữ liệu; get_by_id trả None cả trước/sau reopen |
| S23 | No input mutation | Insert/update không sửa input; sửa dict metadata bên ngoài không đổi dữ liệu đã commit |
| S24 | Finalized group persistence | Giữ nhóm expired, late singleton và nhóm flush; 3 row bảo toàn 4 event, reopen không mất nhóm |

## Chính sách dữ liệu được kiểm thử

- Timestamp dùng UTC Unix epoch seconds dạng float, không thay bằng thời điểm ghi DB.
- SID/rev/priority được lưu dạng decimal TEXT để bảo toàn Python int, đọc lại thành int.
- count là SQLite INTEGER dương; không nhận bool hoặc giá trị vượt signed 64-bit.
- match_information được lưu JSON TEXT và đọc lại thành tuple các dict. Chỉ hỗ trợ
  metadata JSON-compatible; không tuyên bố hỗ trợ bytes hoặc object Python tùy ý.
- Adapter lưu summary Alert. members đầy đủ của AlertGroup và cờ finalized không
  được lưu thành bảng riêng trong implementation hiện tại; S24 kiểm tra summary
  đã finalized vẫn tồn tại, không tuyên bố khôi phục active aggregation sau restart.

Lỗi ghi được tạo bằng SQLite trigger, không giả lập disk-full hoặc permission OS.
S21 dùng RAISE(FAIL): kiểm tra rollback của Repository, thay vì chỉ dựa vào việc một
statement lỗi tự rollback. Các thao tác DROP TRIGGER chỉ tác động database tạm của
scenario; không truy cập hoặc sửa/xóa database thật.

## Cách chạy

Từ repository root:

```powershell
python -B TEST/BT4/TC09/validate.py
```

Runner tự in output và ghi cùng output UTF-8 vào result.txt cạnh validate.py,
ghi đè kết quả lần trước. Không cần redirect console thủ công.

Output gồm command, Python/SQLite version, thời điểm chạy UTC+07:00, từng scenario
PASS/FAIL, assertion count, tổng hợp, error details/traceback, thời lượng và exit code.
Assertion được thực thi tường minh, không bị bỏ bởi Python optimization. Tổng
assertions đếm các kiểm tra đã thực thi; exception cũng làm scenario FAIL.
Exit code 0 chỉ khi cả 24 scenarios PASS và thư mục tạm được dọn; nếu có lỗi trả 1.

## Evidence

result.txt do lần chạy thực tế sinh ra. README không ghi sẵn kết quả PASS.
Không sửa production code hoặc các test TC01–TC08 để thay đổi expected results.
