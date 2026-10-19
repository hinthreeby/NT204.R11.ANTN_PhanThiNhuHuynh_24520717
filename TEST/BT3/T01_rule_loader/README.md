# Test T01 - Rule Loader

## Mục tiêu

Kiểm tra T01 theo `Bai-tap-03_Core_Engine_IDS.pdf`, trang 3, mục 7: đọc file có rule hợp lệ, comment và dòng trống.

Loader lọc comment/dòng trống và chuyển candidate nguyên văn sang Parser. Validator quyết định valid/invalid/unsupported; chỉ rule valid mới được xét chính sách SID để chấp nhận. Test không yêu cầu Loader tự kiểm tra cú pháp Snort.

## Input/Scenario

- `sample.rules`: 3 rule hợp lệ ở dòng 3, 6, 8; 3 dòng trống và 3 comment, trong đó có comment thụt đầu dòng.
- Rule ở dòng 6 có khoảng trắng đầu dòng, dấu `#` và `;` trong `msg` để kiểm tra nội dung được giữ nguyên.
- `additional.rules`: rule hợp lệ SID 100004 ở dòng 3, rule có SID sai kiểu ở dòng 4 và rule hợp lệ SID 100005 ở dòng 6.
- Expected text, filename, line number và SID được khai báo cố định trong `validate.py`.

## Các trường hợp kiểm thử và kết quả mong đợi

1. Đọc `sample.rules`: nhận đúng 3 candidate, không có comment/dòng trống; nội dung và vị trí nguồn khớp expected.
2. Validator thực tế chấp nhận cả 3 candidate, SID lần lượt 100001, 100002, 100003.
3. Đọc hai file: 6 candidate đúng thứ tự, 5 valid và 1 invalid; kết quả validation giữ nguyên nguồn.
4. Tắt từng file, bật cả hai hoặc tắt cả hai: chỉ nhận candidate của các file được bật; file không cấu hình mặc định được bật.
5. Tắt SID 100002 và bật SID 100004: cả 6 candidate vẫn qua Validator; chỉ chấp nhận SID 100001, 100003, 100004, 100005. Bật lại SID 100002 thì chấp nhận đủ 5 rule valid.
6. Rule SID sai kiểu bị Validator trả invalid với reason; rule phía sau vẫn được chấp nhận, input không bị sửa.

## Cách chạy

Chạy từ thư mục gốc repository:

```powershell
python -B TEST/BT3/T01_rule_loader/validate.py
```

Script xác định input từ vị trí `validate.py`, không phụ thuộc current working directory và không tự ghi đè `result.txt`. Assertion thất bại làm exit code khác 0; chỉ in `T01 PASS` sau khi mọi assertion thành công. Không chạy với `-O`.

## Kết quả hiện tại

- Đã chạy lệnh trên từ repository root với Python 3.10.5 trên Windows: cả 6 nhóm assertion PASS, script in `T01 PASS`, exit code 0.
- Đã chạy lại bằng đường dẫn tuyệt đối từ thư mục tạm ngoài repository: cùng output, exit code 0; thư mục tạm đã được dọn.
- Hai file tạo 6 candidate, Validator chấp nhận 5 rule và từ chối 1 rule SID sai kiểu; tắt SID 100002 còn 4 rule được chấp nhận.
- `result.txt` lưu command, phiên bản Python, output và exit code sau khi kiểm thử thành công.

**Trạng thái: PASS**

## Minh chứng

- `sample.rules`
- `additional.rules`
- `validate.py`
- `result.txt` được ghi sau khi xác nhận script thành công.

## Phạm vi

T01 kiểm tra việc nạp và chuyển rule sang Validator, không thực hiện packet matching, indexing, evaluation hoặc sinh Detection Event. Rule SID sai kiểu chỉ dùng để kiểm tra khả năng tiếp tục xử lý, không thay thế testcase T02.
