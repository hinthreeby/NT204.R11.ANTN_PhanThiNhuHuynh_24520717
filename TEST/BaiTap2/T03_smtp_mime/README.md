# Test T03 - SMTP/MIME Base64 và Quoted-Printable

## Mục tiêu

Kiểm tra SMTP/MIME Decoder xử lý Base64 và Quoted-Printable khi `Content-Transfer-Encoding` chỉ ra encoding tương ứng.

## Input/Scenario

`input.jsonl` có 2 event SMTP: một body Base64 và một body Quoted-Printable.

Giữ nguyên dữ liệu, expected result và assertion của hai event này. `validate.py` bổ sung 18 tình huống packet IPv4/TCP chứa MIME message trong một payload, đi qua Detector → SMTP Parser → Decoder → Preprocessor → Flow Tracker.

Các tình huống gồm Base64, Quoted-Printable, header khác kiểu chữ, header gấp dòng, Base64 nhiều dòng, prefix `DATA`, dấu kết thúc DATA, body thiếu/rỗng, encoding lỗi, charset không hỗ trợ hoặc byte không hợp lệ, charset Latin-1, không có header encoding, encoding không hỗ trợ, header trùng và multipart. Output packet được lưu riêng tại `packet_events.jsonl` để giữ nguyên minh chứng cũ.

## Phạm vi hỗ trợ

- MIME đơn phần với headers và body nằm trong cùng một payload; chấp nhận CRLF hoặc LF và dòng kết thúc SMTP DATA tùy chọn.
- Payload có thể bắt đầu trực tiếp bằng MIME headers hoặc có dòng `DATA` phía trước. Nhận diện cần ít nhất một header `MIME-Version`, `Content-Type` hoặc `Content-Transfer-Encoding`.
- Giữ Content-Type, Content-Transfer-Encoding và body gốc; chỉ giải mã transfer encoding khi header chỉ rõ Base64 hoặc Quoted-Printable. Charset lấy từ Content-Type; thiếu charset dùng ASCII/UTF-8 như trước.
- Không tái lắp TCP stream, không lưu trạng thái phiên DATA, không giải mã TLS, không xử lý dot-stuffing hay multipart. Multipart được đánh dấu partial với lý do chưa hỗ trợ; không tuyên bố hỗ trợ fragmented stream.

## Cách chạy

Chạy từ thư mục gốc repository.

```powershell
python main.py --input TEST/BaiTap2/T03_smtp_mime/input.jsonl --output TEST/BaiTap2/T03_smtp_mime/events.jsonl
python TEST/BaiTap2/T03_smtp_mime/validate.py
```

## Kết quả mong đợi

- Base64 giải mã thành `Hello from SMTP!`.
- Quoted-Printable giải mã thành `Hello from Quoted-Printable!`.
- Cả hai event có `decode_status = success`.
- Packet MIME hợp lệ có `decoded_body` đúng và `decode_status = success`.
- Header matching và tên encoding không phân biệt hoa thường.
- Không có header encoding: `decode_status = unchanged`, không sinh `decoded_body` hay tự đoán encoding.
- Base64/Quoted-Printable lỗi, body thiếu, charset lỗi hoặc MIME không hợp lệ: `partial` và có `decode_reason`; không crash.
- Preprocessor nhận trạng thái partial từ Decoder; output serialize/deserialize JSON Lines được.
- SMTP command/response Bài 1 giữ nguyên kết quả parse.

## Kết quả hiện tại

- `events.jsonl` có 2 event SMTP và cả hai đều `decode_status = success`.
- Base64 được giải mã thành `Hello from SMTP!`.
- Quoted-Printable được giải mã thành `Hello from Quoted-Printable!`.
- `validate.py` chạy và trả về `T03 PASS` lưu ở `result.txt`.
- Đã chạy thêm 18 tình huống packet qua pipeline và ghi/đọc lại `packet_events.jsonl`; kết quả từng trường hợp nằm trong `result.txt`.
- Regression Bài 1: `smtp_command`, `smtp_response`, `smtp_nonstandard_port`, `smtp_invalid_base64` đều PASS.

**Trạng thái: PASS**

## Minh chứng hiện có

- `input.jsonl`
- `events.jsonl`
- `validate.py`
- `result.txt`
- `packet_events.jsonl`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
