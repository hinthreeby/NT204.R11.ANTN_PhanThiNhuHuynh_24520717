# Test T04 - Invalid UTF-8 Bytes

## Mục tiêu

Kiểm tra Decoder xử lý byte sequence không hợp lệ theo cách an toàn, đánh dấu partial và tiếp tục chạy.

## Input/Scenario

`test.py` tạo HTTP body `b"Hello \xff world"` chứa byte `0xff` không hợp lệ trong UTF-8.

Giữ nguyên test Decoder trực tiếp và assertion cũ. Bổ sung request POST và response HTTP qua packet IPv4/TCP thực tế được serialize rồi parse lại, với các body:

- ASCII: `Hello world`.
- UTF-8 hợp lệ: `Xin chào`.
- Byte lỗi: `b"Hello \xff world"`.
- UTF-8 bị cắt: `b"Hello \xc3"`.
- Ký tự thay thế `U+FFFD` được encode UTF-8 hợp lệ, để tránh đánh dấu partial chỉ vì thấy ký tự `�`.

Thêm hai packet có byte `0xff` trong HTTP header, tương ứng lỗi có trong testcase `BaiTap1/decode_error`. Tổng cộng 12 event packet được ghi vào `events.jsonl`. Kiểm tra thêm HTTP dùng LF, thông điệp malformed và metadata hex không hợp lệ trong bộ nhớ.

## Cách chạy

Chạy từ thư mục gốc repository.

```powershell
python -X utf8 -m TEST.BaiTap2.T04_invalid_bytes.test
```

## Kết quả mong đợi

- Không ném uncaught `UnicodeDecodeError`.
- Dùng ký tự thay thế `�` cho byte lỗi.
- `decode_status = partial` và có `decode_reason`.
- Với ASCII/UTF-8 hợp lệ: Decoder ghi `success`, Preprocessor ghi `valid`; schema parser giữ nguyên.
- Với body lỗi: parser giữ `raw_body_hex` chính xác, Decoder khôi phục byte gốc để kiểm tra UTF-8 và ghi `partial`; body vẫn là chuỗi có thể serialize JSON.
- Với header lỗi: giữ `raw_header_hex`, Decoder ghi `partial` cùng lý do lỗi header.
- `decoder.status = partial` được Preprocessor nhận biết: `preprocess_status = partial`, `processing_action = continue`.
- URL decoding vẫn hoạt động với URI `/submit?q=%27` trong request.
- Mọi event được serialize/deserialize JSON thành công; ghi và đọc lại bằng JSONLWriter không mất dữ liệu.

## Kết quả hiện tại

- `result.txt` cho thấy body được biểu diễn thành `Hello � world`.
- `raw_body_hex = 48656c6c6f20ff20776f726c64`.
- `decode_status = partial`, có lý do lỗi UTF-8 và dòng cuối là `T04 PASS`.
- Đã chạy đủ 12 packet qua pipeline; ASCII/UTF-8 hợp lệ được phân biệt với byte lỗi trong body/header.
- `events.jsonl` chứa output thực tế của các packet, không chứa đối tượng `bytes`.

**Trạng thái: PASS**

## Minh chứng hiện có

- `test.py`
- `result.txt`
- `events.jsonl`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
