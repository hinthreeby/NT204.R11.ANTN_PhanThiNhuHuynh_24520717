# Test T04 - Invalid UTF-8 Bytes

## Mục tiêu

Kiểm tra Decoder xử lý byte sequence không hợp lệ theo cách an toàn, đánh dấu partial và tiếp tục chạy.

## Input/Scenario

`test.py` tạo HTTP body `b"Hello \xff world"` chứa byte `0xff` không hợp lệ trong UTF-8.

## Cách chạy

```powershell
python -X utf8 -m TEST.T04_invalid_bytes.test
```

## Kết quả mong đợi

- Không ném uncaught `UnicodeDecodeError`.
- Dùng ký tự thay thế `�` cho byte lỗi.
- `decode_status = partial` và có `decode_reason`.

## Kết quả hiện tại

- `result.txt` cho thấy body được biểu diễn thành `Hello � world`.
- `raw_body_hex = 48656c6c6f20ff20776f726c64`.
- `decode_status = partial`, có lý do lỗi UTF-8 và dòng cuối là `T04 PASS`.

**Trạng thái: PASS**

## Minh chứng hiện có

- `test.py`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
