# Test T03 - SMTP/MIME Base64 và Quoted-Printable

## Mục tiêu

Kiểm tra SMTP/MIME Decoder xử lý Base64 và Quoted-Printable khi `Content-Transfer-Encoding` chỉ ra encoding tương ứng.

## Input/Scenario

`input.jsonl` có 2 event SMTP: một body Base64 và một body Quoted-Printable.

## Cách chạy

```powershell
python main.py --input TEST\T03_smtp_mime\input.jsonl --output TEST\T03_smtp_mime\events.jsonl
python TEST\T03_smtp_mime\validate.py
```

## Kết quả mong đợi

- Base64 giải mã thành `Hello from SMTP!`.
- Quoted-Printable giải mã thành `Hello from Quoted-Printable!`.
- Cả hai event có `decode_status = success`.

## Kết quả hiện tại

- `events.jsonl` có 2 event SMTP và cả hai đều `decode_status = success`.
- Base64 được giải mã thành `Hello from SMTP!`.
- Quoted-Printable được giải mã thành `Hello from Quoted-Printable!`.
- `validate.py` chạy và trả về `T03 PASS` lưu ở `result.txt`.

**Trạng thái: PASS**

## Minh chứng hiện có

- `input.jsonl`
- `events.jsonl`
- `validate.py`
- `result.txt`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
