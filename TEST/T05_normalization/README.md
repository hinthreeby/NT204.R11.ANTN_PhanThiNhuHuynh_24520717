# Test T05: Event Normalization

## Mục tiêu

Kiểm tra Preprocessor có chuẩn hóa nhất quán protocol name,
port, timestamp, HTTP header, URI và domain hay không.

## Input

Test gồm hai event:

1. HTTP event có protocol/header khác kiểu chữ và port ở dạng string.
2. DNS event có domain `Example.COM.` và protocol khác kiểu chữ.

## Cách chạy

```bash
python main.py --input TEST/T05_normalization/input.jsonl --output TEST/T05_normalization/events.jsonl
python TEST/T05_normalization/validate.py
```
## Kết quả mong đợi
- ipv4 → IPv4
- tCp → TCP
- uDp → UDP
- hTtP → HTTP
- HTTP header name được chuyển sang lowercase.
- Example.COM. → example.com
- Port string được chuyển thành integer.
- Timestamp được chuẩn hóa thành số.
- preprocess_status = valid

## Kết quả thực tế
- Trạng thái: PASS
- Hai event đều được chuẩn hóa thành representation nhất quán.
- Validator trả về T05 PASS.

## Minh chứng
- input.jsonl
- events.jsonl
- validate.py
- result.txt

## Kết luận
Testcase PASS, Preprocessor chuẩn hóa đúng các field được yêu cầ