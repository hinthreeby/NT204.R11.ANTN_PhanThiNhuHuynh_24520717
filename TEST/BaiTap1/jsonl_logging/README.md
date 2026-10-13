# Test - JSONL Logging

## Mục tiêu

Kiểm tra output log theo định dạng JSON Lines: mỗi event nằm trên một dòng JSON độc lập.

## Input/Scenario

Thư mục hiện chỉ lưu `events.jsonl` làm minh chứng output.

## Cách chạy

```powershell
Get-Content TEST\jsonl_logging\events.jsonl | ForEach-Object { $_ | ConvertFrom-Json | Out-Null }
```

## Kết quả mong đợi

- Mỗi dòng là một JSON object hợp lệ.
- Số dòng tương ứng số event được ghi.

## Kết quả hiện tại

- `events.jsonl` có 3 dòng JSON hợp lệ.
- Ba event tương ứng TCP SYN, SYN/ACK và ACK.

**Trạng thái: PASS**

## Minh chứng hiện có

- `events.jsonl`

## Kết luận

Testcase cho thấy chức năng đang được kiểm tra hoạt động đúng với dữ liệu và minh chứng hiện có trong thư mục này.
