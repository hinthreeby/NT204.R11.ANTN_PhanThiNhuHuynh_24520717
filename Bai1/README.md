# Bài 1 - Packet Capture & Parser cho IDS
Module thu thập và phân tích packet bằng Python, hỗ trợ **Live Capture** và **PCAP Import**, sử dụng chung một parsing pipeline và xuất kết quả dưới dạng JSON Lines.

## Giao thức hỗ trợ
- Network: IPv4
- Transport: TCP, UDP
- Application: HTTP/1.x, DNS, SMTP
- Hỗ trợ nhận diện HTTP, DNS và SMTP trên non-standard port dựa trên payload.

## Chức năng chính
- Bắt packet trực tiếp từ network interface.
- Đọc và xử lý packet từ file PCAP.
- Phân tích IPv4, TCP, UDP.
- Nhận diện và phân tích HTTP/1.x, DNS, SMTP.
- Chuẩn hóa packet thành IDS event.
- Xử lý protocol không hỗ trợ hoặc packet lỗi mà không làm chương trình dừng.
- Ghi kết quả dưới dạng JSON Lines.

## Sử dụng
Đọc file PCAP:
```bash
python main.py --pcap test.pcap
```

Live Capture:
```bash
python main.py --interface "<interface>"
```

Chỉ định file output:
```bash
python main.py --pcap test.pcap --output output/events.jsonl
```

Xem danh sách network interface:
```bash
python -c "from scapy.all import conf; conf.ifaces.show()"
```

## TEST
Các testcase nằm trong thư mục `TEST/`, bao gồm:
- TCP handshake
- TCP data
- UDP
- HTTP GET, POST, Response
- DNS Query, Response
- SMTP Command, Response
- Unknown protocol
- Malformed packet
- HTTP, DNS và SMTP trên non-standard port
- JSONL logging
- Live Capture

## Sử dụng AI
- **Công cụ:** ChatGPT
- **Mục đích:** Hỗ trợ phân tích yêu cầu, tham khảo hướng triển khai, giải thích các vấn đề kỹ thuật, kiểm tra và tìm lỗi trong quá trình thực hiện bài tập.
- **Phạm vi mã nguồn có AI hỗ trợ:** Một số phần trong quá trình xây dựng cấu trúc chương trình, xử lý packet, kiểm thử và debugging được thực hiện với sự hỗ trợ tham khảo từ AI.