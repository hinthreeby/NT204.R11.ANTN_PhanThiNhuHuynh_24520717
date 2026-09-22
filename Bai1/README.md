# Bài 1 - Packet Capture & Parser cho IDS

Module thu thập và phân tích packet bằng Python, hỗ trợ cả **Live Capture** và **PCAP** trên cùng một parsing pipeline.

## Giao thức hỗ trợ

- Network: IPv4
- Transport: TCP, UDP
- Application: HTTP/1.x, DNS, SMTP

## Sử dụng
- Đọc PCAP: python main.py --pcap test.pcap
- Live Capture: python main.py --interface "<interface>"
- Chỉ định file output: python main.py --pcap test.pcap --output output/events.jsonl

## TEST
Các testcase nằm trong thư mục TEST, bao gồm:
- TCP handshake, TCP data, UDP
- HTTP GET, POST, Response
- DNS Query, Response
- SMTP Command, Response
- Unknown protocol
- Malformed packet

## Sử dụng AI
- Công cụ: ChatGPT
- Mục đích: hỗ trợ thiết kế cấu trúc project, tìm lỗi