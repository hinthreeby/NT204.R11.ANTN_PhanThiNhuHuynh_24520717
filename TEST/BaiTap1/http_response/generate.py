from scapy.all import IP, TCP, Raw, wrpcap


http_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 5\r\n"
    b"Server: Day3-Test\r\n"
    b"\r\n"
    b"Hello"
)


packet = (
    IP(
        src="192.168.1.20",
        dst="192.168.1.10",
    )
    / TCP(
        sport=80,
        dport=50000,
        flags="PA",
        seq=2001,
        ack=1001,
    )
    / Raw(
        load=http_response
    )
)


wrpcap(
    "TEST/http_response/input.pcap",
    [packet]
)

print("HTTP response PCAP created.")