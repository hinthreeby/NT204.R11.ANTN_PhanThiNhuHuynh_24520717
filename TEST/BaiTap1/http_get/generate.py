from scapy.all import IP, TCP, Raw, wrpcap


http_request = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: Day3-Test\r\n"
    b"\r\n"
)


packet = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20",
    )
    / TCP(
        sport=50000,
        dport=80,
        flags="PA",
        seq=1001,
        ack=2001,
    )
    / Raw(
        load=http_request
    )
)


wrpcap(
    "TEST/http_get/input.pcap",
    [packet]
)

print("HTTP GET PCAP created.")