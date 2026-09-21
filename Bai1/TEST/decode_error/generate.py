from scapy.all import IP, TCP, Raw, wrpcap


http_payload = (
    b"GET /test HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"X-Test: \xff\xfe\xfa\r\n"
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
    )
    / Raw(
        load=http_payload
    )
)


wrpcap(
    "TEST/decode_error/input.pcap",
    [packet],
)

print("Decode error test PCAP created.")