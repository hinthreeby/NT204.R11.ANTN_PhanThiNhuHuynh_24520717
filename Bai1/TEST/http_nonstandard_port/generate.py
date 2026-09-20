from scapy.all import IP, TCP, Raw, wrpcap


http_request = (
    b"GET /admin HTTP/1.1\r\n"
    b"Host: bonus.example.com\r\n"
    b"\r\n"
)


packet = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20",
    )
    / TCP(
        sport=51000,
        dport=8888,
        flags="PA",
    )
    / Raw(
        load=http_request
    )
)


wrpcap(
    "TEST/http_nonstandard_port/input.pcap",
    [packet]
)

print("Non-standard port HTTP PCAP created.")