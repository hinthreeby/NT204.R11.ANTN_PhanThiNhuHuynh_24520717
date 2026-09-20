from scapy.all import IP, TCP, Raw, wrpcap


body = b"username=admin&password=123"


http_request = (
    b"POST /login HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: 27\r\n"
    b"\r\n"
    + body
)


packet = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20",
    )
    / TCP(
        sport=50001,
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
    "TEST/http_post/input.pcap",
    [packet]
)

print("HTTP POST PCAP created.")