from scapy.all import IP, TCP, Raw, wrpcap


packet = (
    IP(
        src="192.168.1.20",
        dst="192.168.1.10",
    )
    / TCP(
        sport=25,
        dport=50000,
        flags="PA",
    )
    / Raw(
        load=b"250 OK\r\n"
    )
)


wrpcap(
    "TEST/smtp_response/input.pcap",
    [packet],
)

print("SMTP response PCAP created.")