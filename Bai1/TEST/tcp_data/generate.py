from scapy.all import IP, TCP, Raw, wrpcap


packet = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20"
    )
    / TCP(
        sport=50000,
        dport=80,
        flags="PA",
        seq=1001,
        ack=2001,
    )
    / Raw(
        load=b"Hello from TCP"
    )
)


wrpcap(
    "TEST/tcp_data/input.pcap",
    [packet]
)

print("TCP data PCAP created.")