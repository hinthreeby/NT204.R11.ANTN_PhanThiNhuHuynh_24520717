from scapy.all import IP, UDP, Raw, wrpcap


packet = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20"
    )
    / UDP(
        sport=50000,
        dport=9999,
    )
    / Raw(
        load=b"Hello from UDP"
    )
)


wrpcap(
    "TEST/udp/input.pcap",
    [packet]
)

print("UDP PCAP created.")