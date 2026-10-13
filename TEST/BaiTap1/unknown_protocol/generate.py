from scapy.all import IP, ICMP, wrpcap


packet = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20",
    )
    / ICMP()
)


wrpcap(
    "TEST/unknown_protocol/input.pcap",
    [packet],
)

print("Unknown protocol PCAP created.")