from scapy.all import IP, UDP, Raw, wrpcap


malformed_dns_payload = (
    b"\x12\x34\x01\x00\x00"
)


packet = (
    IP(
        src="192.168.1.10",
        dst="8.8.8.8",
    )
    / UDP(
        sport=53000,
        dport=53,
    )
    / Raw(
        load=malformed_dns_payload
    )
)


wrpcap(
    "TEST/malformed_packet/input.pcap",
    [packet],
)

print("Malformed packet PCAP created.")