from scapy.all import IP, TCP, Raw, wrpcap


client_ip = "192.168.1.10"
server_ip = "192.168.1.20"

client_port = 51000
server_port = 2525


ehlo_packet = (
    IP(
        src=client_ip,
        dst=server_ip,
    )
    / TCP(
        sport=client_port,
        dport=server_port,
        flags="PA",
    )
    / Raw(
        load=b"EHLO client.example.com\r\n"
    )
)


response_packet = (
    IP(
        src=server_ip,
        dst=client_ip,
    )
    / TCP(
        sport=server_port,
        dport=client_port,
        flags="PA",
    )
    / Raw(
        load=b"250 OK\r\n"
    )
)


packets = [
    ehlo_packet,
    response_packet,
]


wrpcap(
    "TEST/smtp_nonstandard_port/input.pcap",
    packets,
)

print("SMTP non-standard port PCAP created.")