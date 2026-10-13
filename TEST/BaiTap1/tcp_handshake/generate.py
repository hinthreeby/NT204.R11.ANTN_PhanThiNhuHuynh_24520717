from scapy.all import IP, TCP, wrpcap


client_ip = "192.168.1.10"
server_ip = "192.168.1.20"

client_port = 50000
server_port = 80


syn = (
    IP(src=client_ip, dst=server_ip)
    / TCP(
        sport=client_port,
        dport=server_port,
        flags="S",
        seq=1000,
    )
)

syn_ack = (
    IP(src=server_ip, dst=client_ip)
    / TCP(
        sport=server_port,
        dport=client_port,
        flags="SA",
        seq=2000,
        ack=1001,
    )
)

ack = (
    IP(src=client_ip, dst=server_ip)
    / TCP(
        sport=client_port,
        dport=server_port,
        flags="A",
        seq=1001,
        ack=2001,
    )
)


packets = [
    syn,
    syn_ack,
    ack,
]


wrpcap(
    "TEST/tcp_handshake/input.pcap",
    packets
)

print("TCP handshake PCAP created.")