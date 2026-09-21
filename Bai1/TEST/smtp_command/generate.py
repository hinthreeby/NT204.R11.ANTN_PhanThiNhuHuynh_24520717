from scapy.all import IP, TCP, Raw, wrpcap


client_ip = "192.168.1.10"
server_ip = "192.168.1.20"

client_port = 50000
server_port = 25


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


mail_from_packet = (
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
        load=b"MAIL FROM:<alice@example.com>\r\n"
    )
)


rcpt_to_packet = (
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
        load=b"RCPT TO:<bob@example.com>\r\n"
    )
)


packets = [
    ehlo_packet,
    mail_from_packet,
    rcpt_to_packet,
]


wrpcap(
    "TEST/smtp_command/input.pcap",
    packets,
)

print("SMTP command PCAP created.")