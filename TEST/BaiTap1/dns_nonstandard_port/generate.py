from scapy.all import (
    IP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    wrpcap,
)


client_ip = "192.168.1.10"
server_ip = "192.168.1.20"

client_port = 54000
server_port = 5300


query_packet = (
    IP(
        src=client_ip,
        dst=server_ip,
    )
    / UDP(
        sport=client_port,
        dport=server_port,
    )
    / DNS(
        id=0x1234,
        rd=1,
        qdcount=1,
        qd=DNSQR(
            qname="example.com",
            qtype="A",
        ),
    )
)


response_packet = (
    IP(
        src=server_ip,
        dst=client_ip,
    )
    / UDP(
        sport=server_port,
        dport=client_port,
    )
    / DNS(
        id=0x1234,
        qr=1,
        aa=1,
        qdcount=1,
        ancount=1,
        qd=DNSQR(
            qname="example.com",
            qtype="A",
        ),
        an=DNSRR(
            rrname="example.com",
            type="A",
            ttl=300,
            rdata="93.184.216.34",
        ),
    )
)


packets = [
    query_packet,
    response_packet,
]


wrpcap(
    "TEST/dns_nonstandard_port/input.pcap",
    packets,
)

print("DNS non-standard port PCAP created.")