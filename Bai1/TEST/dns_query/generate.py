from scapy.all import IP, UDP, DNS, DNSQR, wrpcap


packet = (
    IP(
        src="192.168.1.10",
        dst="8.8.8.8",
    )
    / UDP(
        sport=53000,
        dport=53,
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


wrpcap(
    "TEST/dns_query/input.pcap",
    [packet],
)

print("DNS query PCAP created.")