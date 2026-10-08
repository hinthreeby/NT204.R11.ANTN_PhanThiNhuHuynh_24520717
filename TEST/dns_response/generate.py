from scapy.all import (
    IP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    wrpcap,
)


packet = (
    IP(
        src="8.8.8.8",
        dst="192.168.1.10",
    )
    / UDP(
        sport=53,
        dport=53000,
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


wrpcap(
    "TEST/dns_response/input.pcap",
    [packet],
)

print("DNS response PCAP created.")