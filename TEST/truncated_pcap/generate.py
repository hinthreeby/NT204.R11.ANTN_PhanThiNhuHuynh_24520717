from pathlib import Path

from scapy.all import IP, TCP, Raw, wrpcap


valid_path = Path(
    "TEST/truncated_pcap/valid.pcap"
)

truncated_path = Path(
    "TEST/truncated_pcap/input.pcap"
)


packet = (
    IP(
        src="192.168.1.10",
        dst="192.168.1.20",
    )
    / TCP(
        sport=50000,
        dport=80,
        flags="PA",
    )
    / Raw(
        load=b"GET / HTTP/1.1\r\n\r\n"
    )
)


wrpcap(
    str(valid_path),
    [packet],
)


pcap_data = valid_path.read_bytes()


# Remove bytes from the end of the PCAP file
# to simulate a truncated packet.
truncated_data = pcap_data[:-10]


truncated_path.write_bytes(
    truncated_data
)


print("Truncated PCAP created.")