from scapy.layers.inet import UDP


def parse_udp(udp_layer: UDP) -> dict:
    """
    Parse a UDP layer into a normalized dictionary.
    """

    return {
        "protocol": "UDP",
        "src_port": udp_layer.sport,
        "dst_port": udp_layer.dport,
        "length": udp_layer.len,
        "checksum": udp_layer.chksum,
        "payload_length": len(bytes(udp_layer.payload)),
    }