from scapy.layers.inet import UDP


def parse_udp(udp_layer: UDP) -> dict:
    """
    Parse a UDP layer into a normalized dictionary.
    """

    payload = bytes(udp_layer.payload)
    # UDP length includes its eight-byte header; bytes beyond it are padding,
    # not transport payload. Missing/malformed lengths do not discard data.
    if isinstance(udp_layer.len, int) and udp_layer.len >= 8:
        payload = payload[:udp_layer.len - 8]

    return {
        "protocol": "UDP",
        "src_port": udp_layer.sport,
        "dst_port": udp_layer.dport,
        "length": udp_layer.len,
        "checksum": udp_layer.chksum,
        "payload_length": len(payload),
        "payload_hex": payload.hex(),
    }
