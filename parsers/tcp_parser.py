from scapy.layers.inet import TCP


TCP_FLAGS = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]


def get_tcp_flag_names(flag_value: int) -> list[str]:
    """
    Convert TCP flag bits into human-readable names.
    """

    return [
        name
        for bit, name in TCP_FLAGS
        if flag_value & bit
    ]


def parse_tcp(tcp_layer: TCP) -> dict:
    """
    Parse a TCP layer into a normalized dictionary.
    """

    flag_value = int(tcp_layer.flags)

    return {
        "protocol": "TCP",
        "src_port": tcp_layer.sport,
        "dst_port": tcp_layer.dport,
        "sequence": tcp_layer.seq,
        "acknowledgment": tcp_layer.ack,
        "data_offset": tcp_layer.dataofs,
        "flags": get_tcp_flag_names(flag_value),
        "window": tcp_layer.window,
        "checksum": tcp_layer.chksum,
        "urgent_pointer": tcp_layer.urgptr,
        "payload_length": len(bytes(tcp_layer.payload)),
    }