from scapy.layers.inet import IP


def parse_ipv4(ip_layer: IP) -> dict:
    """
    Parse an IPv4 packet layer into a normalized dictionary.

    Args: ip_layer: Scapy IPv4 layer.
    
    Returns: A dictionary containing normalized IPv4 fields.
    """

    return {
        "protocol": "IPv4",
        "version": ip_layer.version,
        "header_length": ip_layer.ihl,
        "tos": ip_layer.tos,
        "total_length": ip_layer.len,
        "id": ip_layer.id,
        "flags": str(ip_layer.flags),
        "fragment_offset": ip_layer.frag,
        "ttl": ip_layer.ttl,
        "next_protocol": ip_layer.proto,
        "checksum": ip_layer.chksum,
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
    }