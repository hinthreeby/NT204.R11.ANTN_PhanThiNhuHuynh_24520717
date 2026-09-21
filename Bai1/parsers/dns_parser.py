from scapy.layers.dns import DNS, DNSQR, DNSRR


DNS_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}


def decode_dns_name(value) -> str:
    """
    Convert a DNS name into a readable string.
    """

    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")

    return str(value).rstrip(".")


def get_first_record(section):
    """
    Return the first DNS record from a Scapy DNS section.
    """

    if section is None:
        return None

    try:
        return section[0]
    except (TypeError, IndexError, KeyError):
        return section


def parse_dns(payload: bytes) -> dict:
    """
    Parse a DNS query or response.
    """

    try:
        dns = DNS(payload)
    except Exception:
        return {
            "protocol": "DNS",
            "type": "UNKNOWN",
        }

    # DNS Query
    # qr = 0

    if int(dns.qr) == 0:
        question = get_first_record(dns.qd)

        if question is None or not isinstance(question, DNSQR):
            return {
                "protocol": "DNS",
                "type": "UNKNOWN",
            }

        query_type_number = int(question.qtype)

        return {
            "protocol": "DNS",
            "type": "query",
            "transaction_id": int(dns.id),
            "domain": decode_dns_name(question.qname),
            "query_type": DNS_TYPE_NAMES.get(
                query_type_number,
                str(query_type_number),
            ),
        }

    # DNS Response
    # qr = 1

    answer = get_first_record(dns.an)

    answers = []

    if isinstance(answer, DNSRR):
        answer_type_number = int(answer.type)

        rdata = answer.rdata

        if isinstance(rdata, bytes):
            rdata = rdata.decode(
                "utf-8",
                errors="replace",
            )

        answers.append(
            {
                "name": decode_dns_name(answer.rrname),
                "type": DNS_TYPE_NAMES.get(
                    answer_type_number,
                    str(answer_type_number),
                ),
                "ttl": int(answer.ttl),
                "data": str(rdata),
            }
        )

    return {
        "protocol": "DNS",
        "type": "response",
        "transaction_id": int(dns.id),
        "response_code": int(dns.rcode),
        "answers": answers,
    }