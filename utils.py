import ipaddress

def ip_range_from_cidr(cidr: str):
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(cidr, strict=False)]
    except Exception:
        return []

def ip_range_from_wildcard(wildcard: str):
    # Ex: 192.168.1.* or 10.0.*.*
    parts = wildcard.split('.')
    ranges = []
    for part in parts:
        if part == '*':
            ranges.append(range(0, 256))
        else:
            ranges.append([int(part)])
    return [
        f"{a}.{b}.{c}.{d}"
        for a in ranges[0]
        for b in ranges[1]
        for c in ranges[2]
        for d in ranges[3]
    ] 