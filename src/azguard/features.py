import ipaddress

import pandas as pd

from .models import (
    NetworkSecurityGroup,
    SecurityAccess,
    SecurityDirection,
    SecurityProtocol,
    SecurityRule,
)


def flatten_ports(port_str: str) -> set[int]:
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return ports


def protocol_code(p: SecurityProtocol | None) -> int:
    if p == SecurityProtocol.ASTERISK:
        return 0
    if p == SecurityProtocol.TCP:
        return 1
    if p == SecurityProtocol.UDP:
        return 2
    if p == SecurityProtocol.ICMP:
        return 3
    if p == SecurityProtocol.ESP:
        return 4
    if p == SecurityProtocol.AH:
        return 5
    return 0


def direction_code(d: SecurityDirection | None) -> int:
    if d == SecurityDirection.INBOUND:
        return 0
    if d == SecurityDirection.OUTBOUND:
        return 1
    return 0


def access_code(a: SecurityAccess | None) -> int:
    if a == SecurityAccess.ALLOW:
        return 1
    if a == SecurityAccess.DENY:
        return 0
    return 1


def source_scope(source: str | None) -> int:
    if source is None:
        return 3
    if source in ("*", "Internet", "0.0.0.0/0"):
        return 3
    if source == "VirtualNetwork":
        return 2
    try:
        net = ipaddress.ip_network(source, strict=False)
        if net.prefixlen == 32:
            return 0
        return 1
    except ValueError:
        return 3


def port_count(p: str | None) -> int:
    if p is None or p == "*":
        return 65536
    p_flatten = flatten_ports(p)
    return len(p_flatten)


def min_port(p: str | None) -> int:
    if p is None or p == "*":
        return 0
    p_flatten = flatten_ports(p)
    return sorted(p_flatten)[0]


def max_port(p: str | None) -> int:
    if p is None or p == "*":
        return 65535
    p_flatten = flatten_ports(p)
    return sorted(p_flatten)[-1]


def rule_to_vector(rule: SecurityRule) -> dict:
    return {
        "priority": rule.priority,
        "protocol_code": protocol_code(rule.protocol),
        "direction_code": direction_code(rule.direction),
        "access_code": access_code(rule.access),
        "source_scope": source_scope(rule.source_address_prefix),
        "dest_scope": source_scope(rule.destination_address_prefix),
        "port_count": port_count(rule.destination_port_range),
        "min_port": min_port(rule.destination_port_range),
        "max_port": max_port(rule.destination_port_range),
    }


def build_feature_dataframe(nsg: NetworkSecurityGroup) -> pd.DataFrame:
    rules_list = []
    for rule in nsg.security_rules:
        rules_list.append(rule_to_vector(rule))
    return pd.DataFrame(rules_list)
