import ipaddress
from .rule_engine import CheckResult
from .models import NetworkSecurityGroup, SecurityProtocol, SecurityRule

def _cidr_covers(a:str | None, b:str| None)-> bool:
    if a is None or b is None:
        return False
    if a in ("*", "Internet","0.0.0.0/0"):
        return True
    if a == b:
        return True
    try:
        net_a = ipaddress.ip_network(a, strict=False)
        net_b = ipaddress.ip_network(b, strict=False)
        return net_a.supernet_of(net_b)
    except ValueError:
        return False

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


def _port_covers(a:str | None, b:str| None)-> bool:
    if a is None or b is None:
        return False
    if a == "*":
        return True
    if a == b:
        return True
    a_ports = flatten_ports(a)
    b_ports = flatten_ports(b)
    return b_ports.issubset(a_ports)

def _protocol_covers(a: SecurityProtocol | None, b: SecurityProtocol | None) -> bool:
    if a is None or b is None:
        return False
    if a == SecurityProtocol.ASTERISK:
        return True
    return a == b

def _rule_covers(higher: SecurityRule | None, lower: SecurityRule | None) -> bool:
    if higher is None or lower is None:
        return False        
    return (_protocol_covers(higher.protocol, lower.protocol) and
                _cidr_covers(higher.source_address_prefix, lower.source_address_prefix) and
                _cidr_covers(higher.destination_address_prefix, lower.destination_address_prefix) and   
                _port_covers(higher.destination_port_range, lower.destination_port_range) and
                higher.direction == lower.direction and higher.priority < lower.priority)

def detect_shadowing(nsg:NetworkSecurityGroup):
    results: list[CheckResult] = []
    rules : list[SecurityRule] = sorted(nsg.security_rules, key=lambda r: r.priority)
    for i in range(len(rules)):
        for j in range(i+1, len(rules)):
            if _rule_covers(rules[i], rules[j]) and rules[i].access != rules[j].access:
                results.append(CheckResult(
                   control_id="ANOMALY",
                    status="fail",
                    severity="Medium",
                    nsg_name=nsg.name,
                    rule_name=rules[j].name,
                    evidence="Rule '{}' is shadowed by rule '{}'".format(rules[j].name, rules[i].name)
                ))

    return results

def run_anomaly_detection(nsgs: list[NetworkSecurityGroup]) -> list[CheckResult]:
    results: list[CheckResult] = []
    for nsg in nsgs:
        results.extend(detect_shadowing(nsg))
        results.extend(detect_redundancy(nsg))
    return results

def detect_redundancy(nsg:NetworkSecurityGroup):
    results: list[CheckResult] = []
    rules : list[SecurityRule] = sorted(nsg.security_rules, key=lambda r: r.priority)
    for i in range(len(rules)):
        for j in range(i+1, len(rules)):
            if _rule_covers(rules[i], rules[j]) and rules[i].access == rules[j].access:
                results.append(CheckResult(
                   control_id="ANOMALY",
                    status="fail",
                    severity="Low",
                    nsg_name=nsg.name,
                    rule_name=rules[j].name,
                    evidence="Rule '{}' is redundant — already covered by rule '{}'".format(rules[j].name, rules[i].name)
                ))

    return results

