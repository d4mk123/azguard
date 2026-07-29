from pathlib import Path

from azguard.collector import collect_from_file
from azguard.models import (
    SecurityProtocol,
    SecurityDirection,
    SecurityAccess,
    SecurityRule,
)
from azguard.features import (
    protocol_code,
    direction_code,
    access_code,
    source_scope,
    port_count,
    min_port,
    max_port,
    rule_to_vector,
    build_feature_dataframe,
)

FIXTURES_DIR = Path(__file__).parents[3] / "test-data"


def collect(fixture_name: str):
    return collect_from_file(FIXTURES_DIR / fixture_name)


def test_protocol_code():
    assert protocol_code(SecurityProtocol.TCP) == 1
    assert protocol_code(SecurityProtocol.ASTERISK) == 0
    assert protocol_code(SecurityProtocol.UDP) == 2
    assert protocol_code(None) == 0


def test_direction_code():
    assert direction_code(SecurityDirection.INBOUND) == 0
    assert direction_code(SecurityDirection.OUTBOUND) == 1
    assert direction_code(None) == 0


def test_access_code():
    assert access_code(SecurityAccess.ALLOW) == 1
    assert access_code(SecurityAccess.DENY) == 0
    assert access_code(None) == 1


def test_source_scope():
    assert source_scope("*") == 3
    assert source_scope("Internet") == 3
    assert source_scope("0.0.0.0/0") == 3
    assert source_scope("VirtualNetwork") == 2
    assert source_scope("10.0.0.0/16") == 1
    assert source_scope("10.0.0.1/32") == 0
    assert source_scope(None) == 3
    assert source_scope("AzureLoadBalancer") == 3


def test_port_count():
    assert port_count("*") == 65536
    assert port_count(None) == 65536
    assert port_count("22") == 1
    assert port_count("22,80,443") == 3
    assert port_count("22-24") == 3


def test_min_port():
    assert min_port("*") == 0
    assert min_port(None) == 0
    assert min_port("22") == 22
    assert min_port("80,22") == 22


def test_max_port():
    assert max_port("*") == 65535
    assert max_port(None) == 65535
    assert max_port("22") == 22
    assert max_port("22-80") == 80


def test_rule_to_vector_returns_dict():
    rule = SecurityRule(
        name="test-rule",
        priority=100,
        direction=SecurityDirection.INBOUND,
        access=SecurityAccess.ALLOW,
        protocol=SecurityProtocol.TCP,
        source_address_prefix="10.0.0.0/16",
        destination_port_range="22",
    )
    vec = rule_to_vector(rule)
    assert isinstance(vec, dict)
    assert vec["priority"] == 100
    assert vec["protocol_code"] == 1
    assert vec["port_count"] == 1
    assert len(vec) == 9


def test_build_feature_dataframe_shape():
    nsgs = collect("shadowed-rules.json")
    df = build_feature_dataframe(nsgs[0])
    assert df.shape == (4, 9)


def test_build_feature_dataframe_empty_nsg():
    nsgs = collect("empty-nsg.json")
    df = build_feature_dataframe(nsgs[0])
    assert df.shape == (0, 0)


def test_build_feature_dataframe_large_ruleset():
    nsgs = collect("large-ruleset.json")
    df = build_feature_dataframe(nsgs[0])
    assert df.shape[1] == 9
    assert df.shape[0] > 0
