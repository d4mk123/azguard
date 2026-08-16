from azure.mgmt.network.models import FlowLog, NetworkWatcher

from azguard.collector import collect_flow_logs_from_azure


def _fake_watcher(name: str, rg: str) -> NetworkWatcher:
    return NetworkWatcher(
        id=f"/subscriptions/0000/resourceGroups/{rg}/providers/Microsoft.Network/networkWatchers/{name}",
        name=name,
        location="eastus",
    )


def _fake_flow_log(name: str, target: str, enabled: bool, days: int) -> FlowLog:
    from azure.mgmt.network.models import RetentionPolicyParameters

    return FlowLog(
        name=name,
        target_resource_id=target,
        enabled=enabled,
        retention_policy=RetentionPolicyParameters(days=days, enabled=bool(days)),
    )


def _fake_client(watchers, logs_by_watcher):
    """logs_by_watcher maps watcher name -> list of FlowLog."""

    class FakeWatchers:
        def list_all(self):
            return watchers

    class FakeFlowLogs:
        def list(self, resource_group_name, network_watcher_name):
            return logs_by_watcher.get(network_watcher_name, [])

    class FakeClient:
        def __init__(self):
            self.network_watchers = FakeWatchers()
            self.flow_logs = FakeFlowLogs()

    return FakeClient()


def _install_fake_client(monkeypatch, client):
    monkeypatch.setattr(
        "azure.identity.DefaultAzureCredential", lambda *a, **k: object()
    )
    monkeypatch.setattr(
        "azure.mgmt.network.NetworkManagementClient",
        lambda cred, sub: client,
    )


def test_collect_flow_logs_from_azure_parses_watchers_and_logs(monkeypatch):
    watcher = _fake_watcher("watcher-eastus", "rg1")
    flow1 = _fake_flow_log(
        "FlowLog-a",
        "/subscriptions/0000/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg-a",
        True,
        90,
    )
    flow2 = _fake_flow_log(
        "FlowLog-b",
        "/subscriptions/0000/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg-b",
        False,
        0,
    )

    client = _fake_client([watcher], {"watcher-eastus": [flow1, flow2]})
    _install_fake_client(monkeypatch, client)

    result = collect_flow_logs_from_azure("sub-123")

    assert len(result) == 2
    assert result[0].name == "FlowLog-a"
    assert result[0].enabled is True
    assert result[0].retention_policy.days == 90
    assert "networkSecurityGroups/nsg-a" in result[0].target_resource_id
    assert result[1].enabled is False


def test_collect_flow_logs_from_azure_skips_watcher_without_rg(monkeypatch):
    watcher_no_rg = NetworkWatcher(id="not-an-arm-id", name="orphan", location="eastus")
    flow = _fake_flow_log(
        "FlowLog-c",
        "/subscriptions/0000/resourceGroups/rg2/providers/Microsoft.Network/networkSecurityGroups/nsg-c",
        True,
        90,
    )

    client = _fake_client([watcher_no_rg], {"orphan": [flow]})
    _install_fake_client(monkeypatch, client)

    result = collect_flow_logs_from_azure("sub-123")

    assert result == []


def test_collect_flow_logs_from_azure_empty_subscription(monkeypatch):
    _install_fake_client(monkeypatch, _fake_client([], {}))

    result = collect_flow_logs_from_azure("sub-123")

    assert result == []
