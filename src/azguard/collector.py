import json
from pathlib import Path
from .models import NSGListResult, FlowLogListResult, NetworkSecurityGroup, FlowLog


def collect_from_file(path: str | Path) -> list[NetworkSecurityGroup]:
    """
    Load NSGs from a JSON file exported via:
        az network nsg list -o json
    """
    with open(path) as f:
        data = json.load(f)

    if isinstance(data, list):
        data = {"value": data}

    result = NSGListResult.model_validate(data)
    return result.value


def collect_from_bytes(data: bytes) -> list[NetworkSecurityGroup]:
    """
    Load NSGs from raw JSON bytes, e.g. a Streamlit file upload.
    Accepts either a bare list or an ARM-style {'value': [...]} payload.
    """
    parsed = json.loads(data)
    if isinstance(parsed, list):
        parsed = {"value": parsed}
    return NSGListResult.model_validate(parsed).value


def collect_from_azure(subscription_id: str) -> list[NetworkSecurityGroup]:
    """
    Load NSGs live from an Azure subscription.
    Requires az login or environment credentials.
    """
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.network import NetworkManagementClient

    credential = DefaultAzureCredential()
    client = NetworkManagementClient(credential, subscription_id)

    raw_nsgs = list(client.network_security_groups.list_all())
    nsg_dicts = [nsg.as_dict() for nsg in raw_nsgs]
    return NSGListResult.model_validate({"value": nsg_dicts}).value


def collect_flow_logs_from_azure(subscription_id: str) -> list[FlowLog]:
    """
    Load flow logs live from an Azure subscription.

    Flow logs are scoped to a Network Watcher (no list_all endpoint), so this
    enumerates all network watchers across regions and lists flow logs per watcher.
    Requires az login or environment credentials.
    """
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.network import NetworkManagementClient

    credential = DefaultAzureCredential()
    client = NetworkManagementClient(credential, subscription_id)

    flow_log_dicts: list[dict] = []
    for watcher in client.network_watchers.list_all():
        watcher_id = watcher.id or ""
        parts = [p for p in watcher_id.split("/") if p]
        if "resourceGroups" not in parts:
            continue
        rg = parts[parts.index("resourceGroups") + 1]
        for flow_log in client.flow_logs.list(rg, watcher.name):
            flow_log_dicts.append(flow_log.as_dict())

    return FlowLogListResult.model_validate({"value": flow_log_dicts}).value


def collect_flow_logs_from_file(path: str | Path) -> list[FlowLog]:
    with open(path) as f:
        data = json.load(f)

    if isinstance(data, list):
        data = {"value": data}

    result = FlowLogListResult.model_validate(data)
    return result.value


def collect_flow_logs_from_bytes(data: bytes) -> list[FlowLog]:
    parsed = json.loads(data)
    if isinstance(parsed, list):
        parsed = {"value": parsed}
    return FlowLogListResult.model_validate(parsed).value
