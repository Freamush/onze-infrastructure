import importlib.util
import sys
import types

if importlib.util.find_spec("azure") is None:
    azure = types.ModuleType("azure")
    azure.__path__ = []
    identity = types.ModuleType("azure.identity")
    monitor = types.ModuleType("azure.monitor")
    monitor.__path__ = []
    query = types.ModuleType("azure.monitor.query")
    class StubCredential:
        def __init__(self, *args, **kwargs):
            pass
        def get_token(self, *args):
            return types.SimpleNamespace(token="test-token")
    class StubLogsClient:
        def __init__(self, *args, **kwargs):
            pass
    identity.AzureCliCredential = StubCredential
    identity.DefaultAzureCredential = StubCredential
    query.LogsQueryClient = StubLogsClient
    query.LogsQueryStatus = types.SimpleNamespace(SUCCESS="success", PARTIAL="partial")
    azure.identity = identity
    azure.monitor = monitor
    monitor.query = query
    sys.modules.update({"azure": azure, "azure.identity": identity,
                        "azure.monitor": monitor, "azure.monitor.query": query})
