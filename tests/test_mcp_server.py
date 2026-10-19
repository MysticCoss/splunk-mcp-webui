"""Offline test: exercises the FastMCP/MCPServer tool wiring against the mock Splunk Web server."""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_offline import PASSWORD, USER, start_server

import splunk_mcp_webui.server as server_module


def main():
    httpd = start_server()
    port = httpd.server_address[1]

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as cfg:
        json.dump(
            {
                "splunk_url": "http://127.0.0.1:{}".format(port),
                "username": USER,
                "password": PASSWORD,
                "poll_interval": 0.05,
            },
            cfg,
        )
        config_path = cfg.name

    import os

    os.environ["SPLUNK_MCP_CONFIG"] = config_path
    # ensure a fresh client (config is cached on module import order)
    server_module._client = None

    async def run():
        async def call(name, args=None):
            result = await server_module.mcp.call_tool(name, args or {})
            if isinstance(result, tuple):  # mcp 1.x
                result = result[0][0]
            else:  # mcp 2.x CallToolResult
                result = result.content[0]
            return json.loads(result.text)

        tools = await server_module.mcp.list_tools()
        names = sorted(t.name for t in tools)
        print("tools:", names)
        assert names == [
            "splunk_get_index_info",
            "splunk_get_indexes",
            "splunk_get_metadata",
            "splunk_run_query",
        ], names

        payload = await call("splunk_get_indexes")
        print("splunk_get_indexes ->", payload["total_indexes"], "indexes:", [i["name"] for i in payload["indexes"]])
        assert payload["total_indexes"] == 2

        payload = await call("splunk_run_query", {"query": "index=main error | stats count"})
        print("splunk_run_query ->", payload["result_count"], "rows, sid:", payload["sid"])
        assert payload["result_count"] == 2

        payload = await call("splunk_get_index_info", {"index_name": "main"})
        print("splunk_get_index_info ->", payload["index"]["name"])
        assert payload["index"]["name"] == "main"

        payload = await call("splunk_get_metadata", {"type": "sourcetypes", "index": "*"})
        print("splunk_get_metadata ->", payload["result_count"], "rows")
        assert payload["result_count"] == 2

        payload = await call("splunk_get_index_info", {"index_name": "nope"})
        print("missing index ->", payload)
        assert payload.get("status_code") == 404

        print("\nMCP server wiring OK")

    asyncio.run(run())
    httpd.shutdown()
    os.unlink(config_path)


if __name__ == "__main__":
    main()
