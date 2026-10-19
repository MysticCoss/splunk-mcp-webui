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
            try:
                result = await server_module.mcp.call_tool(name, args or {})
            except Exception as exc:  # mcp versions that propagate tool errors
                return {"error": str(exc), "raised": True}
            if isinstance(result, tuple):  # mcp 1.x
                content = result[0][0]
                error = getattr(result, "isError", None) or (len(result) > 1 and getattr(result[1], "isError", False))
            else:  # mcp 2.x CallToolResult
                content = result.content[0]
                error = getattr(result, "isError", False)
            try:
                payload = json.loads(content.text)
            except (ValueError, AttributeError):
                payload = {"error": content.text, "isError": bool(error)}
            if error:
                payload.setdefault("isError", True)
            return payload

        tools = await server_module.mcp.list_tools()
        names = sorted(t.name for t in tools)
        print("tools:", names)
        assert names == [
            "splunk_get_index_info",
            "splunk_get_indexes",
            "splunk_get_job_results",
            "splunk_get_metadata",
            "splunk_get_search_job_status",
            "splunk_run_query",
        ], names

        payload = await call("splunk_get_indexes")
        print("splunk_get_indexes ->", payload["total_indexes"], "indexes:", [i["name"] for i in payload["indexes"]])
        assert payload["total_indexes"] == 2

        payload = await call("splunk_run_query", {"query": "index=main error | stats count"})
        print("splunk_run_query ->", payload["result_count"], "rows, sid:", payload["sid"])
        assert payload["result_count"] == 2

        # paginate the finished job by sid without re-running the search
        payload = await call("splunk_get_job_results", {"sid": payload["sid"], "row_limit": 1, "offset": 1})
        print("splunk_get_job_results ->", payload["result_count"], "row at offset", payload["offset"])
        assert payload["result_count"] == 1 and payload["offset"] == 1

        payload = await call("splunk_get_search_job_status", {"sid": "sid_123"})
        print("splunk_get_search_job_status ->", payload["dispatch_state"])
        assert payload["is_done"] is True and payload["result_count"] == 2

        payload = await call("splunk_get_index_info", {"index_name": "main"})
        print("splunk_get_index_info ->", payload["index"]["name"])
        assert payload["index"]["name"] == "main"

        payload = await call("splunk_get_metadata", {"type": "sourcetypes", "index": "*"})
        print("splunk_get_metadata ->", payload["result_count"], "rows")
        assert payload["result_count"] == 2

        payload = await call("splunk_get_index_info", {"index_name": "nope"})
        text = json.dumps(payload)
        assert ("Not found" in text) and (payload.get("isError") is True or payload.get("raised")), payload
        print("missing index -> reported as error:", text[:100])

        print("\nMCP server wiring OK")

    asyncio.run(run())
    httpd.shutdown()
    os.unlink(config_path)


if __name__ == "__main__":
    main()
