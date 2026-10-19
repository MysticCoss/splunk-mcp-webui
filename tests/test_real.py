"""Test connection to your real Splunk Web instance using config.json.

Usage: python tests\\test_real.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from splunk_mcp_webui.client import SplunkAuthError, SplunkWebError, client_from_config


def main():
    client = client_from_config()
    print("Splunk Web:", client.base_url, "| locale:", client.locale)

    try:
        client.login()
    except SplunkAuthError as exc:
        print("LOGIN FAILED:", exc)
        sys.exit(1)
    print("Login OK  (session cookie + form key)")

    for name, fn in [
        ("splunk_get_indexes", lambda: client.get_indexes()),
        ("splunk_get_index_info", lambda: client.get_index_info("main")),
        ("splunk_get_metadata", lambda: client.get_metadata("hosts", "*", "-1h")),
        ("splunk_run_query", lambda: client.run_search("index=_internal | stats count", "-1h")),
    ]:
        try:
            out = fn()
            if name == "splunk_get_indexes":
                print(name, "-> OK,", out["total_indexes"], "indexes:", [i["name"] for i in out["indexes"]][:10])
            elif name == "splunk_get_index_info":
                print(name, "-> OK (index: %s)" % out["index"]["name"])
            else:
                rows = out.get("results", [])
                print(name, "-> OK,", len(rows), "rows")
        except SplunkWebError as exc:
            print(name, "-> FAILED:", exc)

    print("\nDone. All tools that report OK are ready to use via MCP.")


if __name__ == "__main__":
    main()
