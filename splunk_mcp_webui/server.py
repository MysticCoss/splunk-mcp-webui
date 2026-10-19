import json
import sys
from typing import Optional

try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP
except ImportError:  # mcp 2.x renamed FastMCP -> MCPServer
    from mcp.server.mcpserver import MCPServer as FastMCP

from .client import SplunkWebError, SplunkWebClient, client_from_config
from .config import ConfigError

mcp = FastMCP(
    name="splunk-webui",
    instructions=(
        "Splunk MCP server that connects through the Splunk Web UI. "
        "Credentials and URL are read from config.json; use splunk_get_indexes and "
        "splunk_get_metadata to discover data before writing SPL with splunk_run_query."
    ),
)

_client: Optional[SplunkWebClient] = None


def _get_client() -> SplunkWebClient:
    global _client
    if _client is None:
        _client = client_from_config()
    return _client


def _json(data) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


@mcp.tool()
def splunk_run_query(
    query: str,
    earliest_time: str = "-24h",
    latest_time: str = "now",
) -> str:
    """Execute a Splunk search query and return the results. Use this to retrieve log data, perform aggregations, analyze events, and extract insights.

    Args:
        query: Valid SPL query to execute.
            Validation: SPL query is required and limited to 5000 characters.
    Args:
        earliest_time: Start time for search (e.g., -24h, -1d).
        latest_time: End time for search (e.g., now, -1h). If omitted, defaults to now.
    """
    try:
        return _json(_get_client().run_search(query, earliest_time, latest_time))
    except SplunkWebError as exc:
        return _json({"error": str(exc), "status_code": exc.status_code})
    except ConfigError as exc:
        return _json({"error": str(exc)})


@mcp.tool()
def splunk_get_indexes(row_limit: int = 1000) -> str:
    """Get a list of indexes from Splunk. Indexes are data repositories where machine data is stored and organized.

    Args:
        row_limit: Maximum number of rows to return (1-1000).
    """
    try:
        return _json(_get_client().get_indexes(offset=0, count=row_limit))
    except SplunkWebError as exc:
        return _json({"error": str(exc), "status_code": exc.status_code})
    except ConfigError as exc:
        return _json({"error": str(exc)})


@mcp.tool()
def splunk_get_index_info(index_name: str) -> str:
    """Get detailed information about a specific Splunk index. Returns comprehensive configuration and status information for the specified index.

    Args:
        index_name: Name of the index to get information about.
            Validation: Index name can only contain alphanumeric characters, underscores (_), and hyphens (-).
    """
    try:
        return _json(_get_client().get_index_info(index_name))
    except SplunkWebError as exc:
        return _json({"error": str(exc), "status_code": exc.status_code})
    except ConfigError as exc:
        return _json({"error": str(exc)})


@mcp.tool()
def splunk_get_metadata(
    type: str,
    index: str = "*",
    earliest_time: str = "-24h",
    latest_time: str = "now",
) -> str:
    """Retrieve metadata about hosts, sources, or sourcetypes across one or more indexes in the selected time window.

    Args:
        type: Metadata category to list (hosts, sources, or sourcetypes).
    Args:
        index: Index name or wildcard pattern (e.g. main, app_*, *).
            Validation: Index pattern may contain letters, numbers, underscore, dash, and * wildcard.
    Args:
        earliest_time: Start time for search (e.g., -24h, -1d).
        latest_time: End time for search (e.g., now, -1h). If omitted, defaults to now.
    """
    try:
        return _json(
            _get_client().get_metadata(type, index=index, earliest_time=earliest_time, latest_time=latest_time)
        )
    except SplunkWebError as exc:
        return _json({"error": str(exc), "status_code": exc.status_code})
    except ConfigError as exc:
        return _json({"error": str(exc)})


def main() -> None:
    import logging

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    try:
        from .config import load_config

        config = load_config()
        logging.getLogger("splunk_mcp_webui").info(
            "Loaded config from %s (Splunk Web: %s)", config["config_path"], config["splunk_url"]
        )
    except ConfigError as exc:
        logging.getLogger("splunk_mcp_webui").error("%s", exc)
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    mcp.run()


if __name__ == "__main__":
    main()
