import functools
import json
from typing import Annotated, Any, Literal, Optional

import requests
from pydantic import Field

try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.exceptions import ToolError
except ImportError:  # mcp 2.x renamed FastMCP -> MCPServer
    from mcp.server.mcpserver import MCPServer as FastMCP
    from mcp.server.mcpserver.exceptions import ToolError

from .client import SplunkWebClient, SplunkWebError, client_from_config
from .config import ConfigError

mcp = FastMCP(
    name="splunk-webui",
    instructions=(
        "Splunk MCP server that connects through the Splunk Web UI. "
        "Credentials and URL are read from config.json; use splunk_get_indexes and "
        "splunk_get_metadata to discover data before writing SPL with splunk_run_query. "
        "Data-mutating SPL is blocked by default (read_only=true in config.json). "
        "Results are paginated: when truncated=true, fetch the next page with "
        "splunk_run_query offset=next_offset, or reuse the sid with splunk_get_job_results."
    ),
)

_client: Optional[SplunkWebClient] = None


def _get_client() -> SplunkWebClient:
    global _client
    if _client is None:
        _client = client_from_config()
    return _client


def _json(data) -> str:
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False, default=str)


def _guarded(fn):
    """Convert expected errors into ToolError so the MCP client receives the
    message as an isError result instead of a swallowed generic failure."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (SplunkWebError, ConfigError, requests.RequestException) as exc:
            payload = {"error": str(exc), "status_code": getattr(exc, "status_code", None)}
            raise ToolError(_json(payload)) from exc

    return wrapper


SplQuery = Annotated[str, Field(min_length=1, max_length=5000, description="Valid SPL query to execute")]
RowLimit = Annotated[Optional[int], Field(ge=1, le=1000, description="Max rows to return; None uses config default")]
Offset = Annotated[int, Field(ge=0, description="Result offset for pagination")]
MaxRawChars = Annotated[
    Optional[int],
    Field(ge=0, description="Max characters per _raw value (0 disables truncation); None uses config default"),
]
Sid = Annotated[str, Field(description="Search job id (sid) returned by splunk_run_query")]


@mcp.tool()
@_guarded
def splunk_run_query(
    query: SplQuery,
    earliest_time: str = "-24h",
    latest_time: str = "now",
    row_limit: RowLimit = None,
    offset: Offset = 0,
    max_raw_chars: MaxRawChars = None,
) -> str:
    """Execute a Splunk search query and return the results. Use this to retrieve log data, perform aggregations, analyze events, and extract insights.

    Args:
        query: Valid SPL query to execute (max 5000 chars).
        earliest_time: Start time for search (e.g., -24h, -1d).
        latest_time: End time for search (e.g., now, -1h). Defaults to now.
        row_limit: Max rows to return (1-1000). None uses config default (default_row_limit, typically 100).
        offset: Result offset. When truncated=true, re-run with offset=next_offset to page through results.
        max_raw_chars: Max characters per _raw value (0 disables truncation). None uses config default.
    """
    return _json(
        _get_client().run_search(
            query,
            earliest_time=earliest_time,
            latest_time=latest_time,
            row_limit=row_limit,
            offset=offset,
            max_raw_chars=max_raw_chars,
        )
    )


@mcp.tool()
@_guarded
def splunk_get_job_results(
    sid: Sid,
    row_limit: RowLimit = None,
    offset: Offset = 0,
    max_raw_chars: MaxRawChars = None,
) -> str:
    """Fetch results from an existing finished search job WITHOUT re-running the search. Use this instead of re-running splunk_run_query when paginating through a large result set.

    Args:
        sid: Search job id returned by splunk_run_query.
        row_limit: Max rows to return (1-1000). None uses config default.
        offset: Result offset for pagination.
        max_raw_chars: Max characters per _raw value (0 disables truncation). None uses config default.
    """
    return _json(
        _get_client().get_job_results(sid, row_limit=row_limit, offset=offset, max_raw_chars=max_raw_chars)
    )


@mcp.tool()
@_guarded
def splunk_get_search_job_status(sid: Sid) -> str:
    """Check the state of a previously created search job (done, running, failed) and its total result count. Useful before fetching results of a long-running job.

    Args:
        sid: Search job id returned by splunk_run_query.
    """
    return _json(_get_client().get_job_status(sid))


@mcp.tool()
@_guarded
def splunk_get_indexes(
    row_limit: RowLimit = None,
    offset: Offset = 0,
    full: bool = False,
) -> str:
    """Get a list of indexes from Splunk. Indexes are data repositories where machine data is stored and organized.

    Args:
        row_limit: Max number of indexes to return (1-1000). None uses config default.
        offset: Offset into the sorted index list.
        full: Return the full index configuration (100+ fields) instead of the compact summary. Only use when needed.
    """
    return _json(_get_client().get_indexes(offset=offset, count=row_limit, full=full))


@mcp.tool()
@_guarded
def splunk_get_index_info(index_name: str) -> str:
    """Get detailed information about a specific Splunk index. Returns comprehensive configuration and status information for the specified index.

    Args:
        index_name: Name of the index to get information about. Only alphanumeric characters, underscores (_) and hyphens (-).
    """
    return _json(_get_client().get_index_info(index_name))


@mcp.tool()
@_guarded
def splunk_get_metadata(
    type: Literal["hosts", "sources", "sourcetypes"],
    index: str = "*",
    earliest_time: str = "-24h",
    latest_time: str = "now",
    row_limit: RowLimit = None,
    offset: Offset = 0,
) -> str:
    """Retrieve metadata about hosts, sources, or sourcetypes across one or more indexes in the selected time window.

    Args:
        type: Metadata category to list: hosts, sources or sourcetypes.
        index: Index name or wildcard pattern (e.g. main, app_*, *).
        earliest_time: Start time for search (e.g., -24h, -1d).
        latest_time: End time for search (e.g., now, -1h). Defaults to now.
        row_limit: Max rows to return (1-1000). None uses config default.
        offset: Result offset for pagination.
    """
    return _json(
        _get_client().get_metadata(
            type,
            index=index,
            earliest_time=earliest_time,
            latest_time=latest_time,
            row_limit=row_limit,
            offset=offset,
        )
    )


def main() -> None:
    import logging
    import sys

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
    except Exception as exc:
        logging.getLogger("splunk_mcp_webui").error("%s", exc)
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    mcp.run()


if __name__ == "__main__":
    main()
