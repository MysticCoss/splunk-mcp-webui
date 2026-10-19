"""Splunk MCP WebUI - MCP server that talks to Splunk through the Web UI.

Only the client is imported eagerly so that using ``SplunkWebClient``
standalone does not require the ``mcp`` package. The server entry point
(``python -m splunk_mcp_webui``) imports ``splunk_mcp_webui.server`` itself.
"""

from .client import SplunkAuthError, SplunkWebClient, SplunkWebError

__all__ = ["SplunkAuthError", "SplunkWebClient", "SplunkWebError"]
__version__ = "1.1.0"
