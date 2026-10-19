"""Splunk MCP WebUI - MCP server that talks to Splunk through the Web UI."""

from .client import SplunkAuthError, SplunkWebClient, SplunkWebError
from .server import main

__all__ = ["SplunkAuthError", "SplunkWebClient", "SplunkWebError", "main"]
__version__ = "1.0.0"
