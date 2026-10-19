import json
import os
from pathlib import Path
from typing import Any, Dict

REQUIRED_KEYS = ("splunk_url", "username", "password")

DEFAULTS: Dict[str, Any] = {
    "locale": "en-US",
    "verify_ssl": False,
    "read_only": True,
    "max_raw_chars": 1000,
    "request_timeout": 60.0,
    "search_timeout": 300.0,
    "poll_interval": 1.0,
    "default_row_limit": 100,
    "max_row_limit": 1000,
}


class ConfigError(Exception):
    pass


def _candidate_paths() -> list:
    paths = []
    env = os.environ.get("SPLUNK_MCP_CONFIG")
    if env:
        paths.append(Path(env))
    paths.append(Path(__file__).resolve().parent.parent / "config.json")
    paths.append(Path.home() / ".splunk-mcp" / "config.json")
    return paths


def load_config() -> Dict[str, Any]:
    last_error = None
    for path in _candidate_paths():
        try:
            if not path.is_file():
                continue
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if not isinstance(raw, dict):
                raise ConfigError(f"Config file '{path}' must contain a JSON object")
            missing = [key for key in REQUIRED_KEYS if not str(raw.get(key, "")).strip()]
            if missing:
                raise ConfigError(
                    f"Config file '{path}' is missing required keys: {', '.join(missing)}"
                )
            config = dict(DEFAULTS)
            config.update({k: v for k, v in raw.items() if v is not None})
            config["config_path"] = str(path)
            return config
        except ConfigError:
            raise
        except json.JSONDecodeError as exc:
            last_error = ConfigError(f"Config file '{path}' is not valid JSON: {exc}")

    searched = ", ".join(str(p) for p in _candidate_paths())
    if last_error:
        raise last_error
    raise ConfigError(
        "No config file found. Create 'config.json' with keys: "
        "splunk_url, username, password. Searched: " + searched
    )
