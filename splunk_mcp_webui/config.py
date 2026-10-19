import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

REQUIRED_KEYS = ("splunk_url", "username", "password")

ALLOWED_KEYS = frozenset({
    "splunk_url", "username", "password",
    "locale", "verify_ssl", "read_only", "max_raw_chars",
    "request_timeout", "search_timeout", "poll_interval",
    "default_row_limit", "max_row_limit",
})

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


def _candidate_paths() -> List[Path]:
    """Paths searched for config.json. When SPLUNK_MCP_CONFIG is set, that
    file is the ONLY candidate — a broken file must fail loudly instead of
    silently falling back to another one or generic defaults."""
    env = os.environ.get("SPLUNK_MCP_CONFIG")
    if env:
        return [Path(env)]
    return [
        Path(__file__).resolve().parent.parent / "config.json",
        Path.home() / ".splunk-mcp" / "config.json",
    ]


def _bool_value(value: Any, key: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "1", "yes", "on"):
            return True
        if low in ("false", "0", "no", "off"):
            return False
    raise ConfigError("Config key '{}' must be a boolean (true/false), got: {!r}".format(key, value))


def _number_value(value: Any, key: str, minimum: float, maximum: Optional[float] = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError("Config key '{}' must be a number, got: {!r}".format(key, value))
    if value < minimum:
        raise ConfigError("Config key '{}' must be >= {}, got: {!r}".format(key, minimum, value))
    if maximum is not None and value > maximum:
        raise ConfigError("Config key '{}' must be <= {}, got: {!r}".format(key, maximum, value))
    return float(value)


def _validate(raw: Dict[str, Any], path: str) -> Dict[str, Any]:
    """Structural/type validation only — required-key presence is checked
    after environment overrides are applied, so credentials may come from
    either the file or the environment."""
    if not isinstance(raw, dict):
        raise ConfigError("Config file '{}' must contain a JSON object".format(path))

    unknown = sorted(set(raw) - ALLOWED_KEYS)
    if unknown:
        raise ConfigError(
            "Config file '{}' has unknown keys: {}. Allowed keys: {}".format(
                path, ", ".join(unknown), ", ".join(sorted(ALLOWED_KEYS))
            )
        )

    merged = dict(DEFAULTS)
    for key, value in raw.items():
        if value is not None:
            merged[key] = value

    # verify_ssl: boolean, a boolean-like string, or a CA bundle file path.
    verify = merged["verify_ssl"]
    if isinstance(verify, str):
        low = verify.strip().lower()
        if low in ("true", "false", "1", "0", "yes", "no", "on", "off"):
            merged["verify_ssl"] = _bool_value(verify, "verify_ssl")
        elif verify.strip():
            bundle = verify.strip()
            if not Path(bundle).is_file():
                raise ConfigError(
                    "Config key 'verify_ssl' points to a CA bundle that does not exist: {}".format(bundle)
                )
            merged["verify_ssl"] = bundle
        else:
            raise ConfigError("Config key 'verify_ssl' must be true, false or a CA bundle path")
    else:
        merged["verify_ssl"] = _bool_value(verify, "verify_ssl")

    merged["read_only"] = _bool_value(merged["read_only"], "read_only")
    merged["request_timeout"] = _number_value(merged["request_timeout"], "request_timeout", minimum=1.0)
    merged["search_timeout"] = _number_value(merged["search_timeout"], "search_timeout", minimum=1.0)
    merged["poll_interval"] = _number_value(merged["poll_interval"], "poll_interval", minimum=0.05)
    merged["default_row_limit"] = int(_number_value(merged["default_row_limit"], "default_row_limit", minimum=1))
    merged["max_row_limit"] = int(_number_value(merged["max_row_limit"], "max_row_limit", minimum=1))
    merged["max_raw_chars"] = int(_number_value(merged["max_raw_chars"], "max_raw_chars", minimum=0))

    return merged


def _apply_env_overrides(config: Dict[str, Any]) -> None:
    """Environment variables override file values, so credentials can be
    provisioned without storing the password on disk. Passwords are kept
    verbatim (no stripping)."""
    env_map = {
        "SPLUNK_URL": ("splunk_url", True),
        "SPLUNK_USERNAME": ("username", True),
        "SPLUNK_PASSWORD": ("password", False),
    }
    for env_name, (key, strip) in env_map.items():
        value = os.environ.get(env_name)
        if value:
            config[key] = value.strip() if strip else value


def _check_required(config: Dict[str, Any]) -> None:
    missing = [key for key in REQUIRED_KEYS if not str(config.get(key, "")).strip()]
    if missing:
        raise ConfigError(
            "Config is missing required keys: {} "
            "(provide them in config.json or via SPLUNK_URL / SPLUNK_USERNAME / SPLUNK_PASSWORD)".format(
                ", ".join(missing)
            )
        )


def load_config() -> Dict[str, Any]:
    candidates = _candidate_paths()
    explicit_only = bool(os.environ.get("SPLUNK_MCP_CONFIG"))
    last_error: Optional[ConfigError] = None
    for path in candidates:
        try:
            if not path.is_file():
                continue
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            config = _validate(raw, str(path))
            config["config_path"] = str(path)
            _apply_env_overrides(config)
            _check_required(config)
            return config
        except ConfigError:
            # Fail loudly — never silently fall back to another file or to
            # generic defaults when an explicitly chosen file is broken.
            raise
        except json.JSONDecodeError as exc:
            last_error = ConfigError("Config file '{}' is not valid JSON: {}".format(path, exc))
            if explicit_only:
                raise last_error

    config: Dict[str, Any] = dict(DEFAULTS)
    _apply_env_overrides(config)
    try:
        _check_required(config)
    except ConfigError:
        if last_error is not None:
            raise last_error
        searched = ", ".join(str(p) for p in candidates)
        hint = "" if explicit_only else " (or set SPLUNK_URL / SPLUNK_USERNAME / SPLUNK_PASSWORD environment variables)"
        raise ConfigError(
            "No usable config found. Create 'config.json' with keys: splunk_url, username, password{}. Searched: {}".format(
                hint, searched
            )
        )
    return config
