"""Tests for strict config loading: validation, env overrides, fail-loud."""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from splunk_mcp_webui.config import ConfigError, load_config

RESULTS = []


def check(name, condition):
    RESULTS.append((name, bool(condition)))
    print("[{}] {}".format("PASS" if condition else "FAIL", name))


def write_cfg(data):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    handle.write(json.dumps(data) if isinstance(data, dict) else data)
    handle.close()
    return handle.name


def with_env(name, value, fn):
    old = os.environ.get(name)
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value
    try:
        return fn()
    finally:
        if old is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old


VALID = {"splunk_url": "https://splunk.example.com", "username": "u", "password": "p"}


def main():
    # valid config + defaults
    path = write_cfg(VALID)
    with_env("SPLUNK_MCP_CONFIG", path, lambda: load_config())  # smoke
    cfg = with_env("SPLUNK_MCP_CONFIG", path, load_config)
    check("defaults applied", cfg["read_only"] is True and cfg["verify_ssl"] is False and cfg["max_raw_chars"] == 1000)
    check("explicit config path used", cfg["config_path"] == path)
    os.unlink(path)

    # unknown keys rejected
    path = write_cfg({**VALID, "verifySSL": "true"})
    try:
        with_env("SPLUNK_MCP_CONFIG", path, load_config)
        check("unknown key rejected", False)
    except ConfigError as exc:
        check("unknown key rejected", "verifySSL" in str(exc))
    os.unlink(path)

    # wrong value types rejected
    for key, value in [("request_timeout", "fast"), ("default_row_limit", 0), ("poll_interval", -1)]:
        path = write_cfg({**VALID, key: value})
        try:
            with_env("SPLUNK_MCP_CONFIG", path, load_config)
            check("invalid {} rejected".format(key), False)
        except ConfigError:
            check("invalid {} rejected".format(key), True)
        os.unlink(path)

    # string booleans parsed properly ("false" must NOT become True)
    path = write_cfg({**VALID, "read_only": "false", "verify_ssl": "true"})
    cfg = with_env("SPLUNK_MCP_CONFIG", path, load_config)
    check("string booleans parsed", cfg["read_only"] is False and cfg["verify_ssl"] is True)
    os.unlink(path)

    # CA bundle path accepted
    path = write_cfg({**VALID, "verify_ssl": "/etc/ssl/corp-ca.pem"})
    cfg = with_env("SPLUNK_MCP_CONFIG", path, load_config)
    check("CA bundle path accepted", cfg["verify_ssl"] == "/etc/ssl/corp-ca.pem")
    os.unlink(path)

    # invalid JSON with explicit config path must fail loudly (no fallback)
    path = write_cfg("{not json")
    try:
        with_env("SPLUNK_MCP_CONFIG", path, load_config)
        check("broken JSON raises", False)
    except ConfigError as exc:
        check("broken JSON raises", "not valid JSON" in str(exc))
    os.unlink(path)

    # missing required key
    path = write_cfg({"splunk_url": "https://x"})
    try:
        with_env("SPLUNK_MCP_CONFIG", path, load_config)
        check("missing keys raise", False)
    except ConfigError as exc:
        check("missing keys raise", "username" in str(exc))
    os.unlink(path)

    # environment overrides fill credentials without a file
    def env_only():
        os.environ["SPLUNK_URL"] = "https://splunk-env.example.com"
        os.environ["SPLUNK_USERNAME"] = "envuser"
        os.environ["SPLUNK_PASSWORD"] = "envpass"
        try:
            return load_config()
        finally:
            for name in ("SPLUNK_URL", "SPLUNK_USERNAME", "SPLUNK_PASSWORD"):
                os.environ.pop(name, None)

    cfg = with_env("SPLUNK_MCP_CONFIG", None, env_only)
    check(
        "env-only credentials work",
        cfg["splunk_url"] == "https://splunk-env.example.com" and cfg["username"] == "envuser",
    )

    # env overrides file values
    path = write_cfg(VALID)
    cfg = with_env("SPLUNK_MCP_CONFIG", path, lambda: (
        os.environ.__setitem__("SPLUNK_PASSWORD", "envpass"),
        load_config(),
    )[1])
    check("env overrides file", cfg["password"] == "envpass")
    os.environ.pop("SPLUNK_PASSWORD", None)
    os.unlink(path)

    failed = [name for name, ok in RESULTS if not ok]
    print("\n{}/{} tests passed".format(len(RESULTS) - len(failed), len(RESULTS)))
    if failed:
        print("FAILED:", failed)
        sys.exit(1)


if __name__ == "__main__":
    main()
