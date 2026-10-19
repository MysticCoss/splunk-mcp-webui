"""Splunk Web client.

Connects to Splunk through the Web UI port (default 8000) instead of the
splunkd management port (8089). Authentication is performed against
``/{locale}/account/login`` and every subsequent call goes through the
splunkweb proxy ``/{locale}/splunkd/__raw/services/...`` using the session
cookie issued by Splunk Web.
"""

import json
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional

import requests
import urllib3

from .config import ConfigError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_FORM_KEY_PATTERNS = (
    re.compile(r'"cval"\s*:\s*"([0-9a-fA-F]+)"'),
    re.compile(r"'cval'\s*:\s*'([0-9a-fA-F]+)'"),
    re.compile(r'name="cval"\s+value="([^"]+)"'),
    re.compile(r'name="csrf_token"\s+value="([^"]+)"'),
)

# Commands that may start a search pipeline without a leading ``search``
# (source: official splunk-mcp-server generating_commands.json).
_GENERATING_COMMANDS = frozenset({
    "datamodel", "dbinspect", "eventcount", "from", "inputcsv", "inputlookup",
    "loadjob", "metadata", "pivot", "rest", "savedsearch", "search", "tstats",
    "mstats", "mcatalog", "makeresults", "input", "summarize", "collect",
})

_LOCALE_RE = re.compile(r"^https?://[^/]+/([A-Za-z]{2,3}-[A-Za-z]{2,3})$")
_SCHEME_RE = re.compile(r"^(https?)://", re.IGNORECASE)


class SplunkWebError(Exception):
    """Generic error raised for Splunk Web failures."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class SplunkAuthError(SplunkWebError):
    pass


class SplunkWebClient:
    def __init__(
        self,
        splunk_url: str,
        username: str,
        password: str,
        locale: str = "en-US",
        verify_ssl: bool = False,
        request_timeout: float = 60.0,
        search_timeout: float = 300.0,
        poll_interval: float = 1.0,
        default_row_limit: int = 100,
        max_row_limit: int = 1000,
    ):
        base_url = splunk_url.strip().rstrip("/")
        if not _SCHEME_RE.match(base_url):
            base_url = "https://" + base_url

        locale_match = _LOCALE_RE.match(base_url)
        if locale_match:
            self.locale = locale_match.group(1)
            base_url = base_url[: -(len(self.locale) + 1)]
        else:
            self.locale = (locale or "en-US").strip("/")

        self.base_url = base_url
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.request_timeout = float(request_timeout)
        self.search_timeout = float(search_timeout)
        self.poll_interval = max(0.2, float(poll_interval))
        self.default_row_limit = int(default_row_limit)
        self.max_row_limit = int(max_row_limit)

        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.form_key: Optional[str] = None
        self._logged_in = False

    # ------------------------------------------------------------------ #
    # URL helpers
    # ------------------------------------------------------------------ #
    def _web_url(self, path: str) -> str:
        return "{}/{}/{}".format(self.base_url, self.locale, path.lstrip("/"))

    def _proxy_url(self, path: str) -> str:
        return "{}/{}/splunkd/__raw/{}".format(self.base_url, self.locale, path.lstrip("/"))

    # ------------------------------------------------------------------ #
    # Authentication
    # ------------------------------------------------------------------ #
    def _extract_form_key(self, html: str) -> Optional[str]:
        for pattern in _FORM_KEY_PATTERNS:
            match = pattern.search(html)
            if match:
                return match.group(1)
        return None

    def login(self, force: bool = False) -> None:
        if self._logged_in and not force:
            return

        self.session.cookies.clear()
        self.form_key = None

        # Step 1: fetch the login page to obtain pre-auth cookies and the
        # CSRF token embedded in the login form (older Splunk versions).
        # ``loginType=splunk`` forces the local-credential form on instances
        # that would otherwise redirect to a SAML/SSO provider (e.g. Azure AD).
        try:
            pre = self.session.get(
                self._web_url("account/login?loginType=splunk"),
                timeout=self.request_timeout,
                allow_redirects=True,
            )
        except requests.exceptions.SSLError:
            # Self-signed / TLS trouble on https: fall back to http
            self.base_url = re.sub(r"^https://", "http://", self.base_url, flags=re.IGNORECASE)
            pre = self.session.get(
                self._web_url("account/login?loginType=splunk"),
                timeout=self.request_timeout,
                allow_redirects=True,
            )

        login_form_key = self._extract_form_key(pre.text)
        if not login_form_key:
            # Newer Splunk versions deliver the CSRF value as a cookie instead
            # of embedding it in the login form HTML.
            login_form_key = self.session.cookies.get("cval")

        # Step 2: submit credentials like the web login form does.
        data: Dict[str, str] = {"username": self.username, "password": self.password}
        if login_form_key:
            data["cval"] = login_form_key

        response = self.session.post(
            self._web_url("account/login"),
            data=data,
            timeout=self.request_timeout,
            allow_redirects=True,
        )

        body_lower = response.text.lower()
        if response.status_code in (401, 403) or "login failed" in body_lower:
            raise SplunkAuthError(
                "Splunk Web login failed for user '{}': invalid username or password "
                "(HTTP {})".format(self.username, response.status_code),
                status_code=response.status_code,
            )

        has_session_cookie = any(name.lower().startswith("splunkd") for name in self.session.cookies.keys())
        if not has_session_cookie:
            raise SplunkAuthError(
                "Splunk Web login did not produce a session cookie. Is '{}' a valid "
                "Splunk Web endpoint? (HTTP {})".format(self.base_url, response.status_code),
                status_code=response.status_code,
            )

        # Step 3: resolve the form key (cval) required for proxied POSTs.
        self.form_key = self._extract_form_key(response.text)
        if not self.form_key:
            # Modern Splunk issues a post-login CSRF cookie named
            # ``splunkweb_csrf_token_<port>``; its value is the form key.
            for name in self.session.cookies.keys():
                if name.lower().startswith("splunkweb_csrf_token"):
                    self.form_key = self.session.cookies.get(name)
                    break
        if not self.form_key:
            try:
                cfg = self.session.get(
                    self._web_url("config"),
                    timeout=self.request_timeout,
                )
                self.form_key = self._extract_form_key(cfg.text)
            except requests.RequestException:
                self.form_key = None
        if not self.form_key:
            # Last resort: the cval cookie stays valid after login and is
            # accepted as the form key by the splunkd proxy.
            self.form_key = self.session.cookies.get("cval")

        self._logged_in = True

    # ------------------------------------------------------------------ #
    # Low level proxy access
    # ------------------------------------------------------------------ #
    def _headers(self, form_data: bool) -> Dict[str, str]:
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "X-Splunk-Client": "splunk-mcp-webui",
        }
        if form_data:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if self.form_key:
            headers["X-Splunk-Form-Key"] = self.form_key
        return headers

    def _proxy_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        retried: bool = False,
    ) -> Dict[str, Any]:
        self.login()
        url = self._proxy_url(path)
        response = self.session.request(
            method,
            url,
            params=params,
            data=data,
            headers=self._headers(form_data=data is not None),
            timeout=timeout or self.request_timeout,
            allow_redirects=False,
        )

        if response.status_code in (401, 403) and not retried:
            # Session expired or CSRF token rotated: re-login once and retry.
            self.login(force=True)
            return self._proxy_request(method, path, params, data, timeout, retried=True)

        if response.status_code == 302 or response.status_code == 303:
            # splunkweb redirects to the login page when the session is gone
            if not retried:
                self.login(force=True)
                return self._proxy_request(method, path, params, data, timeout, retried=True)
            raise SplunkAuthError("Splunk Web session could not be established", status_code=302)

        if response.status_code == 404:
            raise SplunkWebError("Not found: " + path, status_code=404)

        if response.status_code >= 400:
            raise SplunkWebError(
                self._error_message(response, path),
                status_code=response.status_code,
            )

        try:
            return response.json()
        except ValueError as exc:
            raise SplunkWebError(
                "Splunk returned non-JSON data for {} (HTTP {}): {}".format(
                    path, response.status_code, response.text[:200]
                )
            ) from exc

    @staticmethod
    def _error_message(response: requests.Response, path: str) -> str:
        try:
            payload = response.json()
            messages = payload.get("messages") or []
            details = "; ".join(
                str(m.get("text", m)) for m in messages if isinstance(m, dict)
            )
            if details:
                return "Splunk error on '{}' (HTTP {}): {}".format(path, response.status_code, details)
        except ValueError:
            pass
        text = response.text[:300].replace("\n", " ")
        if "login" in text.lower() or response.status_code in (401, 403):
            return "Splunk Web refused the request on '{}' (HTTP {}). Check credentials.".format(
                path, response.status_code
            )
        return "Splunk error on '{}' (HTTP {}): {}".format(path, response.status_code, text)

    # ------------------------------------------------------------------ #
    # Search job execution
    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalize_query(query: str) -> str:
        """splunkd's REST endpoint requires an explicit generating command:
        a query like ``index=* ...`` is rejected with ``Unknown search
        command 'index'`` unless prefixed with ``search``."""
        tokens = query.split(None, 1)
        if not tokens:
            return query
        first = tokens[0].lower()
        if first == "|" or first.startswith("|") or first in _GENERATING_COMMANDS:
            return query
        return "search " + query

    def run_search(
        self,
        query: str,
        earliest_time: Optional[str] = None,
        latest_time: Optional[str] = None,
        row_limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        query = (query or "").strip()
        if not query:
            raise SplunkWebError("Query must not be empty")
        query = self._normalize_query(query)

        row_limit = self.default_row_limit if row_limit is None else int(row_limit)
        row_limit = max(1, min(row_limit, self.max_row_limit))

        data: Dict[str, Any] = {"search": query, "exec_mode": "normal", "output_mode": "json"}
        if earliest_time:
            data["earliest_time"] = earliest_time
        if latest_time:
            data["latest_time"] = latest_time

        created = self._proxy_request("POST", "services/search/jobs", data=data, timeout=self.search_timeout)
        sid = created.get("sid")
        if not sid:
            raise SplunkWebError("Splunk did not return a search id: " + json.dumps(created)[:300])

        job_info = self._wait_for_job(sid)

        state = job_info.get("dispatchState", "")
        if state == "FAILED":
            messages = self._job_messages(job_info)
            raise SplunkWebError(
                "Search failed (sid={}): {}".format(sid, messages or "unknown error")
            )

        result_count = int(job_info.get("resultCount") or 0)
        results, fields = self._fetch_results(sid, row_limit)

        output: Dict[str, Any] = {
            "sid": sid,
            "results": results,
            "result_count": len(results),
            "total_result_count": result_count,
            "fields": fields,
        }
        messages = self._job_messages(job_info)
        if messages:
            output["messages"] = messages
        if result_count > len(results):
            output["truncated"] = True
            output["note"] = (
                "Showing {} of {} results. Narrow the time range or aggregate the "
                "query (e.g. with stats) to see more.".format(len(results), result_count)
            )
        if job_info.get("runDuration"):
            output["run_duration_seconds"] = round(float(job_info["runDuration"]), 3)
        return output

    def _wait_for_job(self, sid: str) -> Dict[str, Any]:
        deadline = time.monotonic() + self.search_timeout
        last_state: Dict[str, Any] = {}
        while time.monotonic() < deadline:
            payload = self._proxy_request(
                "GET",
                "services/search/jobs/{}".format(sid),
                params={"output_mode": "json"},
            )
            entries = payload.get("entry") or []
            if entries:
                last_state = (entries[0].get("content") or {}).copy()
                last_state.setdefault("name", entries[0].get("name"))
                state = last_state.get("dispatchState", "")
                if last_state.get("isDone") in (1, "1", True):
                    return last_state
                if state in ("FAILED",):
                    return last_state
            time.sleep(self.poll_interval)
        last_state["dispatchState"] = last_state.get("dispatchState", "TIMEOUT")
        return last_state

    @staticmethod
    def _job_messages(job_info: Dict[str, Any]) -> List[str]:
        messages = job_info.get("messages") or []
        cleaned = []
        for msg in messages:
            if isinstance(msg, dict):
                cleaned.append("{}: {}".format(msg.get("type", "info"), msg.get("text", "")))
            else:
                cleaned.append(str(msg))
        return cleaned

    def _fetch_results(self, sid: str, row_limit: int):
        payload = self._proxy_request(
            "GET",
            "services/search/jobs/{}/results".format(sid),
            params={"output_mode": "json", "count": row_limit, "offset": 0},
            timeout=self.search_timeout,
        )
        return payload.get("results", []), payload.get("fields", [])

    # ------------------------------------------------------------------ #
    # Tools
    # ------------------------------------------------------------------ #
    @staticmethod
    def _flatten_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
        content = entry.get("content") or {}
        flat = {"name": entry.get("name")}
        flat.update(content)
        return flat

    def get_indexes(self, offset: int = 0, count: Optional[int] = None) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "output_mode": "json",
            "datatype": "all",
            "count": 0,
            "offset": 0,
        }
        payload = self._proxy_request("GET", "servicesNS/-/-/data/indexes", params=params)
        entries = payload.get("entry") or []
        indexes = [self._flatten_entry(e) for e in entries]
        indexes.sort(key=lambda item: (item.get("name") or "").lower())
        indexes = [i for i in indexes if not (i.get("name") or "").startswith("__")]

        total = len(indexes)
        offset = max(0, int(offset or 0))
        if count is not None:
            count = max(1, int(count))
        else:
            count = self.max_row_limit
        page = indexes[offset : offset + count]

        return {
            "indexes": page,
            "total_indexes": total,
            "offset": offset,
            "count": len(page),
            "truncated": offset + len(page) < total,
        }

    def get_index_info(self, index_name: str) -> Dict[str, Any]:
        index_name = (index_name or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]+", index_name):
            raise SplunkWebError(
                "Index name may only contain letters, numbers, underscores and hyphens"
            )
        payload = self._proxy_request(
            "GET",
            "servicesNS/-/-/data/indexes/{}".format(index_name),
            params={"output_mode": "json"},
        )
        entries = payload.get("entry") or []
        if not entries:
            raise SplunkWebError("Index '{}' was not found or is not accessible".format(index_name), status_code=404)
        return {"index": self._flatten_entry(entries[0])}

    def get_metadata(
        self,
        metadata_type: str,
        index: str = "*",
        earliest_time: Optional[str] = None,
        latest_time: Optional[str] = None,
        row_limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        metadata_type = (metadata_type or "").strip().lower()
        if metadata_type not in ("hosts", "sources", "sourcetypes"):
            raise SplunkWebError("Metadata type must be one of: hosts, sources, sourcetypes")
        index = (index or "*").strip() or "*"
        if not re.fullmatch(r"[A-Za-z0-9_*-]+", index):
            raise SplunkWebError(
                "Index pattern may only contain letters, numbers, underscore, dash and * wildcard"
            )

        query = (
            "| metadata type={} index={} | eval firstTimeIso=if(isnull(firstTime) OR firstTime='', "
            "'Never', strftime(firstTime, \"%Y-%m-%dT%H:%M:%SZ\")), "
            "lastTimeIso=if(isnull(lastTime) OR lastTime='', 'Never', strftime(lastTime, "
            "\"%Y-%m-%dT%H:%M:%SZ\")), recentTimeIso=if(isnull(recentTime) OR recentTime='', "
            "'Never', strftime(recentTime, \"%Y-%m-%dT%H:%M:%SZ\"))".format(metadata_type, index)
        )
        return self.run_search(
            query,
            earliest_time=earliest_time,
            latest_time=latest_time,
            row_limit=row_limit,
        )


def client_from_config() -> SplunkWebClient:
    from .config import load_config

    config = load_config()
    try:
        return SplunkWebClient(
            splunk_url=config["splunk_url"],
            username=config["username"],
            password=config["password"],
            locale=config.get("locale", "en-US"),
            verify_ssl=bool(config.get("verify_ssl", False)),
            request_timeout=config.get("request_timeout", 60.0),
            search_timeout=config.get("search_timeout", 300.0),
            poll_interval=config.get("poll_interval", 1.0),
            default_row_limit=config.get("default_row_limit", 100),
            max_row_limit=config.get("max_row_limit", 1000),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigError("Invalid value in config file: {}".format(exc)) from exc
