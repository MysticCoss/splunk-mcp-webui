"""Splunk Web client.

Connects to Splunk through the Web UI port (default 8000) instead of the
splunkd management port (8089). Authentication is performed against
``/{locale}/account/login`` and every subsequent call goes through the
splunkweb proxy ``/{locale}/splunkd/__raw/services/...`` using the session
cookie issued by Splunk Web.
"""

import json
import logging
import re
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional

import requests
import urllib3

from .config import ConfigError

logger = logging.getLogger("splunk_mcp_webui.client")

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

# SPL commands that mutate data or hand off control — blocked when the
# read_only config flag is enabled (default). Best-effort: only the first
# command of each search pipeline segment is inspected.
_RESTRICTED_COMMANDS = frozenset({
    "delete", "outputlookup", "outputcsv", "outputtelemetry", "sendemail",
    "sendalert", "summaryindex", "collect", "tscollect", "stash", "script",
    "run", "mcollect", "meventcollect", "dump", "runshellscript", "exec",
})

# Commands that can smuggle arbitrary nested SPL (quoted subsearches, saved
# searches) — a segment-level scan cannot see what they execute, so they are
# blocked outright under read_only.
_OPAQUE_COMMANDS = frozenset({"map", "savedsearch"})

_MACRO_RE = re.compile(r"`[^`]+`")
_REST_PASSWORD_RE = re.compile(r"storage[_/]?password", re.IGNORECASE)
_MAX_GUARD_DEPTH = 3

# Splunk storage-internal bookkeeping fields — pure noise for LLM consumers.
_INTERNAL_RESULT_FIELDS = ("_bkt", "_cd", "_si", "_serial", "_indextime")

_SID_RE = re.compile(r"^[0-9._A-Za-z-]+$")

# Fields kept in the compact (default) index listing; the full flattened
# entry carries 100+ low-level storage settings that waste LLM context.
_COMPACT_INDEX_FIELDS = (
    "name", "datatype", "disabled", "currentDBSizeMB", "totalEventCount",
    "splunk_server", "minTime", "maxTime",
)

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
        max_raw_chars: int = 1000,
        read_only: bool = True,
    ):
        base_url = splunk_url.strip().rstrip("/")
        if not _SCHEME_RE.match(base_url):
            base_url = "https://" + base_url
        self._explicit_scheme = bool(_SCHEME_RE.match(splunk_url.strip()))

        locale_match = _LOCALE_RE.match(base_url)
        if locale_match:
            self.locale = locale_match.group(1)
            base_url = base_url[: -(len(self.locale) + 1)]
        else:
            self.locale = (locale or "en-US").strip("/")

        self.base_url = base_url
        self.username = username
        self.password = password
        # verify_ssl may be a bool or a path to a CA bundle file.
        self.verify_ssl = verify_ssl
        self.request_timeout = float(request_timeout)
        self.search_timeout = float(search_timeout)
        self.poll_interval = max(0.05, float(poll_interval))
        self.default_row_limit = int(default_row_limit)
        self.max_row_limit = int(max_row_limit)
        self.max_raw_chars = max(0, int(max_raw_chars))
        self.read_only = bool(read_only)

        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.form_key: Optional[str] = None
        self._logged_in = False
        # Tool calls may run concurrently in MCP thread pools: guard the
        # session cookie jar and the re-login dance behind a lock. A
        # generation counter lets one thread refresh the session while
        # others simply retry against it.
        self._login_lock = threading.RLock()
        self._session_generation = 0
        self._auth_cooldown_until = 0.0

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
        """Ensure a valid session exists. Thread-safe: concurrent tool calls
        share one session, so re-login is serialized and deduplicated via a
        generation counter. After an authentication failure, further attempts
        are suspended for a cooldown to avoid locking the Splunk account."""
        with self._login_lock:
            if self._logged_in and not force:
                return
            if force and time.monotonic() < self._auth_cooldown_until:
                raise SplunkAuthError(
                    "Authentication for user '{}' is in cooldown after recent failures; "
                    "retry in {}s (avoid locking the account)".format(
                        self.username, round(self._auth_cooldown_until - time.monotonic())
                    )
                )
            self._do_login_locked()

    def _do_login_locked(self) -> None:
        self._logged_in = False
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
        except requests.exceptions.SSLError as exc:
            # Never silently downgrade an explicitly requested https:// to
            # http:// — that would send credentials in plaintext. The plain-
            # hostname fallback below only runs when the user did not specify
            # a scheme and SSL checks are disabled.
            if self._explicit_scheme or self.verify_ssl:
                raise SplunkWebError(
                    "TLS handshake with {} failed: {}. Not falling back to HTTP "
                    "because the URL specified a scheme or SSL verification is on.".format(
                        self.base_url, exc
                    )
                ) from exc
            new_base = re.sub(r"^https://", "http://", self.base_url, flags=re.IGNORECASE)
            logger.warning(
                "TLS handshake failed for %s; falling back to plain HTTP (%s). "
                "Credentials will be sent unencrypted!",
                self.base_url,
                exc,
            )
            self.base_url = new_base
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
            # Suspend further attempts briefly — repeated failures lock the
            # Splunk account (default lockout threshold is small).
            self._auth_cooldown_until = time.monotonic() + 120.0
            reason = "invalid username or password"
            if response.status_code == 403:
                reason = "access denied (account locked, missing privilege or IP restricted)"
            raise SplunkAuthError(
                "Splunk Web login failed for user '{}': {} (HTTP {})".format(
                    self.username, reason, response.status_code
                ),
                status_code=response.status_code,
            )

        has_session_cookie = any(name.lower().startswith("splunkd") for name in self.session.cookies.keys())
        if not has_session_cookie:
            self._auth_cooldown_until = time.monotonic() + 120.0
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

        self._session_generation += 1
        self._auth_cooldown_until = 0.0
        self._logged_in = True
        logger.info("Logged in to %s as '%s' (session generation %d)", self.base_url, self.username, self._session_generation)

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
        generation = self._session_generation
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
            # Session expired or CSRF token rotated: refresh once and retry.
            # If another concurrent call already refreshed the session, skip
            # straight to the retry instead of forcing a second login.
            with self._login_lock:
                if self._session_generation == generation:
                    self._do_login_locked()
            return self._proxy_request(method, path, params, data, timeout, retried=True)

        if response.status_code == 302 or response.status_code == 303:
            # splunkweb redirects to the login page when the session is gone
            if not retried:
                with self._login_lock:
                    if self._session_generation == generation:
                        self._do_login_locked()
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
        if response.status_code == 403:
            return "Splunk Web refused the request on '{}' (HTTP 403). The account lacks the required privilege or capability.".format(
                path
            )
        if "login" in text.lower() or response.status_code == 401:
            return "Splunk Web refused the request on '{}' (HTTP {}). Check credentials.".format(
                path, response.status_code
            )
        return "Splunk error on '{}' (HTTP {}): {}".format(path, response.status_code, text)

    # ------------------------------------------------------------------ #
    # Search job execution
    # ------------------------------------------------------------------ #
    @staticmethod
    def _mask_quoted(query: str) -> str:
        """Replace double-quoted string contents with spaces so ``|`` inside
        quoted values does not confuse pipeline segmentation."""
        out = []
        in_quotes = False
        i = 0
        while i < len(query):
            char = query[i]
            if char == "\\" and in_quotes:
                out.append(" ")
                i += 2
                continue
            if char == '"':
                in_quotes = not in_quotes
                out.append(char)
                i += 1
                continue
            out.append(" " if in_quotes else char)
            i += 1
        return "".join(out)

    def _enforce_read_only(self, query: str) -> None:
        """Best-effort block of data-mutating SPL. Scans every pipeline
        segment (quote-masked), recurses into ``[...]`` subsearches, and
        blocks opaque commands (map/savedsearch) and macros entirely."""
        self._scan_read_only(query, "", 0)

    def _scan_read_only(self, query: str, context: str, depth: int) -> None:
        where = " (in{})".format(context) if context else ""
        masked = self._mask_quoted(query)

        if _MACRO_RE.search(masked):
            raise SplunkWebError(
                "Query blocked by read_only=true: macro expansion `...` is not allowed{}".format(where)
            )

        for segment in masked.split("|"):
            tokens = segment.strip().split(None, 1)
            if not tokens:
                continue
            first = tokens[0].lower()
            if first in _OPAQUE_COMMANDS:
                raise SplunkWebError(
                    "Query blocked by read_only=true: '{}' command can hide nested SPL and is not allowed{}".format(
                        first, where
                    )
                )
            if first in _RESTRICTED_COMMANDS:
                raise SplunkWebError(
                    "Query blocked by read_only=true: '{}' command is not allowed{}. "
                    "Set read_only=false in config.json to permit data-mutating commands.".format(first, where)
                )
            if first == "rest" and _REST_PASSWORD_RE.search(segment):
                raise SplunkWebError(
                    "Query blocked by read_only=true: 'rest' access to stored passwords is not allowed{}".format(where)
                )

        # Subsearches in square brackets execute their own commands.
        if depth < _MAX_GUARD_DEPTH:
            for bracket in re.findall(r"\[([^\[\]]*)\]", masked):
                if bracket.strip():
                    self._scan_read_only(bracket, context + " subsearch", depth + 1)

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
        offset: int = 0,
        max_raw_chars: Optional[int] = None,
    ) -> Dict[str, Any]:
        query = (query or "").strip()
        if not query:
            raise SplunkWebError("Query must not be empty")
        query = self._normalize_query(query)
        # Guard runs on the normalized query so that search TERMS (e.g.
        # "delete user=bob" as a literal term after the implicit `search`
        # command) are not mistaken for pipeline commands.
        if self.read_only:
            self._enforce_read_only(query)

        row_limit = self.default_row_limit if row_limit is None else int(row_limit)
        row_limit = max(1, min(row_limit, self.max_row_limit))
        offset = max(0, int(offset or 0))
        max_raw = self.max_raw_chars if max_raw_chars is None else max(0, int(max_raw_chars))

        data: Dict[str, Any] = {"search": query, "exec_mode": "normal", "output_mode": "json"}
        if earliest_time:
            data["earliest_time"] = earliest_time
        if latest_time:
            data["latest_time"] = latest_time
        # Server-side safety nets: kill the job if it exceeds the wall clock
        # or if the client disappears without cancelling it.
        data["auto_cancel"] = int(self.search_timeout)
        data["max_time"] = int(self.search_timeout)

        created = self._proxy_request("POST", "services/search/jobs", data=data, timeout=self.search_timeout)
        sid = created.get("sid")
        if not sid:
            raise SplunkWebError("Splunk did not return a search id: " + json.dumps(created)[:300])

        job_info = self._wait_for_job(sid)

        state = job_info.get("dispatchState", "")
        if state == "TIMEOUT":
            self._cancel_job(sid)
            raise SplunkWebError(
                "Search timed out after {}s and the job was cancelled (sid={}). "
                "Narrow the time range, add filters, or raise search_timeout in config.json.".format(
                    int(self.search_timeout), sid
                )
            )
        if state == "FAILED":
            messages = self._job_messages(job_info)
            raise SplunkWebError(
                "Search failed (sid={}): {}".format(sid, messages or "unknown error")
            )

        result_count = int(job_info.get("resultCount") or 0)
        results, fields = self._fetch_results(sid, row_limit, offset)
        raw_truncated = self._post_process_results(results, max_raw)

        output = self._build_output(sid, results, fields, result_count, offset, raw_truncated, max_raw)
        messages = self._job_messages(job_info)
        if messages:
            output["messages"] = messages
        if job_info.get("runDuration"):
            output["run_duration_seconds"] = round(float(job_info["runDuration"]), 3)
        return output

    @staticmethod
    def _post_process_results(results: List[Dict[str, Any]], max_raw: int) -> bool:
        """Strip storage-internal fields and cap _raw length in place.
        Returns True when any _raw value was truncated."""
        for row in results:
            for field in _INTERNAL_RESULT_FIELDS:
                row.pop(field, None)
        raw_truncated = False
        if max_raw > 0:
            for row in results:
                raw = row.get("_raw")
                if isinstance(raw, str) and len(raw) > max_raw:
                    row["_raw"] = raw[:max_raw]
                    raw_truncated = True
        return raw_truncated

    @staticmethod
    def _build_output(
        sid: str,
        results: List[Dict[str, Any]],
        fields: List[Dict[str, Any]],
        result_count: int,
        offset: int,
        raw_truncated: bool,
        max_raw: int,
    ) -> Dict[str, Any]:
        output: Dict[str, Any] = {
            "sid": sid,
            "results": results,
            "result_count": len(results),
            "total_result_count": result_count,
            "offset": offset,
            "fields": fields,
        }
        truncated = offset + len(results) < result_count
        if truncated:
            output["truncated"] = True
            output["next_offset"] = offset + len(results)
        if raw_truncated:
            output["raw_truncated"] = True
        if truncated or raw_truncated:
            notes = []
            if truncated:
                notes.append(
                    "Showing {} of {} results (offset {}). Set offset={} to get the next page."
                    .format(len(results), result_count, offset, offset + len(results))
                )
            if raw_truncated:
                notes.append("_raw values were truncated to {} chars (max_raw_chars).".format(max_raw))
            output["note"] = " ".join(notes)
        return output

    def _job_state(self, sid: str) -> Dict[str, Any]:
        sid = (sid or "").strip()
        if not _SID_RE.fullmatch(sid):
            raise SplunkWebError("Invalid search id")
        payload = self._proxy_request(
            "GET",
            "services/search/jobs/{}".format(sid),
            params={"output_mode": "json"},
        )
        entries = payload.get("entry") or []
        if not entries:
            raise SplunkWebError("Search job '{}' was not found or is not accessible".format(sid), status_code=404)
        return (entries[0].get("content") or {}).copy()

    def get_job_status(self, sid: str) -> Dict[str, Any]:
        """Inspect a previously created search job without re-running it."""
        content = self._job_state(sid)
        return {
            "sid": sid,
            "dispatch_state": content.get("dispatchState", ""),
            "is_done": content.get("isDone") in (1, "1", True),
            "result_count": int(content.get("resultCount") or 0),
            "run_duration_seconds": round(float(content["runDuration"]), 3) if content.get("runDuration") else None,
        }

    def get_job_results(
        self,
        sid: str,
        row_limit: Optional[int] = None,
        offset: int = 0,
        max_raw_chars: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Fetch results from an existing (finished) search job without
        re-running the search — cheaper pagination for large result sets."""
        sid = (sid or "").strip()
        if not _SID_RE.fullmatch(sid):
            raise SplunkWebError("Invalid search id")

        row_limit = self.default_row_limit if row_limit is None else int(row_limit)
        row_limit = max(1, min(row_limit, self.max_row_limit))
        offset = max(0, int(offset or 0))
        max_raw = self.max_raw_chars if max_raw_chars is None else max(0, int(max_raw_chars))

        state = self._job_state(sid)
        dispatch_state = state.get("dispatchState", "")
        if dispatch_state == "TIMEOUT" or (not state.get("isDone") in (1, "1", True) and dispatch_state not in ("DONE",)):
            if dispatch_state == "FAILED":
                raise SplunkWebError(
                    "Search job {} failed: {}".format(sid, self._job_messages(state) or "unknown error")
                )
            raise SplunkWebError(
                "Search job {} is not finished yet (state: {}). Poll splunk_get_search_job_status first.".format(
                    sid, dispatch_state or "unknown"
                )
            )

        result_count = int(state.get("resultCount") or 0)
        results, fields = self._fetch_results(sid, row_limit, offset)
        raw_truncated = self._post_process_results(results, max_raw)
        return self._build_output(sid, results, fields, result_count, offset, raw_truncated, max_raw)

    def _cancel_job(self, sid: str) -> None:
        """Best-effort job cancellation so timed-out searches do not keep
        consuming the account's search quota."""
        try:
            self._proxy_request(
                "POST",
                "services/search/jobs/{}/control".format(sid),
                data={"action": "cancel"},
            )
            logger.info("Cancelled search job %s after timeout", sid)
        except SplunkWebError as exc:
            logger.warning("Could not cancel search job %s: %s", sid, exc)

    def _wait_for_job(self, sid: str) -> Dict[str, Any]:
        deadline = time.monotonic() + self.search_timeout
        last_state: Dict[str, Any] = {}
        interval = self.poll_interval
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
            # Back off gradually (capped) instead of hammering the server.
            time.sleep(min(interval, max(0.0, deadline - time.monotonic())))
            interval = min(interval * 1.5, 5.0)
        # Deadline reached: mark unambiguously so callers never mistake an
        # unfinished job for a successful one.
        last_state["dispatchState"] = "TIMEOUT"
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

    def _fetch_results(self, sid: str, row_limit: int, offset: int = 0):
        payload = self._proxy_request(
            "GET",
            "services/search/jobs/{}/results".format(sid),
            params={"output_mode": "json", "count": row_limit, "offset": offset},
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

    def get_indexes(self, offset: int = 0, count: Optional[int] = None, full: bool = False) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "output_mode": "json",
            "datatype": "all",
            "count": 0,
            "offset": 0,
        }
        payload = self._proxy_request("GET", "servicesNS/-/-/data/indexes", params=params)
        entries = payload.get("entry") or []
        if full:
            indexes = [self._flatten_entry(e) for e in entries]
        else:
            indexes = [
                {field: flat.get(field) for field in _COMPACT_INDEX_FIELDS}
                for flat in (self._flatten_entry(e) for e in entries)
            ]
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
        offset: int = 0,
    ) -> Dict[str, Any]:
        metadata_type = (metadata_type or "").strip().lower()
        if metadata_type not in ("hosts", "sources", "sourcetypes"):
            raise SplunkWebError("Metadata type must be one of: hosts, sources, sourcetypes")
        index = (index or "*").strip() or "*"
        if not re.fullmatch(r"[A-Za-z0-9_*-]+", index):
            raise SplunkWebError(
                "Index pattern may only contain letters, numbers, underscore, dash and * wildcard"
            )

        # %z keeps the Splunk user's timezone offset in the value so the
        # timestamps are never mistaken for UTC.
        query = (
            "| metadata type={} index={} | eval firstTimeIso=if(isnull(firstTime) OR firstTime='', "
            "'Never', strftime(firstTime, \"%Y-%m-%dT%H:%M:%S%z\")), "
            "lastTimeIso=if(isnull(lastTime) OR lastTime='', 'Never', strftime(lastTime, "
            "\"%Y-%m-%dT%H:%M:%S%z\")), recentTimeIso=if(isnull(recentTime) OR recentTime='', "
            "'Never', strftime(recentTime, \"%Y-%m-%dT%H:%M:%S%z\"))".format(metadata_type, index)
        )
        return self.run_search(
            query,
            earliest_time=earliest_time,
            latest_time=latest_time,
            row_limit=row_limit,
            offset=offset,
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
            max_raw_chars=config.get("max_raw_chars", 1000),
            read_only=config.get("read_only", True),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigError("Invalid value in config file: {}".format(exc)) from exc
