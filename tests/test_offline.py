"""Offline test: spins up a mock Splunk Web server and exercises SplunkWebClient."""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from splunk_mcp_webui.client import SplunkAuthError, SplunkWebError, SplunkWebClient

USER = "admin"
PASSWORD = "changeme"
FORM_KEY = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
MODERN_CSRF = "csrf-token-987654321"
MODERN_CVAL = "cval-cookie-12345"

INDEXES_PAYLOAD = {
    "entry": [
        {
            "name": "main",
            "content": {
                "disabled": "0",
                "currentDBSizeMB": 512,
                "totalEventCount": 123456,
                "splunk_server": "idx01",
                "maxDataSize": "auto",
            },
        },
        {
            "name": "firewall",
            "content": {
                "disabled": "0",
                "currentDBSizeMB": 1024,
                "totalEventCount": 999,
                "splunk_server": "idx02",
            },
        },
    ]
}

INDEX_MAIN_PAYLOAD = {"entry": [INDEXES_PAYLOAD["entry"][0]]}

SEARCH_RESULTS = {
    "preview": False,
    "init_offset": 0,
    "messages": [],
    "fields": [{"name": "index"}, {"name": "count"}],
    "results": [
        {
            "index": "main",
            "count": "42",
            "_raw": "sample raw event for main index " + "x" * 120,
        },
        {
            "index": "firewall",
            "count": "7",
            "_raw": "sample raw event for firewall index " + "y" * 130,
        },
    ],
}

state = {"jobs": {}, "auth_ok": True, "force_relogin": False, "mode": "legacy",
         "login_count": 0, "cancelled": None, "never_done": False}


class MockSplunkWeb(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    # helpers ---------------------------------------------------------- #
    def _send(self, status, body, headers=None, content_type="text/html"):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def _send_json(self, status, payload):
        self._send(status, json.dumps(payload), content_type="application/json")

    def _cookies(self):
        header = self.headers.get("Cookie", "")
        jar = {}
        for part in header.split(";"):
            if "=" in part:
                name, _, value = part.strip().partition("=")
                jar[name] = value
        return jar

    def _authed(self):
        jar = self._cookies()
        return jar.get("splunkd_8000") == "sess-key-1"

    def _expected_form_key(self):
        if state["mode"] == "modern":
            return self._cookies().get("splunkweb_csrf_token_8000")
        return FORM_KEY

    # routes ----------------------------------------------------------- #
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/en-US/account/login":
            if state["mode"] == "modern":
                # Modern Splunk behind SSO: no CSRF value in the HTML, the
                # cval is delivered as a cookie instead.
                self._send(
                    200,
                    "<html><body>login form rendered by JS</body></html>",
                    headers=[
                        ("Set-Cookie", "cval={}; Path=/".format(MODERN_CVAL)),
                        ("Set-Cookie", "splunkweb_uid=MODERN-UID; Path=/"),
                    ],
                )
                return
            self._send(
                200,
                '<html><form><input name="cval" value="{}"><input name="username">'
                '<input name="password"></form></html>'.format(FORM_KEY),
            )
        elif path in ("/en-US/app/launcher/home", "/en-US/config"):
            self._send(200, '<html>{"cval":"%s"}</html>' % FORM_KEY)
        elif path == "/en-US/splunkd/__raw/services/search/jobs" :
            if not self._authed():
                self._send(302, "", headers=[("Location", "/en-US/account/login")])
                return
            self._send_json(200, {"entry": []})
        elif path.startswith("/en-US/splunkd/__raw/services/search/jobs/"):
            if not self._authed():
                self._send(302, "", headers=[("Location", "/en-US/account/login")])
                return
            parts = path.strip("/").split("/")
            sid = parts[-1]
            if path.endswith("/results"):
                qs = parse_qs(urlparse(self.path).query)
                count = int(qs.get("count", ["100"])[0])
                offset = int(qs.get("offset", ["0"])[0])
                sliced = dict(SEARCH_RESULTS)
                sliced["results"] = SEARCH_RESULTS["results"][offset : offset + count]
                self._send_json(200, sliced)
                return
            polls = state["jobs"].get(sid, 0) + 1
            state["jobs"][sid] = polls
            done = polls >= 2 and not state["never_done"]
            self._send_json(
                200,
                {
                    "entry": [
                        {
                            "name": sid,
                            "content": {
                                "isDone": 1 if done else 0,
                                "dispatchState": "DONE" if done else "RUNNING",
                                "resultCount": 2,
                                "runDuration": 0.42,
                                "messages": [],
                            },
                        }
                    ]
                },
            )
        elif path == "/en-US/splunkd/__raw/servicesNS/-/-/data/indexes":
            if not self._authed():
                self._send(302, "", headers=[("Location", "/en-US/account/login")])
                return
            self._send_json(200, INDEXES_PAYLOAD)
        elif path.startswith("/en-US/splunkd/__raw/servicesNS/-/-/data/indexes/"):
            if not self._authed():
                self._send(302, "", headers=[("Location", "/en-US/account/login")])
                return
            name = path.rstrip("/").split("/")[-1]
            entry = next((e for e in INDEXES_PAYLOAD["entry"] if e["name"] == name), None)
            if entry is None:
                self._send_json(404, {"messages": [{"type": "ERROR", "text": "not found"}]})
            else:
                self._send_json(200, {"entry": [entry]})
        else:
            self._send(404, "not found")

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        body = parse_qs(self.rfile.read(length).decode("utf-8"))

        # Job control (cancel) — no form key check needed for the mock.
        if path.startswith("/en-US/splunkd/__raw/services/search/jobs/") and path.endswith("/control"):
            if not self._authed():
                self._send(302, "", headers=[("Location", "/en-US/account/login")])
                return
            if body.get("action", [""])[0] == "cancel":
                state["cancelled"] = path.rstrip("/").split("/")[-2]
            self._send_json(200, {"messages": [{"type": "INFO", "text": "cancelled"}]})
            return

        if path == "/en-US/account/login":
            username = body.get("username", [""])[0]
            password = body.get("password", [""])[0]
            state["login_count"] += 1
            if state["mode"] == "modern":
                # Modern flow: cval must be posted back and must match the
                # pre-auth cval cookie; success returns 200 + cookies.
                jar = self._cookies()
                cval_ok = body.get("cval", [""])[0] == jar.get("cval")
                if state["auth_ok"] and cval_ok and username == USER and password == PASSWORD:
                    self._send(
                        200,
                        '{"status":0}',
                        headers=[
                            ("Set-Cookie", "splunkd_8000=sess-key-1; Path=/"),
                            ("Set-Cookie", "splunkweb_csrf_token_8000={}; Path=/".format(MODERN_CSRF)),
                        ],
                        content_type="application/json",
                    )
                else:
                    self._send(401, '{"status":1}', content_type="application/json")
                return
            if state["auth_ok"] and username == USER and password == PASSWORD:
                self._send(
                    303,
                    "",
                    headers=[
                        ("Location", "/en-US/app/launcher/home"),
                        ("Set-Cookie", "splunkd_8000=sess-key-1; Path=/"),
                    ],
                )
            else:
                self._send(401, "<html>Login failed</html>")
            return

        if path == "/en-US/splunkd/__raw/services/search/jobs":
            if not self._authed():
                self._send(302, "", headers=[("Location", "/en-US/account/login")])
                return
            if self.headers.get("X-Splunk-Form-Key") != self._expected_form_key():
                self._send_json(400, {"messages": [{"type": "ERROR", "text": "Missing or invalid CSRF header"}]})
                return
            if body.get("exec_mode", ["normal"])[0] == "oneshot":
                self._send_json(200, SEARCH_RESULTS)
            else:
                self._send_json(201, {"sid": "sid_123"})
            return

        self._send(404, "not found")


def start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockSplunkWeb)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main():
    server = start_server()
    port = server.server_address[1]
    base = "http://127.0.0.1:{}".format(port)

    results = []

    def check(name, condition):
        results.append((name, bool(condition)))
        print("[{}] {}".format("PASS" if condition else "FAIL", name))

    # --- login flow + run_search -------------------------------------- #
    client = SplunkWebClient(base, USER, PASSWORD, verify_ssl=False, poll_interval=0.05)
    client.login()
    check("login sets session cookie", any(c.lower().startswith("splunkd") for c in client.session.cookies.keys()))
    check("form key extracted", client.form_key == FORM_KEY)

    out = client.run_search("index=* | stats count by index", earliest_time="-24h", latest_time="now")
    check("run_search returns sid", out.get("sid") == "sid_123")
    check("run_search returns results", out.get("results") == SEARCH_RESULTS["results"])
    check("run_search run_duration", out.get("run_duration_seconds") == 0.42)
    check("no truncation when equal", "truncated" not in out)

    client.default_row_limit = 1
    out = client.run_search("index=*")
    check("truncation flagged", out.get("truncated") is True and out["total_result_count"] == 2)
    check("truncation next_offset", out.get("next_offset") == 1)
    client.default_row_limit = 100

    # --- offset pagination ---------------------------------------------- #
    out = client.run_search("index=*", row_limit=1, offset=1)
    check(
        "offset pagination returns second row",
        out.get("results") == [SEARCH_RESULTS["results"][1]] and out.get("offset") == 1,
    )
    check("offset pagination last page not truncated", "truncated" not in out)

    # --- _raw truncation ------------------------------------------------- #
    out = client.run_search("index=*")
    check("no raw truncation under limit", "raw_truncated" not in out)
    client.max_raw_chars = 20
    out = client.run_search("index=*")
    check(
        "raw truncated at limit",
        out.get("raw_truncated") is True
        and all(len(r["_raw"]) <= 20 for r in out["results"]),
    )
    client.max_raw_chars = 0
    out = client.run_search("index=*")
    check("raw truncation disabled with 0", "raw_truncated" not in out)
    client.max_raw_chars = 1000

    # --- compact index list ---------------------------------------------- #
    out = client.get_indexes()
    compact_keys = set(out["indexes"][0].keys())
    check(
        "compact index fields only",
        compact_keys <= {"name", "datatype", "disabled", "currentDBSizeMB", "totalEventCount", "splunk_server", "minTime", "maxTime"}
        and "name" in compact_keys,
    )
    out = client.get_indexes(full=True)
    main_full = next(i for i in out["indexes"] if i["name"] == "main")
    check("full index keeps extra fields", "maxDataSize" in main_full)

    # --- metadata + indexes ------------------------------------------- #
    out = client.get_metadata("hosts", index="main", earliest_time="-1h")
    search_sent = out["sid"] == "sid_123" and "| metadata type=hosts index=main" in json.dumps(out)
    check("get_metadata executes search", search_done(out))

    out = client.get_indexes()
    names = [i["name"] for i in out["indexes"]]
    check("get_indexes sorted list", names == ["firewall", "main"] and out["total_indexes"] == 2)
    main_entry = next(i for i in out["indexes"] if i["name"] == "main")
    check("index entry flattened", main_entry["splunk_server"] == "idx01")

    out = client.get_index_info("main")
    check("get_index_info", out["index"]["name"] == "main" and out["index"]["currentDBSizeMB"] == 512)

    try:
        client.get_index_info("does_not_exist")
        check("get_index_info 404 raises", False)
    except SplunkWebError as exc:
        check("get_index_info 404 raises", exc.status_code == 404)

    # --- validation ---------------------------------------------------- #
    try:
        client.get_metadata("bogus")
        check("metadata type validated", False)
    except SplunkWebError:
        check("metadata type validated", True)

    try:
        client.get_index_info("bad name!")
        check("index name validated", False)
    except SplunkWebError:
        check("index name validated", True)

    # --- read-only guard v2 ----------------------------------------------- #
    client.read_only = True
    try:
        client.run_search("index=* | delete")
        check("read_only blocks delete", False)
    except SplunkWebError as exc:
        check("read_only blocks delete", "read_only" in str(exc))

    for bypass_query in [
        '| makeresults | map search="| makeresults | outputlookup evil.csv"',
        "| mcollect index=main",
        "| dump",
        "| runshellscript cmd.sh",
        "| savedsearch my_saved_search",
        "search `my_macro_with_write()`",
        "index=* [ | makeresults | outputlookup evil.csv ]",
    ]:
        try:
            client.run_search(bypass_query)
            check("guard blocks: " + bypass_query[:40], False)
        except SplunkWebError as exc:
            check("guard blocks: " + bypass_query[:40], "read_only" in str(exc))

    out = client.run_search('index=* | where match(src, "a|b|delete")')
    check("read_only allows pipes inside quotes", out.get("sid") == "sid_123")
    out = client.run_search("delete user=bob")
    check("search terms not treated as commands", out.get("sid") == "sid_123")
    out = client.run_search("script error in logs | stats count")
    check("search terms with 'script' allowed", out.get("sid") == "sid_123")

    client.read_only = False
    out = client.run_search("index=* | delete")
    check("read_only=false allows delete", out.get("sid") == "sid_123")
    client.read_only = True

    # --- search timeout: cancel + clear error ------------------------------ #
    slow = SplunkWebClient(base, USER, PASSWORD, verify_ssl=False, poll_interval=0.05, search_timeout=0.6)
    slow.login()
    state["never_done"] = True
    try:
        slow.run_search("index=*")
        check("timeout raises", False)
    except SplunkWebError as exc:
        check("timeout raises with sid", "timed out" in str(exc) and "sid=" in str(exc))
    check("timed-out job cancelled", state["cancelled"] == "sid_123")
    state["never_done"] = False

    # --- TLS fallback policy ------------------------------------------------ #
    strict = SplunkWebClient("https://127.0.0.1:{}".format(port), USER, PASSWORD, verify_ssl=False)
    try:
        strict.login()
        check("explicit https never downgrades", False)
    except SplunkWebError as exc:
        check("explicit https never downgrades", "TLS handshake" in str(exc) and strict.base_url.startswith("https://"))

    relaxed = SplunkWebClient("127.0.0.1:{}".format(port), USER, PASSWORD, verify_ssl=False, poll_interval=0.05)
    relaxed.login()
    check("bare host falls back to http", relaxed.base_url.startswith("http://127.0.0.1"))
    out = relaxed.run_search("index=*")
    check("run_search after http fallback", out.get("sid") == "sid_123")

    # --- concurrent tool calls share one session ---------------------------- #
    state["login_count"] = 0
    import threading

    def parallel_call():
        c2.run_search("index=*")

    c2 = SplunkWebClient(base, USER, PASSWORD, verify_ssl=False, poll_interval=0.05)
    threads = [threading.Thread(target=parallel_call) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check("concurrent calls log in once", state["login_count"] == 1)

    # --- auth failures -------------------------------------------------- #
    bad = SplunkWebClient(base, USER, "wrongpass", verify_ssl=False)
    try:
        bad.login()
        check("bad password raises", False)
    except SplunkAuthError:
        check("bad password raises", True)

    # --- session expiry triggers re-login ------------------------------ #
    state["auth_ok"] = False  # next login attempts will fail -> proves relogin not called
    # simulate expired cookie: server still authenticates old cookie but we clear client jar
    state["auth_ok"] = True
    client.session.cookies.clear()
    out = client.run_search("index=*")
    check("re-login after session loss", out.get("sid") == "sid_123")

    # --- modern SSO-style login (cval/csrf delivered via cookies) ------- #
    state["mode"] = "modern"
    modern = SplunkWebClient(base, USER, PASSWORD, verify_ssl=False, poll_interval=0.05)
    modern.login()
    check("modern login sets session cookie", any(c.lower().startswith("splunkd") for c in modern.session.cookies.keys()))
    check("modern form key from csrf cookie", modern.form_key == MODERN_CSRF)
    out = modern.run_search("index=*")
    check("modern run_search", out.get("sid") == "sid_123")

    bad_modern = SplunkWebClient(base, USER, "wrongpass", verify_ssl=False)
    try:
        bad_modern.login()
        check("modern bad password raises", False)
    except SplunkAuthError:
        check("modern bad password raises", True)
    state["mode"] = "legacy"

    failed = [name for name, ok in results if not ok]
    print("\n{}/{} tests passed".format(len(results) - len(failed), len(results)))
    server.shutdown()
    if failed:
        print("FAILED:", failed)
        sys.exit(1)


def search_done(out):
    return out.get("sid") == "sid_123" and out.get("results") == SEARCH_RESULTS["results"]


if __name__ == "__main__":
    main()
