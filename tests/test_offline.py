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
    "results": [{"index": "main", "count": "42"}, {"index": "firewall", "count": "7"}],
}

state = {"jobs": {}, "auth_ok": True, "force_relogin": False}


class MockSplunkWeb(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    # helpers ---------------------------------------------------------- #
    def _send(self, status, body, headers=None, content_type="text/html"):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
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

    # routes ----------------------------------------------------------- #
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/en-US/account/login":
            self._send(
                200,
                '<html><form><input name="cval" value="{}"><input name="username">'
                '<input name="password"></form></html>'.format(FORM_KEY),
            )
        elif path in ("/en-US/app/launcher/home", "/en-US/config"):
            self._send(200, '<html>{"cval":"%s"}</html>' % FORM_KEY)
        elif path == "/en-US/splunkd/__raw/services/search/jobs" :
            if not self._authed():
                self._send(302, "", headers={"Location": "/en-US/account/login"})
                return
            self._send_json(200, {"entry": []})
        elif path.startswith("/en-US/splunkd/__raw/services/search/jobs/"):
            if not self._authed():
                self._send(302, "", headers={"Location": "/en-US/account/login"})
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
            done = polls >= 2
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
                self._send(302, "", headers={"Location": "/en-US/account/login"})
                return
            self._send_json(200, INDEXES_PAYLOAD)
        elif path.startswith("/en-US/splunkd/__raw/servicesNS/-/-/data/indexes/"):
            if not self._authed():
                self._send(302, "", headers={"Location": "/en-US/account/login"})
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

        if path == "/en-US/account/login":
            username = body.get("username", [""])[0]
            password = body.get("password", [""])[0]
            if state["auth_ok"] and username == USER and password == PASSWORD:
                self._send(
                    303,
                    "",
                    headers={
                        "Location": "/en-US/app/launcher/home",
                        "Set-Cookie": "splunkd_8000=sess-key-1; Path=/",
                    },
                )
            else:
                self._send(401, "<html>Login failed</html>")
            return

        if path == "/en-US/splunkd/__raw/services/search/jobs":
            if not self._authed():
                self._send(302, "", headers={"Location": "/en-US/account/login"})
                return
            if self.headers.get("X-Splunk-Form-Key") != FORM_KEY:
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
    client.default_row_limit = 100

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
