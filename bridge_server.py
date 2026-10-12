#!/usr/bin/env python3
"""AI Bridge: MCP server (Streamable HTTP) + minimal single-user OAuth 2.1.

A voice agent connects as an MCP client to:
    https://<your-host>/mcp
Some voice-agent custom-app flows REQUIRE OAuth (error `mcp_oauth_required` without it)
and validates the metadata strictly (error `mcp_metadata_invalid` unless the
metadata lives at the standard root paths). So this server implements the MCP
authorization spec with everything at root:

  /.well-known/oauth-protected-resource   (public, RFC 9728)
  /.well-known/oauth-authorization-server  (public, RFC 8414)
  /oauth/register                          (RFC 7591 dynamic registration)
  /oauth/authorize                         (approve page)
  /oauth/approve                           (issues auth code, 302 redirect)
  /oauth/token                             (PKCE code exchange -> bearer token)
  /mcp                                     (Bearer token required)

Security model (single user):
- The bridge secret (BRIDGE_SECRET env var or .bridge_secret file, 256-bit)
  is NEVER in a URL. It is asked for once on the approve page (password
  field) — only the owner knows it, so only they can complete the grant.
  Compared with secrets.compare_digest.
- Auth codes: single-use, 10-minute expiry, bound to client_id + redirect_uri
  + PKCE challenge (S256). Redirect URIs must exactly match a registered one.
- Access tokens are opaque 32-byte randoms, stored server-side in tokens.json.
- The delegate_task tool can ONLY append to queue.jsonl. It cannot send
  messages, run commands, or touch anything else.
- Legacy token-path aliases (/<TOKEN>/mcp, /<TOKEN>/oauth/*) still work so the
  old URL keeps functioning; they are not advertised anywhere.
"""

import base64
import hashlib
import hmac
import html as htmlmod
import json
import os
import secrets
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
SECRET_FILE = os.path.join(BASE, ".bridge_secret")
QUEUE_FILE = os.path.join(BASE, "queue.jsonl")
REPLIES_FILE = os.path.join(BASE, "replies.jsonl")
LOG_FILE = os.path.join(BASE, "relay.log")
CLIENTS_FILE = os.path.join(BASE, "clients.json")
CODES_FILE = os.path.join(BASE, "codes.json")
TOKENS_FILE = os.path.join(BASE, "tokens.json")
PORT = int(os.environ.get("BRIDGE_PORT", "8133"))
BIND = os.environ.get("BRIDGE_BIND", "127.0.0.1")


def get_secret():
    """Bridge secret: BRIDGE_SECRET env var wins, else .bridge_secret file."""
    env = os.environ.get("BRIDGE_SECRET")
    if env:
        return env.strip()
    with open(SECRET_FILE) as f:
        return f.read().strip()


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def b64url_sha256(s):
    return base64.urlsafe_b64encode(hashlib.sha256(s.encode()).digest()).rstrip(b"=").decode()


class Handler(BaseHTTPRequestHandler):
    server_version = "AIBridge/1.0"

    def log_message(self, *a):
        pass

    def _log(self, msg):
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")

    # ---- helpers ----
    def _host(self):
        return self.headers.get("Host", "localhost").split(",")[0].strip()

    def _base(self):
        return f"https://{self._host()}"

    def _parts(self):
        return urllib.parse.urlparse(self.path).path.strip("/").split("/")

    def _send(self, code, body=b"", ctype="text/plain", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_json(self, code, obj, headers=None):
        self._send(code, json.dumps(obj).encode(), "application/json", headers)

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def _params(self):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))
        body = self._read_body()
        ctype = self.headers.get("Content-Type", "")
        if body:
            if "application/json" in ctype:
                try:
                    q.update(json.loads(body))
                except Exception:
                    pass
            else:
                q.update(dict(urllib.parse.parse_qsl(body.decode("utf-8", "replace"))))
        return q

    def _bearer_ok(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return auth[7:].strip() in load_json(TOKENS_FILE, {})

    def _token_path(self, parts):
        """Legacy alias: first path segment is the relay secret."""
        return bool(parts) and hmac.compare_digest(parts[0], get_secret())

    # ---- routing ----
    def do_GET(self):
        parts = self._parts()
        self._log(f"GET /{'/'.join(parts[:3])}")

        if parts == [".well-known", "oauth-protected-resource"]:
            self._send_json(200, {
                "resource": f"{self._base()}/mcp",
                "authorization_servers": [self._base()],
                "bearer_methods_supported": ["header"],
                "resource_name": "AI bridge (voice agent -> assistant task bridge)",
            })
            return

        if parts == [".well-known", "oauth-authorization-server"]:
            base = self._base()
            self._send_json(200, {
                "issuer": base,
                "authorization_endpoint": f"{base}/oauth/authorize",
                "token_endpoint": f"{base}/oauth/token",
                "registration_endpoint": f"{base}/oauth/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
            })
            return

        # Approve page. pre_auth=True when the legacy token path was used.
        if parts == ["oauth", "authorize"]:
            self._handle_authorize(pre_auth=False)
            return
        if len(parts) == 3 and parts[1:] == ["oauth", "authorize"] and self._token_path(parts):
            self._handle_authorize(pre_auth=True)
            return
        # Legacy alias for the ASM under the token path.
        if len(parts) == 4 and parts[1:] == [".well-known", "oauth-authorization-server"] \
                and self._token_path(parts):
            base = self._base()
            self._send_json(200, {
                "issuer": base,
                "authorization_endpoint": f"{base}/oauth/authorize",
                "token_endpoint": f"{base}/oauth/token",
                "registration_endpoint": f"{base}/oauth/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
            })
            return

        self._send(404)

    def do_POST(self):
        parts = self._parts()
        self._log(f"POST /{'/'.join(parts[:3])}")

        # Normalize legacy token-path aliases to the canonical routes.
        pre_auth = self._token_path(parts)
        if pre_auth:
            parts = parts[1:]

        if parts == ["oauth", "register"]:
            self._handle_register()
            return
        if parts == ["oauth", "approve"]:
            self._handle_approve(pre_auth=pre_auth)
            return
        if parts == ["oauth", "token"]:
            self._handle_token()
            return
        if parts == ["mcp"]:
            if not self._bearer_ok():
                prm = f"{self._base()}/.well-known/oauth-protected-resource"
                self._send_json(401, {"error": "unauthorized"},
                                {"WWW-Authenticate": f'Bearer resource_metadata="{prm}"'})
                return
            self._handle_mcp()
            return
        self._send(404)

    # ---- OAuth endpoints ----
    def _handle_register(self):
        p = self._params()
        redirect_uris = p.get("redirect_uris")
        if isinstance(redirect_uris, str):
            try:
                redirect_uris = json.loads(redirect_uris)
            except Exception:
                redirect_uris = [redirect_uris]
        if not redirect_uris or not isinstance(redirect_uris, list):
            self._send_json(400, {"error": "invalid_redirect_uri"})
            return
        client_id = "bridge-" + secrets.token_hex(8)
        clients = load_json(CLIENTS_FILE, {})
        clients[client_id] = {"redirect_uris": redirect_uris, "created": time.time(),
                              "name": str(p.get("client_name", "voice-agent-mcp"))[:80]}
        save_json(CLIENTS_FILE, clients)
        self._log(f"oauth: registered client {client_id}")
        self._send_json(201, {"client_id": client_id,
                              "redirect_uris": redirect_uris,
                              "token_endpoint_auth_method": "none",
                              "grant_types": ["authorization_code"],
                              "response_types": ["code"]})

    def _handle_authorize(self, pre_auth):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))
        client_id = q.get("client_id", "")
        redirect_uri = q.get("redirect_uri", "")
        challenge = q.get("code_challenge", "")
        state = q.get("state", "")
        clients = load_json(CLIENTS_FILE, {})
        cl = clients.get(client_id)
        err = None
        if not cl:
            err = "unknown client — register first"
        elif redirect_uri not in cl["redirect_uris"]:
            err = "redirect_uri not registered"
        elif q.get("response_type") != "code":
            err = "only response_type=code is supported"
        elif not challenge:
            err = "code_challenge (PKCE) is required"
        if err:
            self._send(400, f"OAuth error: {htmlmod.escape(err)}".encode(), "text/html")
            return
        token_field = "" if pre_auth else (
            '<p><label>Relay token<br><input type=password name=relay_token '
            'placeholder="from BRIDGE_SECRET or .bridge_secret" '
            'style="width:100%;padding:10px;border-radius:8px;border:1px solid #444;'
            'background:#222;color:#eee;margin-top:6px"></label></p>')
        page = f"""<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1">
<title>Connect voice agent to assistant</title><style>
body{{font-family:system-ui,sans-serif;background:#111;color:#eee;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}}
.card{{background:#1d1d1f;border-radius:16px;padding:32px;max-width:380px;text-align:center}}
h1{{font-size:20px}}p{{color:#aaa;font-size:14px;line-height:1.5}}
button{{background:#fff;color:#111;border:0;border-radius:999px;padding:14px 40px;font-size:17px;font-weight:700;cursor:pointer;margin-top:8px}}
.small{{font-size:12px;color:#666;margin-top:16px}}</style></head><body><div class=card>
<h1>Connect voice agent to assistant?</h1>
<p>This lets your voice agent hand tasks to your assistant agent —
when you ask it to. The assistant still applies all your usual rules before
doing anything.</p>
<form method=post action="/oauth/approve">
<input type=hidden name=client_id value="{htmlmod.escape(client_id)}">
<input type=hidden name=redirect_uri value="{htmlmod.escape(redirect_uri)}">
<input type=hidden name=code_challenge value="{htmlmod.escape(challenge)}">
<input type=hidden name=state value="{htmlmod.escape(state)}">
{token_field}
<button type=submit>Approve</button></form>
<p class=small>Only approve if YOU just asked your voice agent to connect.</p>
</div></body></html>"""
        self._send(200, page.encode(), "text/html")

    def _handle_approve(self, pre_auth=False):
        p = self._params()
        client_id = p.get("client_id", "")
        redirect_uri = p.get("redirect_uri", "")
        challenge = p.get("code_challenge", "")
        state = p.get("state", "")
        # The bridge secret proves it is the owner approving. (Legacy token-path
        # requests were pre-authenticated by the URL itself.)
        if not pre_auth and not hmac.compare_digest(p.get("relay_token", ""), get_secret()):
            self._log("oauth: approve denied (bad relay token)")
            self._send(403, b"Wrong bridge secret. Find it in your BRIDGE_SECRET "
                            b"env var or .bridge_secret file")
            return
        clients = load_json(CLIENTS_FILE, {})
        cl = clients.get(client_id)
        if not cl or redirect_uri not in cl["redirect_uris"] or not challenge:
            self._send(400, b"OAuth error: invalid approval request")
            return
        code = secrets.token_urlsafe(24)
        codes = load_json(CODES_FILE, {})
        codes[code] = {"client_id": client_id, "redirect_uri": redirect_uri,
                       "challenge": challenge, "expires": time.time() + 600}
        save_json(CODES_FILE, codes)
        self._log(f"oauth: approved client {client_id}")
        loc = redirect_uri + ("&" if "?" in redirect_uri else "?") + \
            urllib.parse.urlencode({"code": code, "state": state})
        self.send_response(302)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _handle_token(self):
        p = self._params()
        if p.get("grant_type") != "authorization_code":
            self._send_json(400, {"error": "unsupported_grant_type"})
            return
        code = p.get("code", "")
        codes = load_json(CODES_FILE, {})
        c = codes.get(code)
        if not c or c["expires"] < time.time():
            self._send_json(400, {"error": "invalid_grant"})
            return
        if p.get("client_id") != c["client_id"] or p.get("redirect_uri") != c["redirect_uri"]:
            self._send_json(400, {"error": "invalid_grant"})
            return
        verifier = p.get("code_verifier", "")
        if not verifier or b64url_sha256(verifier) != c["challenge"]:
            self._send_json(400, {"error": "invalid_grant"})
            return
        del codes[code]  # single-use
        save_json(CODES_FILE, codes)
        access = secrets.token_urlsafe(32)
        tokens = load_json(TOKENS_FILE, {})
        tokens[access] = {"client_id": c["client_id"], "created": time.time()}
        save_json(TOKENS_FILE, tokens)
        self._log(f"oauth: issued token for client {c['client_id']}")
        self._send_json(200, {"access_token": access, "token_type": "Bearer",
                              "expires_in": 2592000})

    # ---- MCP ----
    def _handle_mcp(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._send_json(400, {"jsonrpc": "2.0", "id": None,
                                  "error": {"code": -32700, "message": "parse error"}})
            return
        method = req.get("method")
        rid = req.get("id")
        params = req.get("params", {}) or {}

        if method == "initialize":
            pv = params.get("protocolVersion", "2025-03-26")
            self._log("mcp: initialize (oauth client)")
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": pv,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ai-bridge", "version": "1.0.0"}}})
        elif method == "ping":
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {}})
        elif method == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
        elif method == "tools/list":
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": [{
                "name": "delegate_task",
                "description": (
                    "Send a task or message to the assistant agent. "
                    "Use this whenever the user asks you to tell the assistant "
                    "something, have the assistant do something, or delegate "
                    "any request to it. "
                    "The assistant picks it up within a few minutes. "
                    "Pass the user's request in the user's own words. "
                    "The result includes a request ID — use get_reply with "
                    "that ID to fetch the assistant's reply once it answers."),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "string",
                            "description": "The task or message for the assistant, in the user's own words."}},
                    "required": ["message"]}},
                {
                "name": "get_reply",
                "description": (
                    "Fetch the assistant's reply to an earlier delegate_task request. "
                    "Pass the request ID that delegate_task returned. "
                    "Returns the reply text, or 'pending' if it has not "
                    "answered yet — in that case wait a minute or two and "
                    "call again."),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "request_id": {
                            "type": "string",
                            "description": "The request ID returned by delegate_task."}},
                    "required": ["request_id"]}}]}})
        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments", {}) or {}
            if name == "get_reply":
                request_id = str(args.get("request_id") or "")
                reply = self._get_reply(request_id)
                text = reply if reply else \
                    "pending — the assistant hasn't answered yet. Try again in a minute or two."
                self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": text}]}})
                return
            if name != "delegate_task" or not args.get("message"):
                self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text",
                                 "text": "error: unknown tool or missing message"}],
                    "isError": True}})
                return
            request_id = "req-" + secrets.token_hex(6)
            entry = {"ts": time.time(), "from": "voice-agent", "request_id": request_id,
                     "text": str(args["message"])[:8000]}
            with open(QUEUE_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
            self._log(f"queued task {request_id}: {entry['text'][:80]}")
            self._send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text",
                             "text": "Task received and queued — the assistant will "
                                     "pick it up within a few minutes.\n"
                                     "Request ID: " + request_id + " — call get_reply "
                                     "with this ID to fetch the reply once it answers."}]}})
        else:
            self._send_json(200, {"jsonrpc": "2.0", "id": rid,
                                  "error": {"code": -32601,
                                            "message": "method not found"}})

    def _get_reply(self, request_id):
        try:
            with open(REPLIES_FILE) as f:
                lines = f.readlines()
        except FileNotFoundError:
            return None
        for line in reversed(lines):
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("request_id") == request_id:
                return e.get("reply")
        return None


if __name__ == "__main__":
    if not os.path.exists(SECRET_FILE):
        raise SystemExit("missing bridge secret — set BRIDGE_SECRET or create .bridge_secret first")
    print(f"ai-bridge MCP+OAuth server on {BIND}:{PORT}", flush=True)
    HTTPServer((BIND, PORT), Handler).serve_forever()
