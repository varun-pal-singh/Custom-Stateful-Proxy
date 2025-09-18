#!/usr/bin/env python3
"""
mitmproxy addon: extract full/raw request-response data useful for replaying or
building the "next request".

Outputs:
 - raw/request_<id>.bin        (raw reconstructed request bytes)
 - raw/response_<id>.bin       (raw reconstructed response bytes)
 - cookies.txt                 (Mozilla cookie jar)
 - auth_state.json             (latest sensitive headers per host)
 - state.json                  (latest structured state per host with references to raw files)
"""

from mitmproxy import http, ctx
from http.cookies import SimpleCookie
from http.cookiejar import Cookie, MozillaCookieJar
from email.utils import parsedate_to_datetime
import os, time, json, uuid, base64

# Files / directories
COOKIES_FILE = "cookies.txt"
AUTH_FILE = "auth_state.json"
STATE_FILE = "state.json"
RAW_DIR = "raw"

# headers we consider sensitive and want to persist per-host
SENSITIVE_HEADERS = ["authorization", "x-auth-token", "x-xsrf-token", "cookie"]

def ensure_dirs():
    try:
        os.makedirs(RAW_DIR, exist_ok=True)
    except Exception as e:
        ctx.log.warn(f"Could not create raw dir: {e}")

def safe_save_json(path, obj):
    try:
        with open(path, "w") as f:
            json.dump(obj, f, indent=2)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    except Exception as e:
        ctx.log.error(f"Error saving {path}: {e}")

class FullExtractor:
    def __init__(self):
        ensure_dirs()
        # cookie jar
        self.jar = MozillaCookieJar(COOKIES_FILE)
        if os.path.exists(COOKIES_FILE):
            try:
                self.jar.load(ignore_discard=True, ignore_expires=True)
                ctx.log.info(f"Loaded cookie jar {COOKIES_FILE}")
            except Exception as e:
                ctx.log.warn(f"Failed to load cookie jar: {e}")
        # auth state
        self.auth_state = {}
        if os.path.exists(AUTH_FILE):
            try:
                with open(AUTH_FILE, "r") as f:
                    self.auth_state = json.load(f)
                    ctx.log.info(f"Loaded auth state {AUTH_FILE}")
            except Exception as e:
                ctx.log.warn(f"Failed to load auth state: {e}")
        # state per host
        self.state = {}
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, "r") as f:
                    self.state = json.load(f)
                    ctx.log.info(f"Loaded state {STATE_FILE}")
            except Exception as e:
                ctx.log.warn(f"Failed to load state file: {e}")

    # Helpers
    def parse_expires(self, s):
        if not s:
            return None
        try:
            dt = parsedate_to_datetime(s)
            return int(dt.timestamp())
        except Exception:
            try:
                ma = int(s)
                return int(time.time()) + ma
            except Exception:
                return None

    def make_cookie(self, name, value, domain, path="/", secure=False, expires=None, http_only=False):
        domain_specified = bool(domain)
        domain_initial_dot = domain.startswith(".") if domain else False
        path_specified = bool(path)
        rest = {}
        if http_only:
            rest["HttpOnly"] = True
        c = Cookie(
            version=0,
            name=name,
            value=value,
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=domain_specified,
            domain_initial_dot=domain_initial_dot,
            path=path,
            path_specified=path_specified,
            secure=secure,
            expires=expires,
            discard=False,
            comment=None,
            comment_url=None,
            rest=rest,
            rfc2109=False,
        )
        return c

    def save_cookies(self):
        try:
            self.jar.save(ignore_discard=True, ignore_expires=True)
            try:
                os.chmod(COOKIES_FILE, 0o600)
            except Exception:
                pass
            ctx.log.info(f"Saved cookies to {COOKIES_FILE}")
        except Exception as e:
            ctx.log.error(f"Error saving cookies: {e}")

    def save_auth(self):
        safe_save_json(AUTH_FILE, self.auth_state)
        ctx.log.info("Saved auth_state")

    def save_state(self):
        safe_save_json(STATE_FILE, self.state)
        ctx.log.info("Saved state.json")

    def build_raw_request_bytes(self, req: http.Request):
        # Build initial request line
        path = req.path
        # request line: "METHOD path HTTP/1.1\r\n"
        request_line = f"{req.method} {path} HTTP/{req.http_version}\r\n"
        # headers
        headers = ""
        for k, v in req.headers.items(multi=True):
            headers += f"{k}: {v}\r\n"
        # combine
        body = req.raw_content or b""
        raw = request_line.encode("utf-8") + headers.encode("utf-8") + b"\r\n" + body
        return raw

    def build_raw_response_bytes(self, resp: http.Response):
        # status line: "HTTP/1.1 200 OK\r\n"
        status_line = f"HTTP/{resp.http_version} {resp.status_code} {resp.reason}\r\n"
        headers = ""
        for k, v in resp.headers.items(multi=True):
            headers += f"{k}: {v}\r\n"
        body = resp.raw_content or b""
        raw = status_line.encode("utf-8") + headers.encode("utf-8") + b"\r\n" + body
        return raw

    def write_raw_file(self, prefix, data_bytes):
        uid = uuid.uuid4().hex
        fname = f"{prefix}_{int(time.time())}_{uid}.bin"
        path = os.path.join(RAW_DIR, fname)
        try:
            with open(path, "wb") as f:
                f.write(data_bytes)
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
            return path
        except Exception as e:
            ctx.log.error(f"Failed to write raw file {path}: {e}")
            return None

    # mitmproxy hooks
    def response(self, flow: http.HTTPFlow):
        """Called when response is available. We save full exchange here."""
        if not flow.request or not flow.response:
            return

        host = flow.request.host

        # 1) extract Set-Cookie headers (like before)
        set_cookie_headers = flow.response.headers.get_all("Set-Cookie")
        if set_cookie_headers:
            for header in set_cookie_headers:
                try:
                    sc = SimpleCookie()
                    sc.load(header)
                    for name, morsel in sc.items():
                        value = morsel.value
                        domain = morsel.get("domain") or host
                        path = morsel.get("path") or "/"
                        secure = bool(morsel.get("secure"))
                        http_only = "httponly" in header.lower() or bool(morsel.get("httponly"))
                        expires = None
                        if morsel.get("max-age"):
                            try:
                                expires = int(time.time()) + int(morsel.get("max-age"))
                            except Exception:
                                expires = None
                        elif morsel.get("expires"):
                            expires = self.parse_expires(morsel.get("expires"))
                        cookie_obj = self.make_cookie(name, value, domain, path, secure, expires, http_only)
                        try:
                            self.jar.set_cookie(cookie_obj)
                            ctx.log.info(f"Captured cookie {name} for {domain}{path}")
                        except Exception as e:
                            ctx.log.warn(f"Failed to set cookie {name}: {e}")
                except Exception as e:
                           pass
            self.save_cookies()

        # 2) capture sensitive request headers from the request
        saved_auth = False
        for hdr in SENSITIVE_HEADERS:
            val = flow.request.headers.get(hdr)
            if val:
                entry = self.auth_state.get(host, {})
                entry[hdr] = val
                entry["_last_updated"] = int(time.time())
                self.auth_state[host] = entry
                saved_auth = True
                ctx.log.info(f"Captured auth header {hdr} for {host}")
        if saved_auth:
            self.save_auth()

        # 3) build raw request & response bytes and write them
        raw_req = self.build_raw_request_bytes(flow.request)
        raw_resp = self.build_raw_response_bytes(flow.response)
        req_path = self.write_raw_file("request", raw_req)
        resp_path = self.write_raw_file("response", raw_resp)

        # 4) attempt to parse request body (json, form, or as base64)
        parsed_request_body = None
        try:
            if flow.request.headers.get("Content-Type", "").lower().startswith("application/json"):
                parsed_request_body = flow.request.get_text(strict=False)
                # try to JSON-parse
                try:
                    parsed_request_body = json.loads(parsed_request_body)
                except Exception:
                    # keep as raw text
                    pass
            elif flow.request.urlencoded_form:
                parsed_request_body = dict(flow.request.urlencoded_form)
            else:
                # store as base64 if not text
                if flow.request.raw_content:
                    parsed_request_body = {"__base64": base64.b64encode(flow.request.raw_content).decode("ascii")}
        except Exception as e:
            parsed_request_body = None

        # 5) attempt to parse response body similarly
        parsed_response_body = None
        try:
            if flow.response.headers.get("Content-Type", "").lower().startswith("application/json"):
                parsed_response_body = flow.response.get_text(strict=False)
                try:
                    parsed_response_body = json.loads(parsed_response_body)
                except Exception:
                    pass
            else:
                if flow.response.raw_content:
                    # store small responses as text if UTF-8 decodable
                    try:
                        txt = flow.response.get_text(strict=False)
                        parsed_response_body = txt
                    except Exception:
                        parsed_response_body = {"__base64": base64.b64encode(flow.response.raw_content).decode("ascii")}
        except Exception as e:
            parsed_response_body = None

        # 6) compose structured state entry
        entry = {
            "timestamp": int(time.time()),
            "host": host,
            "scheme": flow.request.scheme,
            "method": flow.request.method,
            "http_version": flow.request.http_version,
            "full_url": flow.request.url,
            "path": flow.request.path,
            "query": flow.request.query.fields if hasattr(flow.request.query, "fields") else flow.request.query,
            "request_headers": list(flow.request.headers.items(multi=True)),
            "response_status": flow.response.status_code,
            "response_reason": flow.response.reason,
            "response_headers": list(flow.response.headers.items(multi=True)),
            "request_body_parsed": parsed_request_body,
            "response_body_parsed": parsed_response_body,
            "request_raw_file": req_path,
            "response_raw_file": resp_path,
            "request_raw_len": len(raw_req) if raw_req else 0,
            "response_raw_len": len(raw_resp) if raw_resp else 0,
        }

        # store per-host latest
        self.state[host] = entry
        self.save_state()

        ctx.log.info(f"Saved full exchange for host {host} -> req:{req_path} resp:{resp_path}")

    def done(self):
        # on shutdown ensure saves
        self.save_cookies()
        self.save_auth()
        self.save_state()


addons = [
    FullExtractor()
]
