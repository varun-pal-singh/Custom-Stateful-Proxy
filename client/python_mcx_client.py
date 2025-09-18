#!/usr/bin/env python3
"""
python_mcx_client_safe.py

Safe reproducible client that:
 - Uses cookies.txt (MozillaCookieJar)
 - Uses mitmproxy CA for TLS verification
 - Uses mitmproxy on localhost:8080 as HTTP/HTTPS proxy
 - Loads saved state.json & auth_state.json (if present) to reconstruct a request
 - Injects saved auth headers into outgoing requests
 - Saves cookies and updates auth_state.json after the request
"""

import os
import sys
import json
import base64
import time
from http.cookiejar import MozillaCookieJar
import requests

# ---------- Config - EDIT THIS ----------
COOKIES_FILE = "cookies.txt"
AUTH_FILE = "auth_state.json"
STATE_FILE = "state.json"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080
PROXIES = {
    "http": f"http://{PROXY_HOST}:{PROXY_PORT}",
    "https": f"http://{PROXY_HOST}:{PROXY_PORT}",
}
# Replace this with the path to your mitmproxy-ca-cert.pem
MITM_CERT = r"C:\Users\admin01\.mitmproxy\mitmproxy-ca-cert.pem"
# Sensitive headers to import from auth_state.json
SENSITIVE_HEADERS = ["authorization", "x-auth-token", "x-xsrf-token", "cookie"]
# ---------------------------------------

def load_json_if_exists(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[warn] failed to load JSON {path}: {e}")
    return None

def save_json_atomic(path, obj):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    except Exception as e:
        print(f"[warn] failed to save JSON {path}: {e}")

def ensure_cookie_jar(path):
    jar = MozillaCookieJar(path)
    if os.path.exists(path):
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
            print(f"[info] Loaded cookie jar: {path}")
        except Exception as e:
            print(f"[warn] Could not load cookie jar {path}: {e}")
    else:
        # create an empty cookie file so other tools can see it
        try:
            jar.save(ignore_discard=True, ignore_expires=True)
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
            print(f"[info] Created empty cookie jar: {path}")
        except Exception as e:
            print(f"[warn] Could not create cookie jar {path}: {e}")
    return jar

def prepare_request_from_state(state_entry):
    """
    state_entry is the structure saved by the mitmproxy addon (see state.json example).
    Returns (method, url, headers, data, json_body)
    """
    method = state_entry.get("method", "GET")
    url = state_entry.get("full_url") or state_entry.get("url") or ""
    headers = {}
    # state stores headers as list of pairs
    for k, v in state_entry.get("request_headers", []):
        # requests lower-cases header keys automatically; keep original names
        headers[k] = v

    data = None
    json_body = None
    rb = state_entry.get("request_body_parsed")
    if rb is not None:
        if isinstance(rb, dict) and "__base64" in rb:
            data = base64.b64decode(rb["__base64"])
        else:
            # if rb is a dict -> form or parsed json
            if isinstance(rb, dict):
                # prefer JSON if content-type indicates that, but we can't reliably check here
                json_body = rb
            else:
                # rb could be text (JSON string or raw text)
                # try to detect JSON
                if isinstance(rb, str):
                    try:
                        parsed = json.loads(rb)
                        json_body = parsed
                    except Exception:
                        data = rb.encode("utf-8")
                else:
                    # fallback: raw bytes maybe
                    try:
                        data = rb
                    except Exception:
                        data = None
    return method, url, headers, data, json_body

def main():
    # Optional override URL from CLI: python script.py https://...
    override_url = sys.argv[1] if len(sys.argv) > 1 else None

    # verify mitm cert path exists
    if not os.path.exists(MITM_CERT):
        print(f"[error] MITM cert not found: {MITM_CERT}")
        print("Either set MITM_CERT to the correct path or install mitmproxy CA in system store.")
        sys.exit(1)

    # load cookie jar (create if missing)
    cj = ensure_cookie_jar(COOKIES_FILE)

    # load saved auth_state & state json if they exist
    auth_state = load_json_if_exists(AUTH_FILE) or {}
    state = load_json_if_exists(STATE_FILE) or {}

    # decide which request to replay
    request_entry = None
    if override_url:
        # If user provided URL, build a minimal entry
        request_entry = {
            "method": "GET",
            "full_url": override_url,
            "request_headers": []
        }
    elif state:
        # pick the first host entry from state.json (or you can choose by host)
        # state.json is host -> entry mapping by the mitmproxy addon
        first_key = None
        try:
            first_key = next(iter(state.keys()))
            request_entry = state[first_key]
            print(f"[info] Using saved state for host: {first_key}")
        except StopIteration:
            request_entry = None

    if not request_entry:
        print("[error] No request to replay: provide a URL as argument or ensure state.json contains saved exchanges.")
        sys.exit(1)

    # prepare method, url, headers, body from state
    method, url, saved_headers, data, json_body = prepare_request_from_state(request_entry)

    # create requests session
    sess = requests.Session()
    sess.cookies = cj
    sess.proxies = PROXIES
    sess.verify = MITM_CERT  # use mitmproxy CA for TLS verification

    # Merge headers from state into session headers
    # But don't blindly overwrite Host header (requests sets it automatically), nor Content-Length
    for k, v in saved_headers.items():
        lk = k.lower()
        if lk in ("host", "content-length"):
            continue
        # if cookie header present in saved headers, it's okay — requests will merge with cookiejar
        sess.headers[k] = v

    # Also import host-specific saved sensitive headers from auth_state.json if present
    host = None
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname
    except Exception:
        pass

    if host and host in auth_state:
        for k, v in auth_state[host].items():
            if k.startswith("_"):
                continue
            if k.lower() == "cookie":
                # cookie header may be present; we let cookiejar handle cookies
                continue
            sess.headers[k] = v
        print(f"[info] Injected saved auth headers for host {host}")

    # Do the request with retries and exception handling
    try:
        print(f"[info] Sending {method} {url}")
        resp = sess.request(method, url, data=data, json=json_body, timeout=30)
    except requests.exceptions.SSLError as e:
        print("[error] SSL error:", e)
        print("Make sure MITM_CERT path is correct and mitmproxy is running with that CA.")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print("[error] Request failed:", e)
        sys.exit(1)

    # Print summary
    print(f"[info] Response: {resp.status_code} {resp.reason}")
    print(f"[info] Response headers (first 20):")
    for i, (k, v) in enumerate(resp.headers.items()):
        if i >= 20:
            break
        print(f"  {k}: {v}")
    # Print first N chars of body safely
    preview = resp.text[:2000] if resp.text else ""
    print("\n--- response preview ---\n")
    print(preview)
    print("\n--- end preview ---\n")

    # Save cookies back to cookies.txt
    try:
        cj.save(ignore_discard=True, ignore_expires=True)
        try:
            os.chmod(COOKIES_FILE, 0o600)
        except Exception:
            pass
        print(f"[info] Saved cookies to {COOKIES_FILE}")
    except Exception as e:
        print(f"[warn] Could not save cookies: {e}")

    # Update auth_state.json with any sensitive headers from response/request
    # We store latest sensitive headers for the host
    if host:
        entry = auth_state.get(host, {})
        # from the request we used
        for h in SENSITIVE_HEADERS:
            val = sess.headers.get(h) or sess.headers.get(h.capitalize())
            if val:
                entry[h] = val
        # also capture auth-like headers from response (some servers return tokens in headers)
        for hdr in SENSITIVE_HEADERS:
            if hdr in resp.headers:
                entry[hdr] = resp.headers.get(hdr)
        entry["_last_updated"] = int(time.time())
        auth_state[host] = entry
        save_json_atomic(AUTH_FILE, auth_state)
        print(f"[info] Updated auth_state.json for host {host}")

if __name__ == "__main__":
    main()
