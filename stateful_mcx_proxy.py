#!/usr/bin/env python3
"""
Stateful MCX Proxy - Maintains session credentials in memory
Usage: mitmdump -s stateful_mcx_proxy.py
"""

import os
import json
from datetime import datetime
from mitmproxy import http
import base64
import re

class StatefulMCXProxy:
    def __init__(self):
        self.base_dir = self.create_folder_structure()
        
        # In-memory credential storage
        self.session_credentials = {
            "cookies": {},           # Latest cookies from Firefox
            "headers": {},           # Session headers
            "tokens": {},            # CSRF tokens, session tokens
            "last_updated": None,    # When credentials were last updated
            "session_active": False  # Track if session is active
        }
        
        self.session_stats = {
            "total_requests": 0,
            "firefox_requests": 0,
            "python_requests": 0,
            "credential_updates": 0,
            "start_time": datetime.now()
        }
        
        print(f"Stateful MCX Proxy initialized")
        print(f"Logs saved to: {self.base_dir}")
        print(f"Session credentials stored in memory")
        print(f"Ready to capture and reuse MCX session state")
    
    def create_folder_structure(self):
        """Create folder structure: 2025/september/18-09-2025/"""
        now = datetime.now()
        year = str(now.year)
        month = now.strftime("%B").lower()
        date = now.strftime("%d-%m-%Y")
        
        base_path = os.path.join(year, month, date)
        os.makedirs(base_path, exist_ok=True)
        return os.path.abspath(base_path)
    
    def is_mcx_bancs_request(self, flow: http.HTTPFlow) -> bool:
        """Check if request is to MCX Bancs endpoints"""
        host = flow.request.pretty_host.lower()
        path = flow.request.path
        return (host == "eclear.mcxccl.com" and path.startswith("/Bancs/"))
    
    def extract_credentials_from_request(self, flow: http.HTTPFlow):
        """Extract and store session credentials from Firefox requests"""
        updated = False
        
        # Extract cookies
        if 'Cookie' in flow.request.headers:
            cookie_header = flow.request.headers['Cookie']
            
            # Parse cookies
            for cookie_pair in cookie_header.split(';'):
                if '=' in cookie_pair:
                    key, value = cookie_pair.strip().split('=', 1)
                    if key not in self.session_credentials["cookies"] or \
                       self.session_credentials["cookies"][key] != value:
                        self.session_credentials["cookies"][key] = value
                        updated = True
        
        # Extract important headers
        important_headers = ['User-Agent', 'Referer', 'Origin', 'X-Requested-With']
        for header in important_headers:
            if header in flow.request.headers:
                header_value = flow.request.headers[header]
                if header not in self.session_credentials["headers"] or \
                   self.session_credentials["headers"][header] != header_value:
                    self.session_credentials["headers"][header] = header_value
                    updated = True
        
        # Extract tokens from form data
        if flow.request.content and 'application/x-www-form-urlencoded' in \
           flow.request.headers.get('content-type', ''):
            try:
                body = flow.request.content.decode('utf-8')
                
                # Extract common MCX tokens
                token_patterns = {
                    'rndaak': r'rndaak=([^&]+)',
                    'IXHRts': r'IXHRts=([^&]+)',
                    'JSESSIONID': r'JSESSIONID=([^&;]+)'
                }
                
                for token_name, pattern in token_patterns.items():
                    match = re.search(pattern, body)
                    if match:
                        token_value = match.group(1)
                        if token_name not in self.session_credentials["tokens"] or \
                           self.session_credentials["tokens"][token_name] != token_value:
                            self.session_credentials["tokens"][token_name] = token_value
                            updated = True
                            
            except UnicodeDecodeError:
                pass
        
        # Extract tokens from response Set-Cookie headers
        if flow.response and 'Set-Cookie' in flow.response.headers:
            set_cookie_headers = flow.response.headers.get_all('Set-Cookie')
            for set_cookie in set_cookie_headers:
                # Parse Set-Cookie header
                cookie_parts = set_cookie.split(';')[0]  # Get name=value part
                if '=' in cookie_parts:
                    key, value = cookie_parts.split('=', 1)
                    if key not in self.session_credentials["cookies"] or \
                       self.session_credentials["cookies"][key] != value:
                        self.session_credentials["cookies"][key] = value
                        updated = True
        
        if updated:
            self.session_credentials["last_updated"] = datetime.now()
            self.session_credentials["session_active"] = True
            self.session_stats["credential_updates"] += 1
            print(f"✓ Credentials updated from Firefox - Cookies: {len(self.session_credentials['cookies'])}")
    
    def inject_credentials_to_request(self, flow: http.HTTPFlow):
        """Inject stored credentials into Python-made requests"""
        if not self.session_credentials["session_active"]:
            print("⚠ No active session credentials available")
            return False
        
        injected = False
        
        # Inject cookies
        if self.session_credentials["cookies"]:
            cookie_header = "; ".join([f"{k}={v}" for k, v in self.session_credentials["cookies"].items()])
            flow.request.headers["Cookie"] = cookie_header
            injected = True
        
        # Inject important headers
        for header, value in self.session_credentials["headers"].items():
            if header not in flow.request.headers:
                flow.request.headers[header] = value
                injected = True
        
        # Inject tokens into form data if it's a POST request
        if flow.request.method == "POST" and flow.request.content:
            try:
                body = flow.request.content.decode('utf-8')
                
                # Add missing tokens
                for token_name, token_value in self.session_credentials["tokens"].items():
                    if token_name not in body:
                        if body:
                            body += f"&{token_name}={token_value}"
                        else:
                            body = f"{token_name}={token_value}"
                        injected = True
                
                if injected:
                    flow.request.content = body.encode('utf-8')
                    flow.request.headers["Content-Length"] = str(len(flow.request.content))
                    
            except UnicodeDecodeError:
                pass
        
        if injected:
            print(f"✓ Injected credentials into Python request")
            return True
        return False
    
    def detect_request_source(self, flow: http.HTTPFlow) -> str:
        """Detect if request is from Firefox or Python script"""
        user_agent = flow.request.headers.get('User-Agent', '')
        
        # Firefox typically has "Firefox" in user agent
        if 'Firefox' in user_agent:
            return 'firefox'
        # Python requests typically have "python-requests" or similar
        elif any(python_lib in user_agent.lower() for python_lib in ['python', 'requests', 'urllib']):
            return 'python'
        # If no specific user agent, assume it's a custom Python script
        elif not user_agent or user_agent == 'python-requests/2.31.0':
            return 'python'
        else:
            return 'unknown'
    
    def save_transaction_log(self, flow: http.HTTPFlow, source: str, credentials_injected: bool = False):
        """Save transaction details for monitoring"""
        timestamp = datetime.now().strftime("%H-%M-%S-%f")[:-3]
        
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "method": flow.request.method,
            "path": flow.request.path,
            "status_code": flow.response.status_code if flow.response else None,
            "credentials_injected": credentials_injected,
            "session_active": self.session_credentials["session_active"],
            "cookie_count": len(self.session_credentials["cookies"]),
            "last_credential_update": self.session_credentials["last_updated"].isoformat() if self.session_credentials["last_updated"] else None
        }
        
        log_file = os.path.join(self.base_dir, f"transaction_{timestamp}.json")
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False)
    
    def request(self, flow: http.HTTPFlow):
        """Called when a request is received"""
        if not self.is_mcx_bancs_request(flow):
            return
        
        source = self.detect_request_source(flow)
        credentials_injected = False
        
        self.session_stats["total_requests"] += 1
        
        if source == 'firefox':
            # Extract credentials from Firefox requests
            self.extract_credentials_from_request(flow)
            self.session_stats["firefox_requests"] += 1
            print(f"🦊 Firefox request: {flow.request.method} {flow.request.path}")
            
        elif source == 'python':
            # Inject credentials into Python requests
            credentials_injected = self.inject_credentials_to_request(flow)
            self.session_stats["python_requests"] += 1
            print(f"🐍 Python request: {flow.request.method} {flow.request.path}")
        
        # Save transaction log
        self.save_transaction_log(flow, source, credentials_injected)
    
    def response(self, flow: http.HTTPFlow):
        """Called when a response is received"""
        if not self.is_mcx_bancs_request(flow):
            return
        
        source = self.detect_request_source(flow)
        
        # Extract credentials from response (like Set-Cookie headers)
        if source == 'firefox':
            self.extract_credentials_from_request(flow)
        
        # Print session stats every 5 requests
        if self.session_stats["total_requests"] % 5 == 0:
            self.print_session_status()
    
    def print_session_status(self):
        """Print current session status"""
        print(f"\n📊 Session Status:")
        print(f"   Total requests: {self.session_stats['total_requests']}")
        print(f"   Firefox: {self.session_stats['firefox_requests']}, Python: {self.session_stats['python_requests']}")
        print(f"   Credentials: {len(self.session_credentials['cookies'])} cookies, {self.session_stats['credential_updates']} updates")
        print(f"   Session active: {'✓' if self.session_credentials['session_active'] else '✗'}")
        if self.session_credentials['last_updated']:
            time_since_update = datetime.now() - self.session_credentials['last_updated']
            print(f"   Last update: {time_since_update.seconds}s ago")
        print()

# Create the addon instance
addons = [StatefulMCXProxy()]