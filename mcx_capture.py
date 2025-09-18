#!/usr/bin/env python3
"""
mitmproxy addon to capture MCX traffic and save request-response data
Usage: mitmdump -s mcx_capture.py
"""

import os
import json
from datetime import datetime
from mitmproxy import http
import base64

class MCXCapture:
    def __init__(self):
        self.base_dir = self.create_folder_structure()
        self.session_stats = {
            "total_requests": 0,
            "margin_requests": 0,
            "ucc_requests": 0,
            "other_requests": 0,
            "start_time": datetime.now()
        }
        print(f"MCX Traffic will be saved to: {self.base_dir}")
        self.update_daily_summary()
    
    def create_folder_structure(self):
        """Create folder structure: 2025/september/18-09-2025/"""
        now = datetime.now()
        year = str(now.year)
        month = now.strftime("%B").lower()  # september
        date = now.strftime("%d-%m-%Y")     # 18-09-2025
        
        # For Windows, create in current directory or specify full path
        base_path = os.path.join(year, month, date)
        os.makedirs(base_path, exist_ok=True)
        
        # Get absolute path for Windows
        abs_path = os.path.abspath(base_path)
        return abs_path
    
    def is_mcx_request(self, flow: http.HTTPFlow) -> bool:
        """Check if the request is to MCX Bancs path specifically"""
        host = flow.request.pretty_host.lower()
        path = flow.request.path
        
        # Only capture requests from eclear.mcxccl.com/Bancs/
        return (host == "eclear.mcxccl.com" and path.startswith("/Bancs/"))
    
    
    def update_daily_summary(self):
        """Update daily summary statistics"""
        summary_file = os.path.join(self.base_dir, "daily_summary.json")
        
        # Create a copy of stats without the datetime object
        stats_copy = self.session_stats.copy()
        stats_copy["start_time"] = self.session_stats["start_time"].isoformat()
        
        summary_data = {
            "date": datetime.now().strftime("%Y-%m-%d"),
            "session_start": self.session_stats["start_time"].isoformat(),
            "last_updated": datetime.now().isoformat(),
            "statistics": stats_copy
        }
        
        try:
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Could not update daily summary: {e}")
    
    def save_request_response(self, flow: http.HTTPFlow):
        """Save request and response data to files"""
        if not self.is_mcx_request(flow):
            return
            
        timestamp = datetime.now().strftime("%H-%M-%S-%f")[:-3]  # HH-MM-SS-mmm
        filename_base = f"reqres_{timestamp}"
        
        # Prepare request data
        request_data = {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
            "timestamp": datetime.now().isoformat(),
            "host": flow.request.pretty_host,
            "path": flow.request.path,
            "query": dict(flow.request.query) if flow.request.query else {}
        }
        
        # Handle request body with form data parsing
        if flow.request.content:
            try:
                # Try to decode as text first
                request_body = flow.request.content.decode('utf-8')
                request_data["body"] = request_body
                request_data["body_type"] = "text"
                
                # Parse form data if it's URL-encoded
                if flow.request.headers.get('content-type', '').startswith('application/x-www-form-urlencoded'):
                    try:
                        from urllib.parse import parse_qs
                        parsed_form = parse_qs(request_body)
                        request_data["form_data"] = {k: v[0] if len(v) == 1 else v for k, v in parsed_form.items()}
                        request_data["body_type"] = "form_data"
                        
                        # Extract key MCX parameters
                        mcx_params = {}
                        for key, value in request_data["form_data"].items():
                            if any(keyword in key.lower() for keyword in ['service', 'window', 'client', 'margin', 'bpid']):
                                mcx_params[key] = value
                        
                        if mcx_params:
                            request_data["mcx_key_params"] = mcx_params
                            
                    except Exception as e:
                        request_data["form_parse_error"] = str(e)
                        
            except UnicodeDecodeError:
                # If binary, encode as base64
                request_data["body"] = base64.b64encode(flow.request.content).decode('ascii')
                request_data["body_type"] = "binary_base64"
        else:
            request_data["body"] = None
            request_data["body_type"] = "empty"
        
        # Prepare response data
        response_data = {
            "status_code": flow.response.status_code if flow.response else None,
            "headers": dict(flow.response.headers) if flow.response else {},
            "timestamp": datetime.now().isoformat(),
        }
        
        # Handle response body with MCX-specific parsing
        if flow.response and flow.response.content:
            try:
                # Try to decode as text first
                response_text = flow.response.content.decode('utf-8')
                response_data["body"] = response_text
                response_data["body_type"] = "text"
                
                # MCX-specific parsing for table data
                if 'RSK335_Table' in response_text or 'BPM215_Table' in response_text:
                    response_data["mcx_data_type"] = "table_data"
                    
                    # Extract key MCX information
                    mcx_info = {}
                    
                    # Extract service name
                    if 'service=' in flow.request.content.decode('utf-8', errors='ignore'):
                        import re
                        service_match = re.search(r'service=([^&]+)', flow.request.content.decode('utf-8', errors='ignore'))
                        if service_match:
                            mcx_info["service"] = service_match.group(1)
                    
                    # Extract window name
                    if 'windowName=' in flow.request.content.decode('utf-8', errors='ignore'):
                        window_match = re.search(r'windowName=([^&]+)', flow.request.content.decode('utf-8', errors='ignore'))
                        if window_match:
                            mcx_info["window"] = window_match.group(1)
                    
                    # Extract table data if present
                    if '<table' in response_text and '</table>' in response_text:
                        mcx_info["has_table_data"] = True
                        # Count table rows
                        row_count = response_text.count('<tr class="c_even_Row"')
                        mcx_info["table_rows"] = row_count
                    
                    # Extract IXHRts timestamp
                    if 'IXHRts#*#' in response_text:
                        timestamp_match = re.search(r'IXHRts#\*#(\d+)', response_text)
                        if timestamp_match:
                            mcx_info["server_timestamp"] = timestamp_match.group(1)
                    
                    response_data["mcx_parsed_info"] = mcx_info
                
                # If it looks like JSON, try to format it nicely
                if 'application/json' in flow.response.headers.get('content-type', ''):
                    try:
                        json_data = json.loads(response_text)
                        response_data["body_json"] = json_data
                    except json.JSONDecodeError:
                        pass
                        
            except UnicodeDecodeError:
                # If binary, encode as base64
                response_data["body"] = base64.b64encode(flow.response.content).decode('ascii')
                response_data["body_type"] = "binary_base64"
        else:
            response_data["body"] = None
            response_data["body_type"] = "empty"
        
        # Save only the combined file
        combined_data = {
            "request": request_data,
            "response": response_data,
            "summary": {
                "url_path": flow.request.path,
                "method": flow.request.method,
                "status_code": flow.response.status_code if flow.response else None,
                "content_type": flow.response.headers.get('content-type', '') if flow.response else '',
                "request_size": len(flow.request.content) if flow.request.content else 0,
                "response_size": len(flow.response.content) if flow.response and flow.response.content else 0,
                "is_margin_data": "RSK335" in flow.request.path,
                "is_ucc_data": "BPM215" in flow.request.path,
                "timestamp_readable": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "flow_info": {
                "client_conn": str(flow.client_conn.address) if flow.client_conn else None,
                "server_conn": str(flow.server_conn.address) if flow.server_conn else None,
            }
        }
        
        complete_file = os.path.join(self.base_dir, f"{filename_base}_complete.json")
        with open(complete_file, 'w', encoding='utf-8') as f:
            json.dump(combined_data, f, indent=2, ensure_ascii=False)
        
        print(f"Saved MCX Bancs traffic: {flow.request.method} {flow.request.path} -> {filename_base}_complete.json")
        
        # Update session statistics
        self.session_stats["total_requests"] += 1
        if "RSK335" in flow.request.path:
            self.session_stats["margin_requests"] += 1
        elif "BPM215" in flow.request.path:
            self.session_stats["ucc_requests"] += 1
        else:
            self.session_stats["other_requests"] += 1
        
        # Update daily summary every 5 requests
        if self.session_stats["total_requests"] % 5 == 0:
            self.update_daily_summary()
            print(f"Session Stats - Total: {self.session_stats['total_requests']}, Margin: {self.session_stats['margin_requests']}, UCC: {self.session_stats['ucc_requests']}")
    
    def response(self, flow: http.HTTPFlow):
        """Called when a response is received"""
        self.save_request_response(flow)

# Create the addon instance
addons = [MCXCapture()]