import http.server
import socketserver
import json
import urllib.request
import urllib.error
import traceback
import os

PORT = 8000
AUTH_TOKEN = None

# Try loading config
CONFIG = {}
if os.path.exists('config.json'):
    with open('config.json', 'r') as f:
        CONFIG = json.load(f)

def get_auth_token():
    global AUTH_TOKEN
    if AUTH_TOKEN:
        return AUTH_TOKEN
    
    # Try different potential login endpoints based on varying docs
    login_urls = [
        "https://api.spamhaus.org/api/v1/login",
        "https://api.spamhaus.com/api/v1/login"
    ]
    
    payload = json.dumps({
        "username": CONFIG.get("username", ""),
        "password": CONFIG.get("password", ""),
        "realm": "intel"
    }).encode('utf-8')
    
    last_err = None
    for url in login_urls:
        req = urllib.request.Request(url, data=payload, method='POST')
        req.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    if 'token' in data:
                        AUTH_TOKEN = data['token']
                        return AUTH_TOKEN
        except urllib.error.URLError as e:
            last_err = e
            continue
            
    print(f"Warning: Could not obtain token. Check credentials or network. {last_err}")
    return None

def check_target(target, target_type):
    token = get_auth_token()
    if not token:
        return {"domain": target, "score": "Auth Error", "date": "-", "status": "Error", "statusClass": "status-error"}

    # Base URL depends on type
    # For domains: /api/intel/v2/byobject/domain/{domain}
    # For IPs: /api/intel/v2/byobject/ip/{ip}
    
    if target_type == 'ips':
        # Validated endpoint for this account based on Spamhaus screenshot & tests
        endpoint = f"https://api.spamhaus.org/api/intel/v1/byobject/cidr/XBL/listed/history/{target}?limit=1"
    else:
        # Domain v2 endpoint throws 403 on this specific account, but maintaining structurally
        endpoint = f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{target}"
        
    req = urllib.request.Request(endpoint, method='GET')
    req.add_header('Authorization', f'Bearer {token}')
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            # Extract data from v1 history array if present
            if target_type == 'ips' and isinstance(data, list) and len(data) > 0:
                record = data[0]
                return {
                    "domain": target,
                    "score": record.get("rule", "-"),
                    "date": record.get("listed", "-"),
                    "status": "Listed",
                    "statusClass": "status-error"
                }
            elif isinstance(data, list) and len(data) == 0:
                return {
                    "domain": target,
                    "score": "0",
                    "date": "-",
                    "status": "Clean",
                    "statusClass": "status-clean"
                }
            
            score = str(data.get('score', '-'))
            # Evaluate reputation internally if no clear label
            val = data.get('score', 0)
            status = "Clean"
            statusClass = "status-clean"
            if isinstance(val, (int, float)) and val < -5:
                status = "Listed"
                statusClass = "status-error"
                
            last_seen = data.get('last-seen', data.get('created', None))
            date_str = "-"
            if last_seen:
                import datetime
                try:
                    date_str = datetime.datetime.fromtimestamp(int(last_seen)).strftime('%Y-%m-%d')
                except:
                    pass
                
            return {
                "domain": target,
                "score": score,
                "date": date_str,
                "status": status,
                "statusClass": statusClass
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"domain": target, "score": "-", "date": "-", "status": "Not Found", "statusClass": "status-clean"}
        elif e.code == 401:
            global AUTH_TOKEN
            AUTH_TOKEN = None # force re-auth next time
            return {"domain": target, "score": "Unauthorized", "date": "-", "status": "Error", "statusClass": "status-error"}
        return {"domain": target, "score": f"HTTP {e.code}", "date": "-", "status": "Error", "statusClass": "status-error"}
    except Exception as e:
        return {"domain": target, "score": "Timeout/Err", "date": "-", "status": "Error", "statusClass": "status-error"}


class ProxyHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/check' or self.path == '/api/index':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                body = json.loads(post_data.decode('utf-8'))
                targets = body.get('targets', [])
                target_type = body.get('type', 'domains')
                
                results = []
                for t in targets:
                    results.append(check_target(t, target_type))
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"results": results}).encode('utf-8'))
                
            except Exception as e:
                traceback.print_exc()
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

Handler = ProxyHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving app and API proxy at http://localhost:{PORT}")
    httpd.serve_forever()
