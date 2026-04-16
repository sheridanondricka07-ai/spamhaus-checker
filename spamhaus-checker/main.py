import http.server
import socketserver
import json
import urllib.request
import urllib.error
import traceback
import os

PORT = 8000
AUTH_TOKEN = None

GLOSSARY = {
    "CSS": "Combined Spam Sources: IPs exhibiting spam-sending behavior.",
    "SS": "Snowshoe Spam: Spread-out spam techniques (often forms part of CSS/SBL).",
    "XBL": "Exploits Block List: Hijacked IPs, infected devices, or botnets.",
    "SBL": "Spamhaus Block List: Verified spam operations and spam support services.",
    "PBL": "Policy Block List: End-user IP space that should not deliver unauthenticated SMTP email.",
    "BCL": "Botnet Controller List: IPs identified as botnet Command & Control servers.",
    "AUTHBL": "Authentication Blocklist: IPs brute-forcing SMTP/Auth protocols.",
    "DROP": "Don't Route Or Peer: Leased/hijacked networks entirely controlled by cybercriminals.",
    "DBL": "Domain Block List: Low reputation domains tied to phishing or spam.",
    "ZRD": "Zero Reputation Domains: Newly minted/observed domains (under 24h old).",
    "SPAM": "Detected bulk sending: Operations or spam trap hits.",
    "WAB": "Weak Authentication Behavior: Missing SPF, DKIM, DMARC alignment.",
    "LTB": "Low Trust Behavior: Suspicious activity not tied to bulk volume.",
    "SPAMBOT": "Infected devices/servers: Sending automated spam or serving as a proxy."
}

def enrich_reason(code, dataset=None):
    if not code or code == "-": 
        return "-", "-"
    code_upper = str(code).upper()
    ds_upper = str(dataset).upper() if dataset else ""

    for k, v in GLOSSARY.items():
        if k == code_upper or k == ds_upper or k in code_upper:
            return k, f"{k}: {v}"
            
    return code, code

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
                    "statusClass": "status-error",
                    "reason": enrich_reason(record.get("rule", "Listed"), record.get("dataset"))[1],
                    "type": enrich_reason(record.get("rule", "Listed"), record.get("dataset"))[0]
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
                "statusClass": statusClass,
                "type": enrich_reason(score) if status == "Listed" else "-",
                "reason": enrich_reason(score) if status == "Listed" else "-"
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
