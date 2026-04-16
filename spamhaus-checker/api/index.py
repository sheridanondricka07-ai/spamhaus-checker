from http.server import BaseHTTPRequestHandler
import json
import urllib.request
import urllib.error
import urllib.parse
import os
import datetime
import time

# Global Token Cache to prevent login rate limits
TOKEN_CACHE = {}

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

def enrich_reason(code):
    if not code or code == "-": return code
    code_upper = str(code).upper()
    if code_upper in GLOSSARY:
        return GLOSSARY[code_upper]
    for k, v in GLOSSARY.items():
        if k in code_upper:
            return v
    return code

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        # Handle CORS
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            req_data = json.loads(post_data.decode('utf-8'))
            targets = req_data.get('targets', [])
            target_type = req_data.get('type', 'domains')
            
            results = []
            for target in targets:
                res = self.query_spamhaus(target, target_type)
                results.append(res)
                
            self.wfile.write(json.dumps(results).encode('utf-8'))
            
        except Exception as e:
            error_response = {
                "domain": "Error",
                "score": f"Server Err",
                "date": "-",
                "status": "Error",
                "statusClass": "status-error"
            }
            self.wfile.write(json.dumps(error_response).encode('utf-8'))

    def load_accounts(self):
        accounts_env = os.environ.get('SPAMHAUS_ACCOUNTS')
        if accounts_env:
            try:
                data = json.loads(accounts_env)
                return data if isinstance(data, list) else [data]
            except:
                pass
                
        try:
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else [data]
        except:
            pass
        return []

    def obtain_token(self, account):
        user = account.get('username')
        now = time.time()
        
        # Return cached token if valid
        if user in TOKEN_CACHE and TOKEN_CACHE[user]["expires"] > now:
            return TOKEN_CACHE[user]["token"]

        body = json.dumps({
            "username": user,
            "password": account.get('password'),
            "realm": account.get('realm', 'intel')
        }).encode('utf-8')
        
        req = urllib.request.Request("https://api.spamhaus.org/api/v1/login", data=body, method='POST')
        req.add_header('Content-Type', 'application/json')
        
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode('utf-8'))
                token = result.get('token')
                if token:
                    TOKEN_CACHE[user] = {"token": token, "expires": now + 82800}
                    return token
        except Exception:
            return None

    def query_spamhaus(self, target, target_type):
        accounts = self.load_accounts()
        if not accounts:
            return {"domain": target, "score": "Config Error", "smtp": "-", "date": "-", "status": "Error", "statusClass": "status-error", "type": "-", "listed_date": "-", "expiry_date": "-", "reason": "-"}

        now = time.time()

        for account in accounts:
            token = self.obtain_token(account)
            if not token:
                continue
                
            if target_type == 'ips':
                datasets = ['ALL', 'WAB']
                all_results = []
                
                for ds in datasets:
                    endpoint = f"https://api.spamhaus.org/api/intel/v1/byobject/cidr/{ds}/listed/live/{target}"
                    req = urllib.request.Request(endpoint, method='GET')
                    req.add_header('Authorization', f'Bearer {token}')
                    try:
                        with urllib.request.urlopen(req, timeout=5) as response:
                            ds_data = json.loads(response.read().decode('utf-8'))
                            all_results.extend(ds_data.get('results', []))
                    except urllib.error.HTTPError as e:
                        if e.code == 404: continue
                        if e.code == 401: TOKEN_CACHE.pop(account.get('username'), None)
                        continue
                    except:
                        continue
                
                if len(all_results) > 0:
                    # Filter active results robustly
                    active_results = []
                    for r in all_results:
                        v_until = r.get("valid_until", 0)
                        if v_until > 0 and v_until < now:
                            continue
                        active_results.append(r)
                    
                    types = set()
                    reasons = set()
                    dates = set()
                    expiries = set()
                    
                    display_results = active_results if active_results else all_results
                    
                    for record in display_results:
                        types.add(record.get("dataset", "Unknown"))
                        reasons.add(record.get("detection", record.get("rule", "Listed")))
                        
                        l_ts = record.get("listed")
                        if l_ts:
                            try: dates.add(datetime.datetime.fromtimestamp(int(l_ts)).strftime('%Y-%m-%d'))
                            except: pass
                        
                        e_ts = record.get("valid_until")
                        if e_ts:
                            try: expiries.add(datetime.datetime.fromtimestamp(int(e_ts)).strftime('%Y-%m-%d'))
                            except: pass

                    status = "Listed" if active_results else "Clean"
                    statusClass = "status-error" if active_results else "status-clean"

                    return {
                        "domain": target, 
                        "score": display_results[0].get("rule", "-"), 
                        "smtp": "-", 
                        "date": sorted(list(dates))[0] if dates else "-", 
                        "status": status, 
                        "statusClass": statusClass,
                        "type": ", ".join(sorted(list(types))),
                        "listed_date": ", ".join(sorted(list(dates))) if dates else "-",
                        "expiry_date": ", ".join(sorted(list(expiries))) if expiries else "-",
                        "reason": " | ".join(sorted(list(set(enrich_reason(r) for r in reasons))))
                    }
                else:
                    return {"domain": target, "score": "0", "smtp": "-", "date": "-", "status": "Clean", "statusClass": "status-clean", "type": "-", "listed_date": "-", "expiry_date": "-", "reason": "-"}
            
            # Domain Check
            endpoint = f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{target}"
            req = urllib.request.Request(endpoint, method='GET')
            req.add_header('Authorization', f'Bearer {token}')
            
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    data = json.loads(response.read().decode('utf-8'))
                    score = str(data.get('score', '-'))
                    val = data.get('score', 0)
                    
                    smtp_score = "-"
                    try:
                        dim_endpoint = f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{target}/dimensions"
                        dim_req = urllib.request.Request(dim_endpoint, method='GET')
                        dim_req.add_header('Authorization', f'Bearer {token}')
                        with urllib.request.urlopen(dim_req, timeout=3) as dim_res:
                            dim_data = json.loads(dim_res.read().decode('utf-8'))
                            smtp_score = str(dim_data.get('smtp', '-'))
                    except:
                        pass

                    status = "Clean"
                    statusClass = "status-clean"
                    if isinstance(val, (int, float)) and val < -5:
                        status = "Listed"
                        statusClass = "status-error"
                        
                    last_seen = data.get('last-seen', data.get('created', None))
                    date_str = "-"
                    if last_seen:
                        try:
                            date_str = datetime.datetime.fromtimestamp(int(last_seen)).strftime('%Y-%m-%d')
                        except:
                            pass
                        
                    return {
                        "domain": target, 
                        "score": score, 
                        "smtp": smtp_score, 
                        "date": date_str, 
                        "status": status, 
                        "statusClass": statusClass,
                        "type": "Domain",
                        "listed_date": "-",
                        "expiry_date": "-",
                        "reason": enrich_reason(score) if status == "Listed" else "-"
                    }
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return {"domain": target, "score": "-", "smtp": "-", "date": "-", "status": "Not Found", "statusClass": "status-clean", "type": "-", "listed_date": "-", "expiry_date": "-", "reason": "-"}
                if e.code == 401:
                    TOKEN_CACHE.pop(account.get('username'), None)
                    continue
                if e.code == 429: continue
                return {"domain": target, "score": f"HTTP {e.code}", "smtp": "-", "date": "-", "status": "Error", "statusClass": "status-error", "type": "-", "listed_date": "-", "expiry_date": "-", "reason": "-"}
            except Exception:
                continue

        return {"domain": target, "score": "All Limits Reached", "smtp": "-", "date": "-", "status": "Error", "statusClass": "status-error", "type": "-", "listed_date": "-", "expiry_date": "-", "reason": "-"}
