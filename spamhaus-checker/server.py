import http.server
import socketserver
import json
import urllib.request
import urllib.error
import traceback
import os
import datetime
import time

PORT = 8000

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

def enrich_reason(code, dataset=None):
    if not code or code == "-": 
        return "-", "-"
    code_upper = str(code).upper()
    ds_upper = str(dataset).upper() if dataset else ""

    for k, v in GLOSSARY.items():
        if k == code_upper or k == ds_upper or k in code_upper:
            return k, f"{k}: {v}"
            
    return code, code

def load_accounts():
    if os.path.exists('config.json'):
        with open('config.json', 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return [data] # fallback for single object
    return []

def obtain_token(account):
    user = account.get("username", "")
    now = time.time()
    
    # Return cached token if still valid (using 23h as buffer)
    if user in TOKEN_CACHE and TOKEN_CACHE[user]["expires"] > now:
        return TOKEN_CACHE[user]["token"]

    payload = json.dumps({
        "username": user,
        "password": account.get("password", ""),
        "realm": account.get("realm", "intel")
    }).encode('utf-8')
    
    # Try different potential login endpoints 
    login_urls = ["https://api.spamhaus.org/api/v1/login"]
    
    for url in login_urls:
        req = urllib.request.Request(url, data=payload, method='POST')
        req.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    token = data.get('token')
                    if token:
                        TOKEN_CACHE[user] = {"token": token, "expires": now + 82800}
                        return token
        except:
            continue
    return None

def check_target(target, target_type):
    accounts = load_accounts()
    if not accounts:
        return {"domain": target, "score": "Config Error", "smtp": "-", "date": "-", "status": "Error", "statusClass": "status-error", "type": "-", "listed_date": "-", "expiry_date": "-", "reason": "-"}

    now = time.time()

    for account in accounts:
        token = obtain_token(account)
        if not token:
            continue
            
        if target_type == 'ips':
            # SIA v1 remains the standard for CIDR reputation
            # ALL includes SBL, XBL, PBL, CSS, BCL. Adding WAB explicitly.
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
                    if e.code == 401: # Token might be expired, clear cache
                        TOKEN_CACHE.pop(account.get("username"), None)
                    continue 
                except:
                    continue

            if len(all_results) > 0:
                # Filter for truly active listings
                active_results = []
                for r in all_results:
                    v_until = r.get("valid_until", 0)
                    # If valid_until is missing or 0, some datasets might still be considered active.
                    # However, if it's explicitly in the past, it's NOT active.
                    if v_until > 0 and v_until < now:
                        continue
                    active_results.append(r)
                
                types = set()
                reasons = set()
                dates = set()
                expiries = set()
                
                # Determine display records: if there are active ones, use only those.
                # If all are expired, we might still want to show the last known info but set status to Clean.
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

                res_list = [enrich_reason(r.get("detection", r.get("rule", "Listed")), r.get("dataset")) for r in display_results]
                
                return {
                    "domain": target, 
                    "score": display_results[0].get("rule", "-"), 
                    "smtp": "-", 
                    "date": sorted(list(dates))[0] if dates else "-", 
                    "status": status, 
                    "statusClass": statusClass,
                    "type": ", ".join(sorted(list(set(r[0] for r in res_list)))),
                    "listed_date": ", ".join(sorted(list(dates))) if dates else "-",
                    "expiry_date": ", ".join(sorted(list(expiries))) if expiries else "-",
                    "reason": " | ".join(sorted(list(set(r[1] for r in res_list))))
                }
            else:
                return {"domain": target, "score": "0", "smtp": "-", "date": "-", "status": "Clean", "statusClass": "status-clean", "type": "-", "listed_date": "-", "expiry_date": "-", "reason": "-"}
        else:
            # Domain Check
            endpoint = f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{target}"
            req = urllib.request.Request(endpoint, method='GET')
            req.add_header('Authorization', f'Bearer {token}')
            
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    resp_data = json.loads(response.read().decode('utf-8'))
                    
                    # Domain logic
                    score = str(resp_data.get('score', '-'))
                    val = resp_data.get('score', 0)
                    
                    smtp_score = "-"
                    if target_type == 'domains':
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
                        
                    last_seen = resp_data.get('last-seen', resp_data.get('created', None))
                    date_str = "-"
                    if last_seen:
                        try:
                            date_str = datetime.datetime.fromtimestamp(int(last_seen)).strftime('%Y-%m-%d')
                        except:
                            pass
                        
                    r_short, r_full = enrich_reason(score) if status == "Listed" else ("-", "-")
                    return {
                        "domain": target, 
                        "score": score, 
                        "smtp": smtp_score, 
                        "date": date_str, 
                        "status": status, 
                        "statusClass": statusClass,
                        "type": r_short,
                        "listed_date": "-",
                        "expiry_date": "-",
                        "reason": r_full
                    }
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return {"domain": target, "score": "-", "smtp": "-", "date": "-", "status": "Not Found", "statusClass": "status-clean", "type": "-", "listed_date": "-", "expiry_date": "-", "reason": "-"}
                if e.code == 401:
                    TOKEN_CACHE.pop(account.get("username"), None)
                    continue
                if e.code == 429: continue
                return {"domain": target, "score": f"HTTP {e.code}", "smtp": "-", "date": "-", "status": "Error", "statusClass": "status-error", "type": "-", "listed_date": "-", "expiry_date": "-", "reason": "-"}
            except Exception:
                continue
            
    return {"domain": target, "score": "All Limits Reached", "smtp": "-", "date": "-", "status": "Error", "statusClass": "status-error", "type": "-", "listed_date": "-", "expiry_date": "-", "reason": "-"}

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
                self.wfile.write(json.dumps(results).encode('utf-8'))
                
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
