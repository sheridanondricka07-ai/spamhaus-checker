from http.server import BaseHTTPRequestHandler
import json
import urllib.request
import urllib.error
import urllib.parse
import os
import datetime
import time
import socket
import ssl
import smtplib
import concurrent.futures
from datetime import datetime, timezone

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import whois
except ImportError:
    whois = None

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


# ============================================================
# DNS / Email Scoring Engine
# ============================================================

def check_spf(domain):
    if not dns:
        return {"exists": False, "record": None, "strictness": None, "score": 0}
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=spf1'):
                score = 0.5
                strictness = "unknown"
                if '-all' in txt:
                    score = 1.5
                    strictness = "strict (-all)"
                elif '~all' in txt:
                    score = 1.0
                    strictness = "softfail (~all)"
                elif '?all' in txt:
                    score = 0.6
                    strictness = "neutral (?all)"
                elif '+all' in txt:
                    score = 0.2
                    strictness = "permissive (+all)"
                return {"exists": True, "record": txt[:120], "strictness": strictness, "score": score}
    except Exception:
        pass
    return {"exists": False, "record": None, "strictness": None, "score": 0}


def check_dkim(domain):
    if not dns:
        return {"exists": False, "selector": None, "score": 0}
    common_selectors = [
        "default", "google", "selector1", "selector2",
        "k1", "k2", "k3", "s1", "s2", "dkim", "mail", "email",
        "mandrill", "smtp", "cm", "pic", "protonmail", "protonmail2",
        "sig1", "mailjet"
    ]
    for sel in common_selectors:
        try:
            qname = f"{sel}._domainkey.{domain}"
            answers = dns.resolver.resolve(qname, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if 'v=DKIM1' in txt or 'p=' in txt:
                    return {"exists": True, "selector": sel, "score": 1.5}
        except Exception:
            continue
    for sel in common_selectors[:6]:
        try:
            qname = f"{sel}._domainkey.{domain}"
            answers = dns.resolver.resolve(qname, 'CNAME')
            if answers:
                return {"exists": True, "selector": sel + " (CNAME)", "score": 1.5}
        except Exception:
            continue
    return {"exists": False, "selector": None, "score": 0}


def check_dmarc(domain):
    if not dns:
        return {"exists": False, "record": None, "policy": None, "has_rua": False, "has_ruf": False, "score": 0}
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if 'v=DMARC1' in txt:
                policy = "none"
                if 'p=reject' in txt:
                    policy = "reject"
                    score = 2.0
                elif 'p=quarantine' in txt:
                    policy = "quarantine"
                    score = 1.5
                elif 'p=none' in txt:
                    policy = "none"
                    score = 0.7
                else:
                    score = 0.5
                
                has_rua = 'rua=' in txt
                has_ruf = 'ruf=' in txt
                if has_rua:
                    score = min(score + 0.1, 2.0)
                
                return {"exists": True, "record": txt[:120], "policy": policy, "has_rua": has_rua, "has_ruf": has_ruf, "score": score}
    except Exception:
        pass
    return {"exists": False, "record": None, "policy": None, "has_rua": False, "has_ruf": False, "score": 0}


def check_mx(domain):
    if not dns:
        return {"exists": False, "records": [], "score": 0}
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        records = []
        for rdata in answers:
            records.append({"priority": rdata.preference, "host": str(rdata.exchange).rstrip('.')})
        if records:
            score = 1.0
            if len(records) >= 2:
                score = 1.5
            return {"exists": True, "records": records[:5], "score": score}
    except Exception:
        pass
    return {"exists": False, "records": [], "score": 0}


def check_bimi(domain):
    if not dns:
        return {"exists": False, "record": None, "score": 0}
    try:
        answers = dns.resolver.resolve(f"default._bimi.{domain}", 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if 'v=BIMI1' in txt:
                return {"exists": True, "record": txt[:120], "score": 0.5}
    except Exception:
        pass
    return {"exists": False, "record": None, "score": 0}


def check_ptr_reverse(domain):
    if not dns:
        return {"exists": False, "ip": None, "ptr": None, "score": 0}
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        for rdata in mx_answers:
            mx_host = str(rdata.exchange).rstrip('.')
            try:
                a_answers = dns.resolver.resolve(mx_host, 'A')
                for a_rdata in a_answers:
                    ip = str(a_rdata)
                    rev_name = dns.reversename.from_address(ip)
                    ptr_answers = dns.resolver.resolve(rev_name, 'PTR')
                    if ptr_answers:
                        return {"exists": True, "ip": ip, "ptr": str(ptr_answers[0]).rstrip('.'), "score": 0.5}
            except Exception:
                continue
    except Exception:
        pass
    return {"exists": False, "ip": None, "ptr": None, "score": 0}


def check_domain_age(domain):
    if not whois:
        return {"exists": False, "creation_date": None, "age_years": None, "score": 0}
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            if creation_date.tzinfo is None:
                age_days = (datetime.now() - creation_date).days
            else:
                age_days = (datetime.now(timezone.utc) - creation_date).days
            age_years = age_days / 365.25
            
            if age_years >= 5: score = 1.0
            elif age_years >= 2: score = 0.7
            elif age_years >= 1: score = 0.5
            elif age_years >= 0.5: score = 0.3
            else: score = 0.1
            
            return {"exists": True, "creation_date": str(creation_date)[:10], "age_years": round(age_years, 1), "score": score}
    except Exception:
        pass
    return {"exists": False, "creation_date": None, "age_years": None, "score": 0}


def check_smtp_tls(domain):
    if not dns:
        return {"exists": False, "host": None, "tls": None, "score": 0}
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        mx_host = str(list(mx_answers)[0].exchange).rstrip('.')
        
        smtp = smtplib.SMTP(timeout=3)
        smtp.connect(mx_host, 25)
        smtp.ehlo()
        
        if smtp.has_extn('starttls'):
            smtp.starttls()
            smtp.quit()
            return {"exists": True, "host": mx_host, "tls": True, "score": 1.0}
        else:
            smtp.quit()
            return {"exists": True, "host": mx_host, "tls": False, "score": 0.3}
    except Exception:
        pass
    return {"exists": False, "host": None, "tls": None, "score": 0}


def compute_email_score(domain):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(check_spf, domain): 'spf',
            executor.submit(check_dkim, domain): 'dkim',
            executor.submit(check_dmarc, domain): 'dmarc',
            executor.submit(check_mx, domain): 'mx',
            executor.submit(check_bimi, domain): 'bimi',
            executor.submit(check_ptr_reverse, domain): 'ptr',
            executor.submit(check_domain_age, domain): 'domain_age',
            executor.submit(check_smtp_tls, domain): 'smtp_tls',
        }
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception:
                results[key] = {"exists": False, "score": 0}
    
    raw_total = sum(r.get('score', 0) for r in results.values())
    max_possible = 9.5
    normalized_score = round(min((raw_total / max_possible) * 10.0, 10.0), 1)
    
    if normalized_score >= 8.5: grade, grade_class = "A+", "grade-excellent"
    elif normalized_score >= 7.0: grade, grade_class = "A", "grade-good"
    elif normalized_score >= 5.5: grade, grade_class = "B", "grade-average"
    elif normalized_score >= 4.0: grade, grade_class = "C", "grade-below"
    elif normalized_score >= 2.0: grade, grade_class = "D", "grade-poor"
    else: grade, grade_class = "F", "grade-fail"
    
    return {
        "score": normalized_score,
        "grade": grade,
        "grade_class": grade_class,
        "raw_total": round(raw_total, 2),
        "max_possible": max_possible,
        "checks": results
    }


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
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
            if target_type == 'domains':
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                    future_map = {executor.submit(self.query_domain_full, t): t for t in targets}
                    for future in concurrent.futures.as_completed(future_map):
                        try:
                            results.append(future.result())
                        except Exception:
                            t = future_map[future]
                            results.append({
                                "domain": t, "score": "Error", "smtp": "-", "date": "-",
                                "status": "Error", "statusClass": "status-error",
                                "email_score": 0, "email_grade": "F", "email_grade_class": "grade-fail",
                                "email_checks": {}
                            })
                target_order = {t: i for i, t in enumerate(targets)}
                results.sort(key=lambda r: target_order.get(r['domain'], 999))
            else:
                for target in targets:
                    res = self.query_spamhaus(target, target_type)
                    results.append(res)
                
            self.wfile.write(json.dumps({"results": results}).encode('utf-8'))
            
        except Exception as e:
            error_response = {
                "domain": "Error",
                "score": f"Server Err",
                "date": "-",
                "status": "Error",
                "statusClass": "status-error"
            }
            self.wfile.write(json.dumps({"error": str(e), "results": [error_response]}).encode('utf-8'))

    def query_domain_full(self, domain):
        spamhaus = self.query_spamhaus(domain, 'domains')
        email_result = compute_email_score(domain)
        
        spamhaus['email_score'] = email_result['score']
        spamhaus['email_grade'] = email_result['grade']
        spamhaus['email_grade_class'] = email_result['grade_class']
        spamhaus['email_checks'] = email_result['checks']
        return spamhaus

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
                    TOKEN_CACHE.pop(account.get('username'), None)
                    continue
                if e.code == 429: continue
                return {"domain": target, "score": f"HTTP {e.code}", "smtp": "-", "date": "-", "status": "Error", "statusClass": "status-error", "type": "-", "listed_date": "-", "expiry_date": "-", "reason": "-"}
            except Exception:
                continue

        return {"domain": target, "score": "All Limits Reached", "smtp": "-", "date": "-", "status": "Error", "statusClass": "status-error", "type": "-", "listed_date": "-", "expiry_date": "-", "reason": "-"}
