import http.server
import socketserver
import json
import urllib.request
import urllib.error
import traceback
import os
import socket
import ssl
import smtplib
import concurrent.futures
from datetime import datetime, timezone

import dns.resolver
import whois

PORT = 8000
AUTH_TOKEN = None

# Try loading config (accepts either a single account object or a list of accounts)
CONFIG = {}
if os.path.exists('config.json'):
    with open('config.json', 'r') as f:
        loaded = json.load(f)
        CONFIG = loaded[0] if isinstance(loaded, list) and loaded else loaded

# ============================================================
# DNS / Email Scoring Engine
# ============================================================

def check_spf(domain):
    """Check SPF record. Returns dict with exists, record, strictness, score (0-1.5)"""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=spf1'):
                score = 0.5  # SPF exists
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
    """Check DKIM by trying common selectors. Returns dict with exists, selector, score (0-1.5)"""
    common_selectors = [
        "default", "google", "selector1", "selector2",  # Microsoft
        "k1", "k2", "k3",  # Mailchimp
        "s1", "s2",  # Generic
        "dkim", "mail", "email",
        "mandrill", "smtp", "cm",  # Campaign Monitor
        "pic",  # Postmark
        "protonmail", "protonmail2", "protonmail3",
        "everlytickey1", "everlytickey2",
        "sig1",  # HubSpot
        "mailjet",
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
    # Also try CNAME records for DKIM
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
    """Check DMARC record. Returns dict with exists, policy, score (0-2.0)"""
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
    """Check MX records. Returns dict with exists, records list, score (0-1.5)"""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        records = []
        for rdata in answers:
            records.append({"priority": rdata.preference, "host": str(rdata.exchange).rstrip('.')})
        if records:
            score = 1.0
            if len(records) >= 2:
                score = 1.5  # Redundancy bonus
            return {"exists": True, "records": records[:5], "score": score}
    except Exception:
        pass
    return {"exists": False, "records": [], "score": 0}


def check_bimi(domain):
    """Check BIMI record (Brand Indicators for Message Identification). Score 0-0.5"""
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
    """Check if MX hosts have proper reverse DNS (PTR). Score 0-0.5"""
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        for rdata in mx_answers:
            mx_host = str(rdata.exchange).rstrip('.')
            try:
                # Resolve MX to IP
                a_answers = dns.resolver.resolve(mx_host, 'A')
                for a_rdata in a_answers:
                    ip = str(a_rdata)
                    # Reverse lookup
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
    """Check domain age via WHOIS. Older domains score higher. Score 0-1.0"""
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
            
            if age_years >= 5:
                score = 1.0
            elif age_years >= 2:
                score = 0.7
            elif age_years >= 1:
                score = 0.5
            elif age_years >= 0.5:
                score = 0.3
            else:
                score = 0.1
            
            return {"exists": True, "creation_date": str(creation_date)[:10], "age_years": round(age_years, 1), "score": score}
    except Exception:
        pass
    return {"exists": False, "creation_date": None, "age_years": None, "score": 0}


def check_smtp_tls(domain):
    """Check if MX server supports STARTTLS. Score 0-1.0"""
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        mx_host = str(list(mx_answers)[0].exchange).rstrip('.')
        
        smtp = smtplib.SMTP(timeout=5)
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
    """
    Compute a comprehensive emailing score from 0.0 to 10.0 based on real DNS checks.
    
    Scoring breakdown (max 10.0):
    - SPF:        0 - 1.5 points
    - DKIM:       0 - 1.5 points
    - DMARC:      0 - 2.0 points  (most important for Gmail)
    - MX:         0 - 1.5 points
    - BIMI:       0 - 0.5 points  (Gmail blue checkmark)
    - PTR:        0 - 0.5 points  (reverse DNS)
    - Domain Age: 0 - 1.0 points  (trust signal)
    - SMTP TLS:   0 - 1.0 points  (encryption)
    Total max: 9.5 → normalized to 10.0
    """
    results = {}
    
    # Run checks with threading for speed
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
    
    # Calculate total raw score
    raw_total = sum(r.get('score', 0) for r in results.values())
    max_possible = 9.5
    
    # Normalize to 0-10 scale
    normalized_score = round(min((raw_total / max_possible) * 10.0, 10.0), 1)
    
    # Determine grade
    if normalized_score >= 8.5:
        grade = "A+"
        grade_class = "grade-excellent"
    elif normalized_score >= 7.0:
        grade = "A"
        grade_class = "grade-good"
    elif normalized_score >= 5.5:
        grade = "B"
        grade_class = "grade-average"
    elif normalized_score >= 4.0:
        grade = "C"
        grade_class = "grade-below"
    elif normalized_score >= 2.0:
        grade = "D"
        grade_class = "grade-poor"
    else:
        grade = "F"
        grade_class = "grade-fail"
    
    return {
        "score": normalized_score,
        "grade": grade,
        "grade_class": grade_class,
        "raw_total": round(raw_total, 2),
        "max_possible": max_possible,
        "checks": results
    }


# ============================================================
# Spamhaus API (existing)
# ============================================================

def get_auth_token():
    global AUTH_TOKEN
    if AUTH_TOKEN:
        return AUTH_TOKEN
    
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

    if target_type == 'ips':
        endpoint = f"https://api.spamhaus.org/api/intel/v1/byobject/cidr/XBL/listed/history/{target}?limit=1"
    else:
        endpoint = f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{target}"
        
    req = urllib.request.Request(endpoint, method='GET')
    req.add_header('Authorization', f'Bearer {token}')
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            
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
            AUTH_TOKEN = None
            return {"domain": target, "score": "Unauthorized", "date": "-", "status": "Error", "statusClass": "status-error"}
        return {"domain": target, "score": f"HTTP {e.code}", "date": "-", "status": "Error", "statusClass": "status-error"}
    except Exception as e:
        return {"domain": target, "score": "Timeout/Err", "date": "-", "status": "Error", "statusClass": "status-error"}


def check_domain_full(domain):
    """Check a domain: Spamhaus + Email Score"""
    # Get Spamhaus result
    spamhaus = check_target(domain, 'domains')
    
    # Get email score
    email_result = compute_email_score(domain)
    
    # Merge results
    spamhaus['email_score'] = email_result['score']
    spamhaus['email_grade'] = email_result['grade']
    spamhaus['email_grade_class'] = email_result['grade_class']
    spamhaus['email_checks'] = email_result['checks']
    
    return spamhaus


# ============================================================
# HTTP Server
# ============================================================

class ProxyHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/check':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                body = json.loads(post_data.decode('utf-8'))
                targets = body.get('targets', [])
                target_type = body.get('type', 'domains')
                
                results = []
                
                if target_type == 'domains':
                    # Use threaded processing for domains (email score + spamhaus)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                        future_map = {executor.submit(check_domain_full, t): t for t in targets}
                        for future in concurrent.futures.as_completed(future_map):
                            try:
                                results.append(future.result())
                            except Exception as e:
                                t = future_map[future]
                                results.append({
                                    "domain": t, "score": "Error", "date": "-",
                                    "status": "Error", "statusClass": "status-error",
                                    "email_score": 0, "email_grade": "F", "email_grade_class": "grade-fail",
                                    "email_checks": {}
                                })
                    # Re-order results to match input order
                    target_order = {t: i for i, t in enumerate(targets)}
                    results.sort(key=lambda r: target_order.get(r['domain'], 999))
                else:
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
        
        elif self.path == '/api/email-details':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                body = json.loads(post_data.decode('utf-8'))
                domain = body.get('domain', '')
                
                if not domain:
                    raise ValueError("No domain provided")
                
                result = compute_email_score(domain)
                result['domain'] = domain
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode('utf-8'))
                
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
