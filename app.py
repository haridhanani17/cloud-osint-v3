"""
CloudOSINT Toolkit v3.0
========================
Full real-world cloud OSINT platform.
Modules: CRT.sh · DNS · Wayback · HackerTarget · VirusTotal · 
         Cloud Storage (AWS/Azure/GCP) · GitHub · Shodan · Censys ·
         Firebase · Azure AD · AWS IAM · Risk Scoring
"""

from flask import Flask, render_template, request, jsonify, Response
import threading, queue, json, time, datetime, socket
import requests, dns.resolver
import os, hashlib, re
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

app = Flask(__name__)
app.secret_key = os.urandom(24)

scan_results = {}
scan_queues  = {}
scan_status  = {}

# ─── Helpers ──────────────────────────────────────────────────────────────────
def ts():
    return datetime.datetime.utcnow().strftime('%H:%M:%S')

def emit(sid, etype, data):
    if sid in scan_queues:
        scan_queues[sid].put({"type": etype, "data": data, "time": ts()})

def safe_get(url, timeout=12, headers=None, auth=None, params=None):
    try:
        h = {"User-Agent": "CloudOSINT/3.0 Security-Research"}
        if headers:
            h.update(headers)
        return requests.get(url, timeout=timeout, headers=h, auth=auth, params=params, allow_redirects=True)
    except Exception as e:
        return None

# ─── MODULE 1: Certificate Transparency (crt.sh) ──────────────────────────────
def mod_crt_sh(domain, sid):
    emit(sid, "phase", {"id":"crt","status":"running"})
    emit(sid, "info",  f"[CRT.SH] Querying certificate transparency for *.{domain}")
    r = safe_get(f"https://crt.sh/?q=%.{domain}&output=json")
    found = []
    if r and r.status_code == 200:
        try:
            seen = set()
            for c in r.json():
                for name in c.get("name_value","").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and "." in name and name not in seen and domain in name:
                        seen.add(name)
                        found.append({
                            "subdomain": name,
                            "issuer": c.get("issuer_name","")[:55],
                            "not_before": c.get("not_before","")[:10],
                            "not_after":  c.get("not_after","")[:10],
                            "source": "crt.sh"
                        })
        except:
            pass
    emit(sid, "crt_results", found[:150])
    emit(sid, "success", f"[CRT.SH] {len(found)} subdomains from certificate logs")
    emit(sid, "phase", {"id":"crt","status":"done","count":len(found)})
    return found

# ─── MODULE 2: Wayback Machine CDX subdomain mining ───────────────────────────
def mod_wayback(domain, sid):
    emit(sid, "phase", {"id":"wayback","status":"running"})
    emit(sid, "info",  f"[WAYBACK] Mining Wayback Machine CDX for *.{domain}")
    found = set()
    r = safe_get(
        "https://web.archive.org/cdx/search/cdx",
        params={"url": f"*.{domain}", "output": "json", "fl": "original", "collapse": "urlkey", "limit": "5000"},
        timeout=20
    )
    if r and r.status_code == 200:
        try:
            entries = r.json()
            for row in entries[1:]:
                url = row[0] if row else ""
                try:
                    from urllib.parse import urlparse
                    host = urlparse(url).hostname or ""
                    host = host.lower().strip()
                    if host and domain in host and not host.startswith("*"):
                        found.add(host)
                except:
                    pass
        except:
            pass
    result = [{"subdomain": s, "source": "wayback"} for s in found]
    emit(sid, "wayback_results", result)
    emit(sid, "success", f"[WAYBACK] {len(result)} subdomains from Wayback Machine")
    emit(sid, "phase", {"id":"wayback","status":"done","count":len(result)})
    return result

# ─── MODULE 3: HackerTarget API ───────────────────────────────────────────────
def mod_hackertarget(domain, sid):
    emit(sid, "phase", {"id":"hackertarget","status":"running"})
    emit(sid, "info",  f"[HACKERTARGET] Querying HackerTarget host search for {domain}")
    found = []
    r = safe_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
    if r and r.status_code == 200 and "error" not in r.text.lower()[:20]:
        for line in r.text.strip().split("\n"):
            parts = line.split(",")
            if len(parts) >= 2:
                sub = parts[0].strip().lower()
                ip  = parts[1].strip()
                if domain in sub:
                    found.append({"subdomain": sub, "ip": ip, "source": "hackertarget"})
                    emit(sid, "dns_hit", {"subdomain": sub, "ips": [ip], "cloud": detect_cloud(ip), "source": "hackertarget"})
    emit(sid, "success", f"[HACKERTARGET] {len(found)} hosts found")
    emit(sid, "phase", {"id":"hackertarget","status":"done","count":len(found)})
    return found

# ─── MODULE 4: VirusTotal Passive DNS ─────────────────────────────────────────
def mod_virustotal(domain, vt_key, sid):
    if not vt_key:
        emit(sid, "warn", "[VIRUSTOTAL] No API key — skipping (add VT_API_KEY)")
        emit(sid, "phase", {"id":"virustotal","status":"skipped"})
        return []
    emit(sid, "phase", {"id":"virustotal","status":"running"})
    emit(sid, "info",  f"[VIRUSTOTAL] Querying passive DNS for {domain}")
    found = []
    r = safe_get(
        f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
        headers={"x-apikey": vt_key},
        params={"limit": "40"}
    )
    if r and r.status_code == 200:
        items = r.json().get("data", [])
        for item in items:
            sub = item.get("id","")
            if sub:
                found.append({"subdomain": sub, "source": "virustotal"})
                emit(sid, "dns_hit", {"subdomain": sub, "ips": [], "cloud": "Unknown", "source": "virustotal"})
    emit(sid, "success", f"[VIRUSTOTAL] {len(found)} subdomains from passive DNS")
    emit(sid, "phase", {"id":"virustotal","status":"done","count":len(found)})
    return found

# ─── MODULE 5: DNS Resolution + Brute Force ───────────────────────────────────
WORDLIST = [
    "www","mail","ftp","api","api-v1","api-v2","dev","staging","prod","beta","test",
    "admin","portal","dashboard","app","secure","login","auth","sso","oauth","cdn",
    "assets","static","files","images","upload","media","storage","backup","data",
    "db","database","redis","cache","queue","kafka","elastic","kibana","grafana",
    "prometheus","jenkins","gitlab","github","jira","confluence","vpn","remote",
    "citrix","owa","exchange","smtp","pop","imap","autodiscover","webmail","mx",
    "ns1","ns2","shop","pay","billing","account","support","help","docs","status",
    "health","monitor","log","logs","s3","blob","gcs","azure","aws","cloud","k8s",
    "kube","consul","vault","nomad","internal","intranet","corp","private","public",
    "sandbox","qa","uat","stg","preprod","infra","ci","cd","build","deploy","repo",
    "git","svn","npm","pip","registry","hub","proxy","gateway","lb","waf","fw",
    "vpn2","bastion","jump","mgmt","management","monitoring","alert","pagerduty",
]

def resolve_sub(sub):
    try:
        r = dns.resolver.Resolver()
        r.timeout = 3; r.lifetime = 3
        ans = r.resolve(sub, "A")
        return sub, [str(x) for x in ans]
    except:
        return sub, []

def detect_cloud(ip):
    try:
        host = socket.gethostbyaddr(ip)[0].lower()
        if any(x in host for x in ["amazonaws","aws"]): return "AWS"
        if any(x in host for x in ["azure","microsoft","windows.net"]): return "Azure"
        if any(x in host for x in ["google","gcp","googlecloud"]): return "GCP"
        if "cloudflare" in host: return "Cloudflare"
        if "fastly" in host: return "Fastly"
        if "akamai" in host: return "Akamai"
    except:
        pass
    return "Unknown"

def mod_dns(domain, extra_subs, sid):
    emit(sid, "phase", {"id":"dns","status":"running"})
    emit(sid, "info",  f"[DNS] Resolving subdomains — brute-force + aggregated sources")
    all_subs = set([f"{w}.{domain}" for w in WORDLIST])
    for e in extra_subs:
        s = e.get("subdomain","")
        if s and domain in s:
            all_subs.add(s)
    live = []
    with ThreadPoolExecutor(max_workers=60) as ex:
        futures = {ex.submit(resolve_sub, s): s for s in all_subs}
        for future in as_completed(futures):
            sub, ips = future.result()
            if ips:
                cloud = detect_cloud(ips[0])
                entry = {"subdomain": sub, "ips": ips, "cloud": cloud, "source": "dns"}
                live.append(entry)
                emit(sid, "dns_hit", entry)
    emit(sid, "success", f"[DNS] {len(live)} live hosts resolved")
    emit(sid, "phase", {"id":"dns","status":"done","count":len(live)})
    return live

# ─── MODULE 6: Cloud Storage Enumeration ──────────────────────────────────────
def check_bucket(url, name, provider):
    try:
        r = requests.get(url, timeout=7, headers={"User-Agent":"CloudOSINT/3.0"}, allow_redirects=True)
        if r.status_code == 200:
            content_hint = ""
            try:
                text = r.text[:300]
                if "<Key>" in text or "Contents" in text: content_hint = "directory listing"
                elif "{" in text: content_hint = "JSON data"
                else: content_hint = "public content"
            except: pass
            return {"name":name,"url":url,"provider":provider,"status":"PUBLIC","hint":content_hint,"severity":"critical"}
        elif r.status_code == 403:
            return {"name":name,"url":url,"provider":provider,"status":"EXISTS (private)","hint":"","severity":"info"}
    except: pass
    return None

def mod_storage(keyword, sid):
    emit(sid, "phase", {"id":"storage","status":"running"})
    emit(sid, "info",  f"[STORAGE] Enumerating AWS S3 + Azure Blob + GCP Storage for: {keyword}")
    perms = [
        keyword, f"{keyword}-prod", f"{keyword}-dev", f"{keyword}-staging",
        f"{keyword}-backup", f"{keyword}-data", f"{keyword}-assets", f"{keyword}-static",
        f"{keyword}-media", f"{keyword}-files", f"{keyword}-logs", f"{keyword}-archive",
        f"{keyword}-public", f"{keyword}-private", f"{keyword}-uploads", f"{keyword}-images",
        f"{keyword}prod", f"{keyword}dev", f"{keyword}test", f"{keyword}backup",
        f"{keyword}-db", f"{keyword}-database", f"{keyword}-config", f"{keyword}-secrets",
    ]
    checks = []
    for p in perms:
        s = p.replace("_","-").lower()
        checks += [
            (f"https://{s}.s3.amazonaws.com", s, "AWS S3"),
            (f"https://s3.amazonaws.com/{s}", s, "AWS S3"),
            (f"https://{s}.s3-website-us-east-1.amazonaws.com", s, "AWS S3"),
            (f"https://{s}.blob.core.windows.net", s, "Azure Blob"),
            (f"https://{s}.blob.core.windows.net/{s}", s, "Azure Blob"),
            (f"https://storage.googleapis.com/{s}", s, "GCP Storage"),
            (f"https://{s}.storage.googleapis.com", s, "GCP Storage"),
        ]
    found = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        futures = {ex.submit(check_bucket, url, name, prov): (url,name,prov) for url,name,prov in checks}
        for future in as_completed(futures):
            res = future.result()
            if res:
                found.append(res)
                emit(sid, "bucket_found", res)
    emit(sid, "success", f"[STORAGE] {len(found)} cloud storage resources found")
    emit(sid, "phase", {"id":"storage","status":"done","count":len(found)})
    return found

# ─── MODULE 7: GitHub OSINT ────────────────────────────────────────────────────
GH_QUERIES = [
    ("{org} AWS_ACCESS_KEY_ID",        "AWS Key",        "critical"),
    ("{org} AWS_SECRET_ACCESS_KEY",     "AWS Secret",     "critical"),
    ("{org} AKIA",                      "AWS Key Prefix", "critical"),
    ("{org} password filename:.env",    "ENV Password",   "high"),
    ("{org} api_key",                   "API Key",        "high"),
    ("{org} secret_key",                "Secret Key",     "high"),
    ("{org} terraform.tfstate",         "Terraform State","high"),
    ("{org} private_key filename:.pem", "Private Key",    "critical"),
    ("{org} db_password",               "DB Password",    "high"),
    ("{org} AIza",                      "GCP API Key",    "critical"),
    ("{org} AccountKey= azure",         "Azure Storage",  "critical"),
    ("{org} BEGIN RSA PRIVATE",         "RSA Key",        "critical"),
]

def mod_github(org, gh_token, sid):
    emit(sid, "phase", {"id":"github","status":"running"})
    emit(sid, "info",  f"[GITHUB] Scanning public repos for secrets — org/keyword: {org}")
    headers = {"Accept": "application/vnd.github.v3+json"}
    if gh_token:
        headers["Authorization"] = f"token {gh_token}"
    found = []
    for query_tpl, label, sev in GH_QUERIES:
        q = query_tpl.format(org=org)
        r = safe_get(
            "https://api.github.com/search/code",
            headers=headers,
            params={"q": q, "per_page": "5"}
        )
        if r and r.status_code == 200:
            for item in r.json().get("items", []):
                hit = {
                    "repo":     item.get("repository",{}).get("full_name",""),
                    "file":     item.get("name",""),
                    "path":     item.get("path",""),
                    "url":      item.get("html_url",""),
                    "type":     label,
                    "severity": sev
                }
                found.append(hit)
                emit(sid, "github_hit", hit)
        elif r and r.status_code == 403:
            emit(sid, "warn", "[GITHUB] Rate limited — add GitHub token for full access")
            break
        time.sleep(0.4)
    emit(sid, "success", f"[GITHUB] {len(found)} potential secret exposures found")
    emit(sid, "phase", {"id":"github","status":"done","count":len(found)})
    return found

# ─── MODULE 8: Shodan ─────────────────────────────────────────────────────────
SHODAN_QUERIES = [
    ('org:"{org}" port:9200',                        "Elasticsearch",   "critical"),
    ('org:"{org}" port:6443 ssl',                    "Kubernetes API",  "critical"),
    ('org:"{org}" port:2379',                        "etcd",            "critical"),
    ('org:"{org}" port:5601',                        "Kibana",          "high"),
    ('org:"{org}" port:3000 http.title:"Grafana"',   "Grafana",         "high"),
    ('org:"{org}" port:8080 http.title:"Dashboard"', "Web Dashboard",   "medium"),
    ('org:"{org}" port:6379',                        "Redis",           "high"),
    ('org:"{org}" port:27017',                       "MongoDB",         "critical"),
    ('org:"{org}" port:5432',                        "PostgreSQL",      "high"),
    ('org:"{org}" port:22',                          "SSH",             "medium"),
    ('org:"{org}" ssl.cert.subject.cn:*.amazonaws.com', "AWS Service",  "info"),
    ('org:"{org}" "X-Amz-Bucket-Region"',            "S3 Exposure",     "high"),
    ('org:"{org}" http.title:"phpMyAdmin"',          "phpMyAdmin",      "critical"),
    ('org:"{org}" port:4443 product:"Kubernetes"',   "K8s Dashboard",   "critical"),
]

def mod_shodan(org, api_key, sid):
    if not api_key:
        emit(sid, "warn",  "[SHODAN] No API key — skipping (add your Shodan key in config)")
        emit(sid, "phase", {"id":"shodan","status":"skipped"})
        return []
    emit(sid, "phase", {"id":"shodan","status":"running"})
    emit(sid, "info",  f"[SHODAN] Querying Shodan for org: {org}")
    found = []
    for qtpl, stype, sev in SHODAN_QUERIES:
        q = qtpl.format(org=org)
        r = safe_get("https://api.shodan.io/shodan/host/search",
                     params={"key": api_key, "query": q, "minify": "true"})
        if r and r.status_code == 200:
            data = r.json()
            total = data.get("total", 0)
            for m in data.get("matches", [])[:4]:
                hit = {
                    "ip":       m.get("ip_str",""),
                    "port":     m.get("port",""),
                    "org":      m.get("org",""),
                    "hostname": (m.get("hostnames") or [""])[0],
                    "service":  stype,
                    "country":  m.get("location",{}).get("country_name",""),
                    "severity": sev,
                    "total":    total,
                }
                found.append(hit)
                emit(sid, "shodan_hit", hit)
            if total > 0:
                emit(sid, "info", f"[SHODAN] {stype}: {total} results")
        time.sleep(1.1)
    emit(sid, "success", f"[SHODAN] {len(found)} exposed services mapped")
    emit(sid, "phase", {"id":"shodan","status":"done","count":len(found)})
    return found

# ─── MODULE 9: Censys ─────────────────────────────────────────────────────────
def mod_censys(domain, api_id, api_secret, sid):
    if not api_id or not api_secret:
        emit(sid, "warn",  "[CENSYS] No credentials — skipping (add Censys API ID + secret)")
        emit(sid, "phase", {"id":"censys","status":"skipped"})
        return []
    emit(sid, "phase", {"id":"censys","status":"running"})
    emit(sid, "info",  f"[CENSYS] Searching certificates + hosts for: {domain}")
    found = []
    # Certificate search
    r = safe_get("https://search.censys.io/api/v2/certificates/search",
                 params={"q": f"parsed.names: {domain}", "per_page": "30"},
                 auth=(api_id, api_secret))
    if r and r.status_code == 200:
        for hit in r.json().get("result",{}).get("hits",[]):
            for name in hit.get("parsed",{}).get("names",[]):
                if domain in name:
                    entry = {
                        "type": "certificate",
                        "name": name,
                        "fingerprint": hit.get("fingerprint_sha256","")[:20]+"...",
                        "source": "censys"
                    }
                    found.append(entry)
                    emit(sid, "censys_hit", entry)
    # Host search
    r2 = safe_get("https://search.censys.io/api/v2/hosts/search",
                  params={"q": f"dns.names: {domain}", "per_page": "10"},
                  auth=(api_id, api_secret))
    if r2 and r2.status_code == 200:
        for hit in r2.json().get("result",{}).get("hits",[]):
            entry = {
                "type": "host",
                "name": hit.get("ip",""),
                "fingerprint": ", ".join(str(s.get("port","")) for s in hit.get("services",[])[:5]),
                "source": "censys"
            }
            found.append(entry)
            emit(sid, "censys_hit", entry)
    emit(sid, "success", f"[CENSYS] {len(found)} entries from Censys intelligence")
    emit(sid, "phase", {"id":"censys","status":"done","count":len(found)})
    return found

# ─── MODULE 10: Firebase / GCP OSINT ──────────────────────────────────────────
def mod_firebase(keyword, sid):
    emit(sid, "phase", {"id":"firebase","status":"running"})
    emit(sid, "info",  f"[FIREBASE] Probing Firebase RTDB endpoints for: {keyword}")
    targets = [
        f"https://{keyword}.firebaseio.com/.json",
        f"https://{keyword}-default-rtdb.firebaseio.com/.json",
        f"https://{keyword}-prod.firebaseio.com/.json",
        f"https://{keyword}-dev.firebaseio.com/.json",
        f"https://{keyword}-staging.firebaseio.com/.json",
    ]
    found = []
    for url in targets:
        r = safe_get(url, timeout=8)
        if r:
            if r.status_code == 200:
                size = len(r.text)
                hit = {"url":url,"status":"OPEN — UNAUTHENTICATED ACCESS","data_size":size,"severity":"critical"}
                found.append(hit)
                emit(sid, "firebase_hit", hit)
                emit(sid, "error", f"[FIREBASE] CRITICAL: {url} is publicly readable ({size} bytes)!")
            elif r.status_code == 401:
                emit(sid, "info", f"[FIREBASE] {url.split('//')[1].split('.')[0]} — exists, auth required")
    emit(sid, "success", f"[FIREBASE] {len(found)} open Firebase databases found")
    emit(sid, "phase", {"id":"firebase","status":"done","count":len(found)})
    return found

# ─── MODULE 11: Azure AD Tenant Discovery ─────────────────────────────────────
def mod_azure_ad(domain, sid):
    emit(sid, "phase", {"id":"azure","status":"running"})
    emit(sid, "info",  f"[AZURE AD] Running tenant discovery for domain: {domain}")
    found = []
    # OpenID config
    r = safe_get(f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration")
    if r and r.status_code == 200:
        try:
            data = r.json()
            tid = data.get("token_endpoint","").split("/")[3] if data.get("token_endpoint") else "unknown"
            hit = {
                "type":      "Azure AD Tenant",
                "domain":    domain,
                "tenant_id": tid,
                "issuer":    data.get("issuer","")[:80],
                "detail":    data.get("token_endpoint","")[:80],
                "status":    "TENANT FOUND",
                "severity":  "medium"
            }
            found.append(hit)
            emit(sid, "azure_hit", hit)
            emit(sid, "success", f"[AZURE AD] Tenant ID discovered: {tid}")
        except: pass
    # Getuserinfo / UDI
    r2 = safe_get(f"https://login.microsoftonline.com/common/userrealm/{domain}?api-version=2.1")
    if r2 and r2.status_code == 200:
        try:
            d = r2.json()
            if d.get("NameSpaceType") == "Managed":
                hit2 = {
                    "type":      "O365 Managed Domain",
                    "domain":    domain,
                    "tenant_id": d.get("federation_active_auth_url","")[:40],
                    "issuer":    d.get("AuthURL","")[:80],
                    "detail":    f"MX={d.get('MX','')} / DNS={d.get('DnsDomainName','')}",
                    "status":    d.get("NameSpaceType",""),
                    "severity":  "low"
                }
                found.append(hit2)
                emit(sid, "azure_hit", hit2)
        except: pass
    # Check o365 MX
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        mx = resolver.resolve(domain, "MX")
        for m in mx:
            if "mail.protection.outlook.com" in str(m.exchange).lower():
                emit(sid, "info", f"[AZURE] O365 MX record confirmed: {m.exchange}")
    except: pass
    emit(sid, "success", f"[AZURE AD] {len(found)} Azure resources found")
    emit(sid, "phase", {"id":"azure","status":"done","count":len(found)})
    return found

# ─── MODULE 12: AWS IAM Enumeration ───────────────────────────────────────────
def mod_aws_iam(aws_key, aws_secret, sid):
    if not aws_key or not aws_secret:
        emit(sid, "warn",  "[AWS IAM] No credentials — skipping (add leaked AWS key to test)")
        emit(sid, "phase", {"id":"awsiam","status":"skipped"})
        return []
    emit(sid, "phase", {"id":"awsiam","status":"running"})
    emit(sid, "info",  "[AWS IAM] Testing AWS credentials via STS GetCallerIdentity")
    found = []
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        sts = boto3.client("sts", aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
        try:
            identity = sts.get_caller_identity()
            hit = {
                "type":       "Valid AWS Credentials",
                "account_id": identity.get("Account",""),
                "arn":        identity.get("Arn",""),
                "user_id":    identity.get("UserId",""),
                "severity":   "critical"
            }
            found.append(hit)
            emit(sid, "awsiam_hit", hit)
            emit(sid, "error", f"[AWS IAM] VALID CREDENTIALS! Account: {identity.get('Account')} ARN: {identity.get('Arn')}")
            # Try listing S3 buckets
            try:
                s3 = boto3.client("s3", aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
                buckets = s3.list_buckets().get("Buckets",[])
                for b in buckets:
                    bname = b.get("Name","")
                    bentry = {"type":"S3 Bucket (owned)","account_id":identity.get("Account",""),"arn":f"arn:aws:s3:::{bname}","user_id":bname,"severity":"high"}
                    found.append(bentry)
                    emit(sid, "awsiam_hit", bentry)
                emit(sid, "error", f"[AWS IAM] Listed {len(buckets)} S3 buckets!")
            except ClientError as e:
                emit(sid, "info", f"[AWS IAM] S3 list denied: {e.response['Error']['Code']}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidClientTokenId":
                emit(sid, "info", "[AWS IAM] Credentials invalid / expired")
            elif code == "AccessDenied":
                emit(sid, "warn", "[AWS IAM] Credentials valid but access denied — limited permissions")
                hit = {"type":"Restricted AWS Credentials","account_id":"unknown","arn":"access denied","user_id":aws_key[:8]+"...","severity":"high"}
                found.append(hit)
                emit(sid, "awsiam_hit", hit)
    except ImportError:
        emit(sid, "warn", "[AWS IAM] boto3 not installed — run: pip install boto3")
    except Exception as e:
        emit(sid, "error", f"[AWS IAM] Error: {str(e)[:80]}")
    emit(sid, "phase", {"id":"awsiam","status":"done","count":len(found)})
    return found

# ─── Risk Scoring Engine ───────────────────────────────────────────────────────
def compute_risk(buckets, github, shodan, firebase, azure, awsiam):
    score = 0
    findings = []
    for b in buckets:
        if b.get("severity") == "critical": score += 25; findings.append(f"Public bucket: {b['name']}")
        elif b.get("severity") == "info":   score += 2
    for g in github:
        if g.get("severity") == "critical": score += 20; findings.append(f"Credential leak: {g['type']} in {g['repo']}")
        elif g.get("severity") == "high":   score += 10
    for s in shodan:
        if s.get("severity") == "critical": score += 15; findings.append(f"Exposed service: {s['service']} @ {s['ip']}")
        elif s.get("severity") == "high":   score += 8
        elif s.get("severity") == "medium": score += 3
    for f in firebase:
        if f.get("severity") == "critical": score += 30; findings.append(f"Open Firebase DB: {f['url']}")
    for a in awsiam:
        if a.get("severity") == "critical": score += 50; findings.append(f"Valid AWS creds: {a['arn']}")
        elif a.get("severity") == "high":   score += 25
    for a in azure:
        if a.get("severity") == "medium": score += 5
    return min(100, score), findings[:10]

# ─── Master Orchestrator ──────────────────────────────────────────────────────
def run_scan(sid, cfg):
    scan_status[sid] = "running"
    domain     = cfg.get("domain","").strip().lower()
    keyword    = cfg.get("keyword","").strip() or domain.split(".")[0]
    org        = cfg.get("org","").strip()     or keyword
    gh_token   = cfg.get("github_token","").strip()
    sh_key     = cfg.get("shodan_key","").strip()
    ce_id      = cfg.get("censys_id","").strip()
    ce_sec     = cfg.get("censys_secret","").strip()
    vt_key     = cfg.get("vt_key","").strip()
    aws_key    = cfg.get("aws_key","").strip()
    aws_secret = cfg.get("aws_secret","").strip()

    scan_results[sid] = {
        "domain":domain,"keyword":keyword,"org":org,
        "crt":[],"wayback":[],"hackertarget":[],"virustotal":[],
        "dns_live":[],"buckets":[],"github":[],"shodan":[],
        "censys":[],"firebase":[],"azure":[],"awsiam":[],
        "summary":{},"risk_findings":[]
    }

    emit(sid, "start", f"╔══ CLOUDOSINT v3.0 — TARGET: {domain.upper()} ══╗")
    emit(sid, "info",  f"Keyword: {keyword} | Org: {org} | Modules: ALL")
    emit(sid, "info",  "━"*56)

    # ── Phase 1-4: Subdomain Intelligence
    crt   = mod_crt_sh(domain, sid)
    wb    = mod_wayback(domain, sid)
    ht    = mod_hackertarget(domain, sid)
    vt    = mod_virustotal(domain, vt_key, sid)
    scan_results[sid]["crt"]          = crt
    scan_results[sid]["wayback"]      = wb
    scan_results[sid]["hackertarget"] = ht
    scan_results[sid]["virustotal"]   = vt

    # ── Phase 5: DNS Resolution
    all_extra = crt + wb + ht + vt
    dns_live = mod_dns(domain, all_extra, sid)
    scan_results[sid]["dns_live"] = dns_live

    # ── Phase 6: Cloud Storage
    buckets = mod_storage(keyword, sid)
    scan_results[sid]["buckets"] = buckets

    # ── Phase 7: GitHub OSINT
    github = mod_github(org, gh_token, sid)
    scan_results[sid]["github"] = github

    # ── Phase 8: Shodan
    shodan = mod_shodan(org, sh_key, sid)
    scan_results[sid]["shodan"] = shodan

    # ── Phase 9: Censys
    censys = mod_censys(domain, ce_id, ce_sec, sid)
    scan_results[sid]["censys"] = censys

    # ── Phase 10: Firebase
    firebase = mod_firebase(keyword, sid)
    scan_results[sid]["firebase"] = firebase

    # ── Phase 11: Azure AD
    azure = mod_azure_ad(domain, sid)
    scan_results[sid]["azure"] = azure

    # ── Phase 12: AWS IAM
    awsiam = mod_aws_iam(aws_key, aws_secret, sid)
    scan_results[sid]["awsiam"] = awsiam

    # ── Risk scoring
    all_subs = set()
    for s in (crt+wb+ht+vt): all_subs.add(s.get("subdomain",""))
    risk_score, risk_findings = compute_risk(buckets, github, shodan, firebase, azure, awsiam)
    public_buckets = [b for b in buckets if b.get("status","") == "PUBLIC"]

    summary = {
        "total_subdomains": len(all_subs),
        "live_hosts":       len(dns_live),
        "buckets_found":    len(buckets),
        "public_buckets":   len(public_buckets),
        "github_hits":      len(github),
        "shodan_services":  len(shodan),
        "firebase_open":    len(firebase),
        "azure_tenants":    len(azure),
        "aws_iam_hits":     len(awsiam),
        "censys_hits":      len(censys),
        "risk_score":       risk_score,
    }
    scan_results[sid]["summary"]       = summary
    scan_results[sid]["risk_findings"] = risk_findings

    emit(sid, "info",    "━"*56)
    emit(sid, "summary", summary)
    if risk_findings:
        emit(sid, "warn", "[RISK] Critical findings:")
        for f in risk_findings:
            emit(sid, "error", f"  ► {f}")
    emit(sid, "complete", f"╚══ SCAN COMPLETE — Risk Score: {risk_score}/100 ══╝")
    scan_status[sid] = "done"

# ─── Flask Routes ──────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def start_scan():
    cfg = request.json or {}
    if not cfg.get("domain"):
        return jsonify({"error":"domain required"}), 400
    sid = hashlib.md5(f"{cfg['domain']}{time.time()}".encode()).hexdigest()[:12]
    scan_queues[sid] = queue.Queue()
    threading.Thread(target=run_scan, args=(sid,cfg), daemon=True).start()
    return jsonify({"scan_id": sid})

@app.route("/api/stream/<sid>")
def stream(sid):
    def gen():
        while True:
            try:
                msg = scan_queues[sid].get(timeout=90)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg["type"] in ("complete","fatal"):
                    break
            except queue.Empty:
                yield "data: {\"type\":\"ping\"}\n\n"
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route("/api/results/<sid>")
def results(sid):
    if sid not in scan_results:
        return jsonify({"error":"not found"}), 404
    return jsonify(scan_results[sid])

@app.route("/api/status/<sid>")
def status(sid):
    return jsonify({"status": scan_status.get(sid,"unknown")})

if __name__ == "__main__":
    print("\n  ╔══════════════════════════════════════════╗")
    print("  ║   CLOUDOSINT TOOLKIT  v3.0               ║")
    print("  ║   http://127.0.0.1:5000                  ║")
    print("  ╚══════════════════════════════════════════╝\n")
    app.run(debug=False, threaded=True, host="0.0.0.0", port=5000)
