"""ThreatLens backend v4: normalise -> group -> cluster -> score -> prioritise -> explain.
Run:  python app.py   ->  http://127.0.0.1:5000
"""
import os, re, json, random, socket, sqlite3, sys, threading, time
from collections import deque
try:
    from flask import Flask, jsonify, request, send_from_directory
except ImportError:
    sys.exit("Flask is not installed. Activate your venv (venv\\Scripts\\activate) and run:  pip install flask")

BASE = os.path.dirname(os.path.abspath(__file__))          # works no matter which folder the terminal is in
STATIC = os.path.join(BASE, "static")
app = Flask(__name__, static_folder=STATIC, static_url_path="")
LOCK = threading.RLock()
EVENTS, SEQ, FEED, CACHE = deque(maxlen=500), [0], [False], {}
STATUS = ["New", "Investigating", "Resolved"]
DB = sqlite3.connect(os.path.join(BASE, "threatlens.db"), check_same_thread=False); DB.row_factory = sqlite3.Row

def reset():  # clean demo state on every start (delete this call's DROPs to persist data)
    DB.executescript("""DROP TABLE IF EXISTS incidents; DROP TABLE IF EXISTS alerts;
    CREATE TABLE incidents(id INTEGER PRIMARY KEY, k TEXT UNIQUE, type TEXT, asset TEXT, status INT DEFAULT 0, override TEXT, ts REAL);
    CREATE TABLE alerts(id INTEGER PRIMARY KEY, inc INT, ts REAL, source TEXT, sev INT, conf INT, ip TEXT, raw TEXT);"""); CACHE.clear()
reset()

# ---------------- knowledge base ----------------
TYPES = {  # business impact, kill-chain stage, response, typical severity
 "Ransomware behaviour":  (95, "Execution",    "Isolate the host, block lateral movement and start the incident-response playbook", 90),
 "Data exfiltration":     (92, "Exfiltration", "Cut the outbound connection and review data-loss logs", 85),
 "Suspicious login":      (85, "Access",       "Force a password reset, revoke sessions and check MFA logs", 65),
 "Malware signature":     (70, "Execution",    "Quarantine the endpoint and run a full scan", 70),
 "Multiple failed logins":(60, "Access",       "Temporarily lock the account and verify with its owner", 40),
 "Unusual file download": (50, "Exfiltration", "Review user activity and confirm the business need", 40),
 "Port scan":             (25, "Recon",        "Rate-limit the source and keep monitoring", 22)}
ORDER = ["Recon", "Access", "Execution", "Exfiltration"]
WEIGHTS = [1, 2, 3, 4, 10, 8, 12]
ASSETS = {"Core Banking DB": 95, "Payment Gateway": 92, "Admin Account": 90, "Web Server": 70, "HR Laptop": 45, "Guest Wi-Fi": 20}
HOSTS = {"Core Banking DB": "core-bank-db-01", "Payment Gateway": "pay-gw-prod", "Admin Account": "svc-admin@corp", "Web Server": "web-srv-03", "HR Laptop": "hr-lap-117", "Guest Wi-Fi": "guest-wifi-ap2"}
ASSET_ALIAS = [("bank", "Core Banking DB"), ("pay", "Payment Gateway"), ("admin", "Admin Account"), ("web", "Web Server"), ("hr", "HR Laptop"), ("guest", "Guest Wi-Fi")]
TYPE_ALIAS = [("ransom", "Ransomware behaviour"), ("exfil", "Data exfiltration"), ("data transfer", "Data exfiltration"), ("fail", "Multiple failed logins"),
              ("brute", "Multiple failed logins"), ("login", "Suspicious login"), ("malware", "Malware signature"), ("trojan", "Malware signature"),
              ("download", "Unusual file download"), ("scan", "Port scan"), ("recon", "Port scan")]
SOURCE_CONF = {"EDR": 88, "IAM": 80, "SIEM": 75, "DLP": 70, "Firewall": 65}   # typical fidelity of each tool
SOURCES = {"Frankfurt": (8.7, 50.1), "Singapore": (103.8, 1.35), "Virginia": (-78, 38), "São Paulo": (-46.6, -23.5), "Lagos": (3.4, 6.5),
           "Sydney": (151.2, -33.9), "Toronto": (-79.4, 43.7), "Dubai": (55.3, 25.2), "Tokyo": (139.7, 35.7)}

# five tools, five different alert formats (this is what the normaliser has to cope with)
FMT = {
 "SIEM":     lambda t, a, s, ip: {"source": "SIEM", "rule_name": t, "host": a, "severity": "critical" if s >= 90 else "high" if s >= 70 else "medium" if s >= 45 else "low", "src_ip": ip},
 "EDR":      lambda t, a, s, ip: {"source": "EDR", "detection": t, "hostname": a, "score": round(s / 10), "remote_ip": ip},
 "Firewall": lambda t, a, s, ip: {"source": "Firewall", "signature": t, "dest_host": a, "priority": 1 if s >= 70 else 2 if s >= 40 else 3, "src": ip},
 "IAM":      lambda t, a, s, ip: {"source": "IAM", "event": t, "account": a, "risk": s, "ip": ip},
 "DLP":      lambda t, a, s, ip: {"source": "DLP", "policy": t, "resource": a, "level": "H" if s >= 70 else "M" if s >= 40 else "L", "ip": ip}}
# mixed demo set: (source, raw text, host, severity, ip, repeats). Contains every edge case.
DEMO = [("EDR", "ransomware.encrypt.activity", "core-bank-db-01", 95, "203.0.113.9", 1), ("SIEM", "Ransomware behaviour detected", "core-bank-db-01", 90, "203.0.113.9", 2),   # clear critical, 2 sources
        ("IAM", "Impossible travel login", "svc-admin@corp", 40, "198.18.0.5", 1), ("SIEM", "Suspicious login from new device", "svc-admin@corp", 30, "198.18.0.5", 1), ("EDR", "Credential login anomaly", "svc-admin@corp", 50, "198.18.0.5", 1),  # many alerts -> one incident
        ("EDR", "Trojan.Gen malware detected", "guest-wifi-ap2", 90, "192.0.2.44", 2),                       # high severity, LOW-value asset
        ("Firewall", "Nmap port scan", "hr-lap-117", 25, "198.51.100.7", 3), ("IAM", "Brute force attempt - failed logins", "hr-lap-117", 30, "198.51.100.7", 3), ("DLP", "Bulk file download anomaly", "hr-lap-117", 35, "198.51.100.7", 3),  # LOW severity alerts, together a kill chain
        ("SIEM", "outbound data transfer anomaly", "pay-gw-prod", 60, "203.0.113.50", 2), ("Firewall", "Port scan", "web-srv-03", 20, "192.0.2.77", 4)]  # noise

# ---------------- 1. normalisation ----------------
def pick(raw, keys, default=None):
    return next((raw[k] for k in keys if raw.get(k) not in (None, "")), default)

def norm_sev(src, v):  # every tool uses its own scale -> one 0-100 scale
    if isinstance(v, str): return {"low": 25, "l": 25, "medium": 55, "m": 55, "high": 80, "h": 80, "critical": 95}.get(v.lower(), 50)
    v = float(v)
    return {1: 85, 2: 55, 3: 25}.get(int(v), 50) if src == "Firewall" else round(v * 10) if src == "EDR" else round(v)

def normalise(raw):
    src = str(pick(raw, ("source",), "Unknown"))
    text = str(pick(raw, ("rule_name", "detection", "signature", "event", "policy", "type"), "")).lower()
    typ = next((c for k, c in TYPE_ALIAS if k in text), None)
    if not typ: raise ValueError("unrecognised alert type: " + text)
    host = str(pick(raw, ("host", "hostname", "dest_host", "account", "resource", "asset"), "")).lower()
    return {"source": src, "type": typ, "asset": next((c for k, c in ASSET_ALIAS if k in host), host or "Unknown asset"),
            "sev": norm_sev(src, pick(raw, ("severity", "score", "priority", "risk", "level"), 50)),
            "ip": str(pick(raw, ("src_ip", "remote_ip", "src", "ip", "source_ip"), "0.0.0.0")), "conf": int(raw.get("confidence", SOURCE_CONF.get(src, 60)))}

def geo(ip): return SOURCES[list(SOURCES)[sum(map(int, re.findall(r"\d+", ip))) % len(SOURCES)]]

# ---------------- 2. grouping (alert -> incident) ----------------
def store(raw):
    a = normalise(raw); key = f"{a['type']}|{a['asset']}"; now = time.time()
    r = DB.execute("SELECT id FROM incidents WHERE k=?", (key,)).fetchone()
    iid = r["id"] if r else DB.execute("INSERT INTO incidents(k,type,asset,ts) VALUES(?,?,?,?)", (key, a["type"], a["asset"], now)).lastrowid
    DB.execute("INSERT INTO alerts(inc,ts,source,sev,conf,ip,raw) VALUES(?,?,?,?,?,?,?)", (iid, now, a["source"], a["sev"], a["conf"], a["ip"], json.dumps(raw)))
    DB.commit(); return (iid, *geo(a["ip"]))

def emit(kind, **kw): SEQ[0] += 1; EVENTS.append({"seq": SEQ[0], "kind": kind, **kw})
def level(s): return "Critical" if s >= 85 else "High" if s >= 70 else "Medium" if s >= 50 else "Low"

# ---------------- 3+4. clustering + risk scoring + reasoning ----------------
def reason(d):
    top = sorted([("severity", d["sev"]), ("asset value", d["ast"]), ("business impact", d["imp"]), ("confidence", d["conf"])], key=lambda x: -x[1])[:2]
    s = [f"{d['type']} on {d['asset']} scores {d['score']}/100 ({level(d['score'])}), driven mainly by {top[0][0]} ({top[0][1]}) and {top[1][0]} ({top[1][1]})."]
    if d["n"] > 1: s.append(f"{d['n']} alerts from {d['srcs']} source(s) ({', '.join(d['sources'])}) were normalised and grouped into one incident (+{d['grp']}).")
    if d["chain"]: s.append(f"Likely attack cluster {d['cluster']}: {' → '.join(d['stages'])} (+{d['chain']}).")
    if d["coll"]: s.append(f"Each alert is only low severity, but together they point to a coordinated problem (+{d['coll']}).")
    if d["capped"]: s.append(f"High technical severity ({d['sev']}) on a low-value asset, so priority is capped below High to avoid false urgency.")
    if d["override"]: s.append(f"Analyst override: priority set to {d['override']}.")
    return " ".join(s)

def score_one(m, chain, coll, cid, label, stages):
    ast = ASSETS.get(m["asset"], 50); imp = round((TYPES[m["type"]][0] + ast) / 2)
    conf = min(100, round(m["conf"] + 4 * (m["srcs"] - 1)))                # corroboration by several tools
    grp = min(10, (m["n"] - 1) * 2)
    score = min(100, round(.30 * m["sev"] + .25 * ast + .25 * imp + .20 * conf + grp + chain + coll))
    capped = m["sev"] >= 80 and ast < 30                                   # edge case: severe alert, worthless asset
    if capped: score = min(score, 69)
    eff = {"Critical": 90, "High": 75, "Medium": 55, "Low": 30}.get(m["override"], score)
    d = dict(id=m["id"], type=m["type"], asset=m["asset"], n=m["n"], srcs=m["srcs"], sources=m["names"].split(","), sev=m["sev"], ast=ast, imp=imp, conf=conf,
             grp=grp, chain=chain, coll=coll, capped=capped, cluster=cid, cluster_label=label, stages=stages, score=score, eff=eff, level=level(eff),
             override=m["override"], status=m["status"], status_name=STATUS[m["status"]], action=TYPES[m["type"]][2])
    d["reason"] = reason(d); return d

def rescore(force_ids=()):
    """Dynamic: runs after every ingest, so a new alert can re-rank the whole queue."""
    rows = DB.execute("""SELECT i.*, COUNT(a.id) n, MAX(a.sev) sev, AVG(a.conf) conf, COUNT(DISTINCT a.source) srcs,
        GROUP_CONCAT(DISTINCT a.source) names, GROUP_CONCAT(DISTINCT a.ip) ips FROM incidents i JOIN alerts a ON a.inc=i.id GROUP BY i.id""").fetchall()
    par = {r["id"]: r["id"] for r in rows}
    def find(x):
        while par[x] != x: par[x] = par[par[x]]; x = par[x]
        return x
    seen = {}
    for r in rows:   # stretch: incidents sharing an asset or an attacker IP belong to one likely cluster
        for key in [("a", r["asset"])] + [("ip", ip) for ip in r["ips"].split(",") if ip != "0.0.0.0"]:
            if key in seen: par[find(r["id"])] = find(seen[key])
            else: seen[key] = r["id"]
    groups = {}
    for r in rows: groups.setdefault(find(r["id"]), []).append(r)
    old = {k: v["eff"] for k, v in CACHE.items()}; CACHE.clear(); no = 0
    for ms in sorted(groups.values(), key=lambda g: min(m["id"] for m in g)):
        multi = len(ms) > 1; stages = sorted({TYPES[m["type"]][1] for m in ms}, key=ORDER.index)
        chain = min(20, 8 * (len(stages) - 1)) if multi else 0                       # kill-chain progression
        coll = 12 if multi and max(m["sev"] for m in ms) < 45 and sum(m["n"] for m in ms) >= 6 else 0   # many small alerts = big problem
        cid = label = None
        if multi: no += 1; cid = f"C{no}"; label = " → ".join(stages) + " · " + ", ".join(sorted({m["asset"] for m in ms}))
        for m in ms: CACHE[m["id"]] = score_one(m, chain, coll, cid, label, stages)
    for i, d in CACHE.items():
        if d["eff"] >= 85 and d["status"] < 2 and (old.get(i, 0) < 85 or i in force_ids): emit("critical", incident=d)

def ingest(raws, force=False):
    with LOCK:
        got = []
        for r in raws:
            try: got.append(store(r))
            except (ValueError, KeyError): pass
        rescore({g[0] for g in got} if force else set())
        for iid, lon, lat in got[-30:]: emit("alert", lon=lon, lat=lat, level=CACHE[iid]["level"])
        return [CACHE[g[0]] for g in got]

def stats():
    a = DB.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]; v = list(CACHE.values()); i = len(v)
    return {"alerts": a, "incidents": i, "critical": sum(d["eff"] >= 85 and d["status"] < 2 for d in v), "noise": round(100 * (1 - i / a)) if a else 0,
            "avg": round(sum(d["eff"] for d in v) / i) if i else 0}

def set_field(iid, col, val):
    with LOCK: DB.execute(f"UPDATE incidents SET {col}=? WHERE id=?", (val, iid)); DB.commit(); rescore()

def rand_alert():
    t = random.choices(list(TYPES), WEIGHTS)[0]; a = random.choice(list(HOSTS)); s = max(5, min(99, TYPES[t][3] + random.randint(-12, 12)))
    return FMT[random.choice(list(FMT))](t, HOSTS[a], s, f"{random.randint(11,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")

def demo_alerts():
    out = [FMT[s](t, h, v, ip) for s, t, h, v, ip, n in DEMO for _ in range(n)]; random.shuffle(out); return out

def feed():
    while True:
        time.sleep(2.4)
        if FEED[0]: ingest([rand_alert()])

# ---------------- SOC copilot ----------------
def llm_answer(msg, rows, st):
    if not os.getenv("ANTHROPIC_API_KEY"): return None
    try:
        import anthropic
        r = anthropic.Anthropic().messages.create(model="claude-sonnet-5-5", max_tokens=450,
            system="You are ThreatLens Copilot, an expert SOC assistant. Answer briefly using ONLY the incident data provided and cite incident IDs.",
            messages=[{"role": "user", "content": f"STATS: {json.dumps(st)}\nINCIDENTS: {json.dumps(rows)}\nQUESTION: {msg}"}])
        return r.content[0].text
    except Exception: return None

def line(d): return f"#{d['id']} {d['type']} on {d['asset']} — {d['eff']}/100 ({d['level']}, {d['n']} alerts)"

def copilot(msg):
    m = msg.lower().strip()
    with LOCK:
        rows = sorted([d for d in CACHE.values() if d["status"] < 2], key=lambda d: -d["eff"]); st = stats()
    ai = llm_answer(msg, [{k: d[k] for k in ("id", "type", "asset", "eff", "level", "n", "sources", "cluster_label", "reason", "status_name")} for d in rows[:10]], st)
    if ai: return ai
    num = re.search(r"#?\b(\d+)\b", m)
    tgt = next((d for d in rows if d["asset"].lower() in m or d["type"].lower() in m), None)
    if num: tgt = next((d for d in rows if d["id"] == int(num.group(1))), tgt)
    if re.search(r"\b(resolve|close|fixed)\b", m) and tgt: set_field(tgt["id"], "status", 2); return f"Done — #{tgt['id']} ({tgt['type']} on {tgt['asset']}) is Resolved."
    if re.search(r"\binvestigate\b", m) and tgt and "first" not in m: set_field(tgt["id"], "status", 1); return f"Marked #{tgt['id']} as Investigating. First step: {tgt['action']}."
    if re.search(r"\b(hi|hello|hey)\b", m): return "Hi, I'm ThreatLens Copilot. Ask what to investigate first, about attack clusters, or why an incident (e.g. #3) got its priority."
    if not rows: return "No open incidents — the queue is clear."
    if re.search(r"cluster|chain|pattern|correlat", m):
        cl = {d["cluster"]: d["cluster_label"] for d in rows if d["cluster"]}
        return ("Likely incident clusters:\n" + "\n".join(f"• {k}: {v}" for k, v in cl.items())) if cl else "No multi-stage clusters detected right now."
    if re.search(r"first|priorit|urgent|top|start|most", m) and not tgt:
        t = rows[0]; return f"Investigate this first:\n{line(t)}\n\nWhy: {t['reason']}\nAction: {t['action']}.\n\nThen:\n" + "\n".join("• " + line(d) for d in rows[1:3])
    if "critical" in m:
        c = [d for d in rows if d["eff"] >= 85]; return ("Open critical incidents:\n" + "\n".join("• " + line(d) for d in c)) if c else "No open critical incidents right now."
    if re.search(r"noise|how many|stat|summar|overview|status", m):
        return f"{st['alerts']} alerts were normalised and grouped into {st['incidents']} incidents — {st['noise']}% less noise. {st['critical']} critical open; average risk {st['avg']}/100."
    if re.search(r"score|scoring|formula|how.*work|calculat", m):
        return ("Risk = 30% severity + 25% asset value + 25% business impact + 20% confidence, plus grouping (+10 max), attack-cluster (+20 max) and "
                "low-severity-pattern (+12) boosts. High-severity alerts on low-value assets are capped below High. Analysts can override priority.")
    if tgt: return f"{tgt['reason']}\nRecommended action: {tgt['action']}."
    return "Try: 'What should I investigate first?', 'Show attack clusters', 'Why is #3 high?' or 'Resolve #2'."

# ---------------- API ----------------
@app.get("/")
def home(): return send_from_directory(STATIC, "index.html")

@app.get("/api/state")
def state():
    since = int(request.args.get("since", -1))
    with LOCK:
        inc = sorted(CACHE.values(), key=lambda d: (d["status"] == 2, -d["eff"], -d["score"]))[:30]
        cl = {}
        for d in CACHE.values():
            if d["cluster"]: cl[d["cluster"]] = {"id": d["cluster"], "label": d["cluster_label"]}
        recent = [dict(r) for r in DB.execute("SELECT a.source, a.sev, i.type, i.asset FROM alerts a JOIN incidents i ON i.id=a.inc ORDER BY a.id DESC LIMIT 6")]
        ev = [] if since < 0 else [e for e in EVENTS if e["seq"] > since]
        events = [e for e in ev if e["kind"] == "alert"][-30:] + [e for e in ev if e["kind"] == "critical"]
        return jsonify(seq=SEQ[0], stats=stats(), incidents=inc, clusters=list(cl.values()), recent=recent, events=events)

@app.post("/api/ingest")  # real integration: POST one alert (any supported tool format) or a list of them
def api_ingest():
    d = request.get_json(force=True); res = ingest(d if isinstance(d, list) else [d])
    return jsonify(incidents=res) if res else (jsonify(error="could not normalise alert"), 400)

@app.post("/api/load-demo")
def load_demo():
    with LOCK: reset(); FEED[0] = False
    ingest(demo_alerts()); return jsonify(stats=stats())

@app.post("/api/simulate")
def simulate():
    t = random.choice(["Ransomware behaviour", "Data exfiltration"]); a = "Core Banking DB" if t[0] == "R" else "Payment Gateway"
    return jsonify(ingest([FMT["EDR"](t, HOSTS[a], random.randint(92, 99), "203.0.113.%d" % random.randint(2, 250))], force=True))

@app.post("/api/burst")
def burst():
    ingest([rand_alert() for _ in range(min(int((request.get_json(silent=True) or {}).get("n", 200)), 500))])
    return simulate()

@app.post("/api/feed")
def toggle_feed(): FEED[0] = not FEED[0]; return jsonify(on=FEED[0])

@app.post("/api/incidents/<int:iid>/status")
def api_status(iid): set_field(iid, "status", int(request.get_json(force=True)["status"])); return jsonify(ok=True)

@app.post("/api/incidents/<int:iid>/priority")
def api_priority(iid): set_field(iid, "override", request.get_json(force=True).get("level") or None); return jsonify(ok=True)

@app.post("/api/chat")
def chat(): return jsonify(reply=copilot(request.get_json(force=True).get("message") or ""))

def free_port(start=5000):
    for p in range(start, start + 20):
        with socket.socket() as k:
            if k.connect_ex(("127.0.0.1", p)) != 0: return p
    return start
# ======================================================================
#  ThreatLens AI SUITE  (paste ABOVE:  if __name__ == "__main__":)
# ======================================================================
import math, statistics
from datetime import datetime

def llm_text(system, user, tokens=500):
    if not os.getenv("ANTHROPIC_API_KEY"): return None
    try:
        import anthropic
        r = anthropic.Anthropic().messages.create(model="claude-sonnet-5-5", max_tokens=tokens, system=system,
                                                  messages=[{"role": "user", "content": user}])
        return r.content[0].text
    except Exception: return None

MITRE = {"Ransomware behaviour": ("Impact", "T1486", "Data Encrypted for Impact"),
         "Data exfiltration": ("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
         "Suspicious login": ("Initial Access", "T1078", "Valid Accounts"),
         "Malware signature": ("Execution", "T1204", "User Execution"),
         "Multiple failed logins": ("Credential Access", "T1110", "Brute Force"),
         "Unusual file download": ("Collection", "T1005", "Data from Local System"),
         "Port scan": ("Discovery", "T1046", "Network Service Discovery")}

NEXT = {"Port scan": [("Multiple failed logins", .45), ("Suspicious login", .25), ("Malware signature", .15)],
        "Multiple failed logins": [("Suspicious login", .55), ("Malware signature", .20), ("Unusual file download", .10)],
        "Suspicious login": [("Unusual file download", .35), ("Malware signature", .25), ("Data exfiltration", .20)],
        "Malware signature": [("Ransomware behaviour", .30), ("Data exfiltration", .30), ("Suspicious login", .15)],
        "Unusual file download": [("Data exfiltration", .60), ("Ransomware behaviour", .10)],
        "Data exfiltration": [("Ransomware behaviour", .20)], "Ransomware behaviour": []}

PLAYBOOK = {
 "Ransomware behaviour": [("Isolate the host from the network", "auto"), ("Block the attacker IP at the firewall", "auto"), ("Snapshot memory and disk for forensics", "auto"), ("Disable affected service accounts", "approve"), ("Restore from the last clean backup", "approve")],
 "Data exfiltration": [("Cut the outbound connection", "auto"), ("Block the destination IP/domain", "auto"), ("Pull data-loss logs to size the leak", "auto"), ("Rotate credentials on the source system", "approve"), ("Notify the data-protection officer", "approve")],
 "Suspicious login": [("Revoke active sessions", "auto"), ("Force MFA re-enrolment", "auto"), ("Review the last 24h of account activity", "auto"), ("Reset the password", "approve")],
 "Malware signature": [("Quarantine the endpoint", "auto"), ("Run a full EDR scan", "auto"), ("Hunt for the same hash fleet-wide", "auto"), ("Re-image the machine", "approve")],
 "Multiple failed logins": [("Temporarily lock the account", "auto"), ("Rate-limit the source IP", "auto"), ("Verify with the account owner", "approve")],
 "Unusual file download": [("Snapshot the user session", "auto"), ("Review the files accessed", "auto"), ("Confirm the business need with the manager", "approve")],
 "Port scan": [("Rate-limit the source IP", "auto"), ("Add the IP to the watchlist", "auto"), ("Block the source if the scan repeats", "approve")]}

ACTLOG, AUTO, HANDLED = deque(maxlen=40), [False], set()

def geo_name(ip): return list(SOURCES)[sum(map(int, re.findall(r"\d+", ip))) % len(SOURCES)]
def _members(d): return [x for x in CACHE.values() if d["cluster"] and x["cluster"] == d["cluster"]] or [d]

def _mitre_of(d):
    seen = {}
    for m in _members(d):
        t, i, n = MITRE[m["type"]]; seen[i] = {"tactic": t, "id": i, "name": n}
    return list(seen.values())

def ai_predict(d):
    have = {m["type"] for m in _members(d)}; best = {}
    for m in _members(d):
        for t, p in NEXT.get(m["type"], []):
            if t in have: continue
            p = min(.97, p * (.7 + d["eff"] / 100 * .6))          # hotter incident -> likelier escalation
            if p > best.get(t, (0, ""))[0]: best[t] = (p, m["type"])
    return [{"type": t, "prob": round(p * 100), "eta_min": max(3, round(45 * (1 - p))), "from": f, "mitre": MITRE[t][1]}
            for t, (p, f) in sorted(best.items(), key=lambda kv: -kv[1][0])[:3]]

def ai_fp(d):  # logistic estimate that an incident is benign
    x = 3.0 - .025 * d["conf"] - .025 * d["sev"] - .4 * (d["srcs"] - 1) - .1 * min(d["n"], 10) - (.8 if d["cluster"] else 0)
    return round(100 / (1 + math.exp(-x)))

def ai_anomaly():
    now, B, N = time.time(), 10, 36; counts = [0] * N          # 36 buckets x 10 s
    for r in DB.execute("SELECT ts FROM alerts WHERE ts>?", (now - B * N,)).fetchall():
        k = int((now - r["ts"]) // B)
        if 0 <= k < N: counts[N - 1 - k] += 1
    base, cur = counts[:-3], counts[-3:]
    mu, sd = statistics.mean(base), max(1.0, statistics.pstdev(base))
    rate = sum(cur) / 3; z = round((rate - mu) / sd, 1)
    status = "Surge" if z >= 3 else "Elevated" if z >= 1.5 else "Normal"
    note = {"Surge": f"Alert volume is {z} standard deviations above baseline - possible storm or coordinated attack.",
            "Elevated": "Volume is rising above the normal baseline - keep an eye on new clusters.",
            "Normal": "Alert volume is within the normal baseline."}[status]
    return {"series": counts, "z": z, "rate": round(rate * 6), "base": round(mu * 6), "status": status, "note": note}

def _persona(types):
    t = set(types)
    if "Ransomware behaviour" in t: return "Ransomware operator"
    if "Data exfiltration" in t and t & {"Suspicious login", "Multiple failed logins", "Malware signature"}: return "APT-style intruder"
    if "Data exfiltration" in t: return "Data thief"
    if t & {"Multiple failed logins", "Suspicious login"}: return "Credential attacker"
    if "Malware signature" in t: return "Malware campaign"
    return "Opportunistic scanner"

def ai_attackers():
    rows = DB.execute("""SELECT a.ip, COUNT(*) n, COUNT(DISTINCT a.inc) incs, MAX(a.sev) sev, GROUP_CONCAT(DISTINCT i.type) types
                         FROM alerts a JOIN incidents i ON i.id=a.inc WHERE a.ip!='0.0.0.0' GROUP BY a.ip""").fetchall()
    out = []
    for r in rows:
        sc = min(100, round(.5 * r["sev"] + 12 * r["incs"] + 2 * r["n"]))
        out.append({"ip": r["ip"], "origin": geo_name(r["ip"]), "profile": _persona(r["types"].split(",")), "alerts": r["n"],
                    "incidents": r["incs"], "score": sc, "action": "Block at perimeter" if sc >= 70 else "Rate-limit and watch"})
    return sorted(out, key=lambda x: -x["score"])[:6]

def _run_playbook(d, approve=False, who="Analyst"):
    stamp = datetime.now().strftime("%H:%M:%S"); log = []
    for step, mode in PLAYBOOK[d["type"]]:
        log.append(f"[{stamp}] ✔ {step} (simulated)" if mode == "auto" or approve else f"[{stamp}] ⏸ {step} - waiting for human approval")
    done = sum("✔" in l for l in log)
    ACTLOG.appendleft(f"{stamp} {who}: #{d['id']} {d['type']} -> {done}/{len(log)} steps run")
    if d["status"] == 0: set_field(d["id"], "status", 1)
    return log

def _autopilot():
    while True:
        time.sleep(3)
        if not AUTO[0]: continue
        with LOCK:
            for d in [x for x in CACHE.values() if x["eff"] >= 85 and x["status"] == 0]:
                key = (d["id"], d["type"], d["asset"])
                if key not in HANDLED: HANDLED.add(key); _run_playbook(d, False, "Autopilot")
threading.Thread(target=_autopilot, daemon=True).start()

def ai_brief():
    with LOCK:
        rows = sorted([d for d in CACHE.values() if d["status"] < 2], key=lambda d: -d["eff"])
        st, an, atk = stats(), ai_anomaly(), ai_attackers()[:3]
        cl = sorted({d["cluster_label"] for d in rows if d["cluster"]}); pred = ai_predict(rows[0]) if rows else []
    posture = "SEVERE" if st["critical"] >= 2 or an["status"] == "Surge" else "ELEVATED" if st["critical"] else \
              "GUARDED" if any(d["level"] == "High" for d in rows) else "STABLE"
    facts = {"posture": posture, "stats": st, "traffic": an["status"], "top": [line(d) for d in rows[:3]], "clusters": cl,
             "forecast": pred[:2], "attackers": atk, "actions": [rows[0]["action"]] if rows else []}
    txt = llm_text("You are the SOC's AI analyst briefing a non-technical executive. Using ONLY the JSON facts, write under 140 words: "
                   "posture, what matters most, what happens next, and a closing 'Decisions needed' line.", json.dumps(facts))
    if txt: return {"text": txt, "engine": "Claude", "posture": posture}
    if not rows: return {"text": "No open incidents. The queue is clear.", "engine": "Rule engine", "posture": posture}
    L = [f"• Volume: {st['alerts']} alerts reduced to {st['incidents']} incidents ({st['noise']}% noise removed). Traffic is {an['status'].lower()} (z={an['z']}).",
         f"• Top risk: {line(rows[0])}. Action: {rows[0]['action']}."]
    if cl: L.append("• Attack clusters: " + "; ".join(cl))
    if pred: L.append(f"• Forecast: {pred[0]['prob']}% chance of {pred[0]['type']} within ~{pred[0]['eta_min']} min.")
    if atk: L.append(f"• Top source: {atk[0]['ip']} ({atk[0]['origin']}) - {atk[0]['profile']}, score {atk[0]['score']}.")
    crit = [d for d in rows if d["eff"] >= 85]
    L.append("• Decisions needed: approve containment on " + ", ".join(f"#{d['id']}" for d in crit) + "." if crit else "• Decisions needed: none right now.")
    return {"text": "\n".join(L), "engine": "Rule engine", "posture": posture}

# ---- smarter copilot: wraps the existing copilot(), nothing is replaced ----
_base_copilot = copilot
def copilot(msg):
    m = msg.lower()
    with LOCK:
        rows = sorted([d for d in CACHE.values() if d["status"] < 2], key=lambda d: -d["eff"])
        num = re.search(r"#?\b(\d+)\b", m)
        tgt = next((d for d in rows if num and d["id"] == int(num.group(1))), None) or (rows[0] if rows else None)
        if re.search(r"playbook|contain|isolate|mitigate", m) and tgt:
            return "Playbook executed (simulated):\n" + "\n".join(_run_playbook(tgt, False, "Copilot"))
        if re.search(r"brief|sitrep|executive", m): return ai_brief()["text"]
        if re.search(r"anomal|spike|surge|storm|unusual (traffic|volume)", m):
            a = ai_anomaly(); return f"Traffic is {a['status']}: {a['rate']} alerts/min vs baseline {a['base']}/min (z={a['z']}). {a['note']}"
        if re.search(r"attacker|threat actor|who.*(attack|behind)|\bips?\b|origin", m):
            a = ai_attackers()[:3]
            return "Top threat sources:\n" + "\n".join(f"• {x['ip']} ({x['origin']}) - {x['profile']}, score {x['score']}, {x['incidents']} incidents. {x['action']}." for x in a) if a else "No attacker IPs recorded yet."
        if re.search(r"false.?positive|benign|likely noise", m):
            fp = sorted(rows, key=lambda d: -ai_fp(d))[:3]
            return "Most likely false positives:\n" + "\n".join(f"• {line(d)} - {ai_fp(d)}% benign likelihood" for d in fp) if fp else "No open incidents."
        if re.search(r"mitre|att&ck|tactic|technique", m) and tgt:
            return f"MITRE ATT&CK for #{tgt['id']}:\n" + "\n".join(f"• {x['tactic']} - {x['id']} {x['name']}" for x in _mitre_of(tgt))
        if re.search(r"predict|forecast|next move|next step|happen next", m) and tgt:
            p = ai_predict(tgt)
            if not p: return f"#{tgt['id']} looks like the last stage of its chain. Focus on containment: {tgt['action']}."
            return f"Forecast for {line(tgt)}:\n" + "\n".join(f"• {x['prob']}% -> {x['type']} (~{x['eta_min']} min, {x['mitre']})" for x in p) + f"\nGet ahead of it: {tgt['action']}."
    return _base_copilot(msg)

# ---- AI API ----
@app.get("/api/ai/overview")
def ai_overview_api():
    with LOCK: return jsonify(anomaly=ai_anomaly(), attackers=ai_attackers(), autopilot=AUTO[0], log=list(ACTLOG)[:8])

@app.get("/api/ai/incident/<int:iid>")
def ai_incident_api(iid):
    with LOCK:
        d = CACHE.get(iid)
        if not d: return jsonify(error="unknown incident"), 404
        pred = ai_predict(d); involved = {m["asset"] for m in _members(d)}
        crown = [a for a, v in ASSETS.items() if v >= 90 and a not in involved] if any(p["type"] in ("Data exfiltration", "Ransomware behaviour") for p in pred) else []
        return jsonify(id=iid, type=d["type"], asset=d["asset"], eff=d["eff"], level=d["level"], fp=ai_fp(d), mitre=_mitre_of(d),
                       predictions=pred, at_risk=crown, playbook=[{"step": s, "mode": m} for s, m in PLAYBOOK[d["type"]]])

@app.post("/api/ai/playbook/<int:iid>/run")
def ai_run_api(iid):
    with LOCK:
        d = CACHE.get(iid)
        if not d: return jsonify(error="unknown incident"), 404
        return jsonify(log=_run_playbook(d, bool((request.get_json(silent=True) or {}).get("approve")), "Analyst"))

@app.post("/api/ai/autopilot")
def ai_autopilot_api(): AUTO[0] = not AUTO[0]; return jsonify(on=AUTO[0])

@app.post("/api/ai/brief")
def ai_brief_api(): return jsonify(ai_brief())
# ====================== END AI SUITE ======================
# ======================================================================
#  ZERO-TRUST STREAM ACCESS  (paste ABOVE:  if __name__ == "__main__":)
# ======================================================================
import ipaddress, secrets, math
from html import escape
from datetime import datetime, timedelta
from flask import session
from werkzeug.security import generate_password_hash, check_password_hash

DEMO_MODE = True   # True = location/network simulators + detailed denial reasons. Set False in production.
app.secret_key = os.getenv("TL_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", PERMANENT_SESSION_LIFETIME=timedelta(minutes=30))
DB.execute("""CREATE TABLE IF NOT EXISTS access_log(id INTEGER PRIMARY KEY, ts REAL, user TEXT, role TEXT, stream TEXT,
              allowed INT, ip TEXT, zone TEXT, loc TEXT, reasons TEXT)"""); DB.commit()

# ---------- roles / users (demo accounts: password = demo123, or env TL_DEMO_PASSWORD) ----------
ROLE_RANK = {"viewer": 1, "analyst": 2, "senior": 3, "admin": 4}
_pw = generate_password_hash(os.getenv("TL_DEMO_PASSWORD", "demo123"))
USERS = {n: {"role": r, "hash": _pw} for n, r in [("viewer1", "viewer"), ("analyst1", "analyst"), ("senior1", "senior"), ("admin1", "admin")]}
DUMMY = generate_password_hash("not-a-real-password")
REVOKED, FAILS, LAST, DENIES, ALERTED = {}, {}, {}, {}, {}

# ---------- network zones + physical sites (lat, lon, geofence radius in metres) ----------
ZONES = {"SOC LAN": ["10.10.0.0/16"], "Corp VPN": ["10.20.0.0/16"], "Localhost": ["127.0.0.0/8", "::1/128"]}
SITES = {"SOC (Hebbal)": (13.0450, 77.6215, 150), "Data Centre": (12.8452, 77.6602, 200), "Head Office": (12.9756, 77.6068, 150)}
SIM_IP = {"SOC LAN": "10.10.4.20", "Corp VPN": "10.20.7.9", "Public internet": "49.37.12.8"}                       # demo only
SIM_POS = {"At SOC": (13.0450, 77.6215, 10), "At Data Centre": (12.8452, 77.6602, 10),
           "At Head Office": (12.9756, 77.6068, 10), "Off-site": (12.9116, 77.6389, 15)}                         # demo only

# ---------- stream catalogue + policy ----------
STREAMS = {
 "cam-lobby":   dict(name="Branch lobby CCTV", kind="video", asset="Guest Wi-Fi", level="Internal", role="viewer", zones=["SOC LAN", "Corp VPN", "Localhost"], sites=None),
 "log-web":     dict(name="Web server access log", kind="log", asset="Web Server", level="Internal", role="analyst", zones=["SOC LAN", "Corp VPN", "Localhost"], sites=None),
 "log-core":    dict(name="Core Banking DB audit log", kind="log", asset="Core Banking DB", level="Confidential", role="analyst", zones=["SOC LAN", "Corp VPN"], sites=["SOC (Hebbal)", "Head Office"]),
 "cam-dc-cage": dict(name="Data-centre cage 4 CCTV", kind="video", asset="Core Banking DB", level="Restricted", role="senior", zones=["SOC LAN"], sites=["SOC (Hebbal)", "Data Centre"]),
 "log-admin":   dict(name="Admin privileged-session log", kind="log", asset="Admin Account", level="Restricted", role="senior", zones=["SOC LAN"], sites=["SOC (Hebbal)"]),
 "cam-vault":   dict(name="Cash vault CCTV", kind="video", asset="Payment Gateway", level="Restricted", role="admin", zones=["SOC LAN"], sites=["Head Office"])}

# ---------- helpers ----------
def _dist_m(a, b, c, d):
    p1, p2 = math.radians(a), math.radians(c); h = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(d - b) / 2) ** 2
    return 2 * 6371000 * math.asin(math.sqrt(h))

def client_ip(b):
    ip = request.remote_addr or "0.0.0.0"          # never trust X-Forwarded-For unless behind your own proxy (use ProxyFix)
    sim = b.get("sim_net")
    return SIM_IP[sim] if DEMO_MODE and isinstance(sim, str) and sim in SIM_IP else ip

def zone_of(ip):
    try: a = ipaddress.ip_address(ip)
    except ValueError: return "Public internet"
    return next((z for z, nets in ZONES.items() if any(a in ipaddress.ip_network(n) for n in nets)), "Public internet")

def resolve_location(b):
    sim = b.get("sim_site")
    if DEMO_MODE and isinstance(sim, str) and sim in SIM_POS: return (*SIM_POS[sim], "simulated")
    try: lat, lon, acc, ts = float(b["lat"]), float(b["lon"]), float(b.get("acc", 9999)), float(b.get("ts", 0)) / 1000
    except (KeyError, TypeError, ValueError): return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180) or abs(time.time() - ts) > 30: return None   # stale / replayed fix
    return lat, lon, acc, "gps"

def current_user():
    n = session.get("u"); u = USERS.get(n)
    if not u or session.get("iat", 0) < REVOKED.get(n, 0): return None
    return {"name": n, "role": u["role"]}

def decide(u, sid, b, ip):
    s, zone, checks = STREAMS[sid], zone_of(ip), []
    checks.append({"name": "Role", "ok": ROLE_RANK[u["role"]] >= ROLE_RANK[s["role"]], "detail": f"{u['role']} - needs {s['role']} or higher"})
    checks.append({"name": "Network", "ok": zone in s["zones"], "detail": f"{zone} ({ip}) - allowed: {', '.join(s['zones'])}"})
    loc, locs = resolve_location(b), "none"
    if not s["sites"]: checks.append({"name": "Location", "ok": True, "detail": "No physical restriction"})
    elif not loc: checks.append({"name": "Location", "ok": False, "detail": "No fresh location fix shared"})
    else:
        lat, lon, acc, src = loc; locs = f"{lat:.4f},{lon:.4f}"
        n, d = min(((n, _dist_m(lat, lon, SITES[n][0], SITES[n][1])) for n in s["sites"]), key=lambda x: x[1]); lim = SITES[n][2]
        ok = d <= lim and acc <= 200                       # coarse fixes (Wi-Fi/IP based, km-level) are rejected
        checks.append({"name": "Location", "ok": ok, "detail": f"{round(d)} m from {n} (limit {lim} m, accuracy ±{round(acc)} m, {src})"})
    return {"allowed": all(c["ok"] for c in checks), "checks": checks, "zone": zone, "loc": locs}

def public_checks(dec):   # in production, don't tell an attacker WHICH factor failed in detail
    return [{"name": c["name"], "ok": c["ok"], **({"detail": c["detail"]} if DEMO_MODE else {})} for c in dec["checks"]]

def record(u, sid, dec, ip, opened):
    key = (u["name"], sid); changed = LAST.get(key) != dec["allowed"]; LAST[key] = dec["allowed"]
    if not (changed or opened): return
    why = ", ".join(c["name"] for c in dec["checks"] if not c["ok"]) or "policy satisfied"
    with LOCK:
        DB.execute("INSERT INTO access_log(ts,user,role,stream,allowed,ip,zone,loc,reasons) VALUES(?,?,?,?,?,?,?,?,?)",
                   (time.time(), u["name"], u["role"], sid, int(dec["allowed"]), ip, dec["zone"], dec["loc"], why)); DB.commit()
    if dec["allowed"] or STREAMS[sid]["level"] == "Internal": return
    q = DENIES.setdefault(u["name"], deque(maxlen=5)); q.append(time.time())
    if len(q) >= 3 and q[-1] - q[-3] < 120 and time.time() - ALERTED.get(u["name"], 0) > 300:   # self-defence: feed ThreatLens itself
        ALERTED[u["name"]] = time.time()
        ingest([FMT["IAM"]("Multiple failed logins - blocked restricted stream access", HOSTS[STREAMS[sid]["asset"]], 70, ip)])

# ---------- log streams + role-based field masking ----------
LOGTPL = {"log-web": ["INFO  GET /login 200 {ip} user={u}", "INFO  POST /api/transfer 201 {ip} user={u} acct={a}", "WARN  POST /login 401 {ip} user={u}", "ERROR GET /admin 403 {ip} user={u}", "WARN  GET /../../etc/passwd 400 {ip}"],
          "log-core": ["INFO  SELECT balance FROM accounts acct={a} by user={u} from {ip}", "INFO  UPDATE accounts SET balance acct={a} by user={u} from {ip}", "WARN  bulk export 40000 rows by user={u} from {ip}", "ERROR privilege escalation attempt user={u} from {ip}"],
          "log-admin": ["INFO  sudo session opened user={u} from {ip}", "WARN  admin password reset for user={u} from {ip}", "ERROR MFA bypass attempt user={u} from {ip}", "INFO  key rotation completed by user={u}"]}
FAKE_USERS = ["svc_batch", "j.rao", "m.iyer", "k.nair", "root", "dbadmin", "s.khan"]
LOGBUF = {s: deque(maxlen=200) for s in LOGTPL}; LOGSEQ = {s: 0 for s in LOGTPL}; LOGT = {s: 0 for s in LOGTPL}

def _gen(sid):
    now = time.time(); n = min(5, int((now - LOGT[sid]) / 1.2))
    if n <= 0: return
    LOGT[sid] = now; tpl = LOGTPL[sid]
    for _ in range(n):
        ip = f"{random.randint(11,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        l = random.choices(tpl, weights=[5, 3, 2, 1, 1][:len(tpl)])[0].format(ip=ip, u=random.choice(FAKE_USERS), a="".join(random.choices("0123456789", k=12)))
        LOGSEQ[sid] += 1; LOGBUF[sid].append((LOGSEQ[sid], time.strftime("%H:%M:%S ") + l))

def mask(line, role):
    r = ROLE_RANK[role]
    if r < 4: line = re.sub(r"\b(\d{4})\d{4}(\d{4})\b", r"\1****\2", line)                       # account numbers
    if r < 3:
        line = re.sub(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b", r"\1.xxx", line)              # IP addresses
        line = re.sub(r"user=\S+", "user=****", line)                                            # usernames
    return line

# ---------- watermarked synthetic CCTV frame ----------
def cctv_svg(sid, who):
    s, t = STREAMS[sid], time.time(); w, nm = escape(who), escape(s["name"]); stamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    px, py = 320 + 200 * math.sin(t / 4), 250 + 10 * math.sin(t / 1.3)
    if sid == "cam-dc-cage":
        scene = "".join(f'<rect x="{50+i*110}" y="60" width="85" height="190" fill="#0d1830" stroke="#22d3ee" stroke-opacity=".3"/><circle cx="{65+i*110}" cy="80" r="3" fill="#34d399"><animate attributeName="opacity" values="1;.2;1" dur="{1+i*.37:.2f}s" repeatCount="indefinite"/></circle>' for i in range(5))
    elif sid == "cam-vault":
        scene = '<rect x="200" y="50" width="240" height="210" rx="14" fill="#0d1830" stroke="#8b5cf6" stroke-width="3"/><circle cx="320" cy="155" r="55" fill="none" stroke="#22d3ee" stroke-width="4"/><circle cx="320" cy="155" r="8" fill="#22d3ee"/>'
    else:
        scene = '<rect x="60" y="140" width="220" height="60" fill="#0d1830" stroke="#22d3ee" stroke-opacity=".3"/><rect x="460" y="50" width="110" height="200" fill="#0b1326" stroke="#8fa0bf" stroke-opacity=".4"/>'
    wm = "".join(f'<text x="{x}" y="{y}">{w} {stamp}</text>' for y in range(20, 460, 80) for x in range(-120, 700, 320))
    lines = "".join(f'<rect y="{i*4}" width="640" height="1"/>' for i in range(90))
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 360"><rect width="640" height="360" fill="#070d1a"/>'
            f'<path d="M0 260 L640 260 L640 360 L0 360Z" fill="#0a1426"/>{scene}'
            f'<g transform="translate({px:.1f} {py:.1f})"><circle cy="-62" r="11" fill="#9db4d8"/><rect x="-11" y="-50" width="22" height="48" rx="8" fill="#6f87b0"/></g>'
            f'<g fill="#fff" fill-opacity=".035">{lines}</g>'
            f'<g transform="rotate(-20 320 180)" fill="#fff" fill-opacity=".11" font-family="monospace" font-size="14">{wm}</g>'
            f'<circle cx="24" cy="24" r="6" fill="#ff3b4e"><animate attributeName="opacity" values="1;0;1" dur="1.2s" repeatCount="indefinite"/></circle>'
            f'<g fill="#e6edf7" font-family="monospace" font-size="13"><text x="38" y="29">REC · {nm}</text><text x="628" y="29" text-anchor="end">{stamp}</text>'
            f'<text x="16" y="348">{s["level"].upper()} · viewer {w}</text></g></svg>')

@app.after_request
def _sec_headers(r):
    if request.path.startswith("/api/secure"): r.headers["Cache-Control"] = "no-store"; r.headers["X-Content-Type-Options"] = "nosniff"
    return r

# ---------- API ----------
@app.post("/api/secure/login")
def sec_login():
    b = request.get_json(silent=True) or {}; name = str(b.get("user", "")); key = (request.remote_addr, name); now = time.time()
    f = [t for t in FAILS.get(key, []) if now - t < 300]
    if len(f) >= 5: return jsonify(error="Too many attempts - try again in a few minutes"), 429
    u = USERS.get(name)
    if not check_password_hash(u["hash"] if u else DUMMY, str(b.get("password", ""))) or not u:
        f.append(now); FAILS[key] = f; return jsonify(error="Invalid credentials"), 401
    FAILS.pop(key, None); session.clear(); session.permanent = True; session["u"] = name; session["iat"] = now
    return jsonify(user=name, role=u["role"])

@app.post("/api/secure/logout")
def sec_logout(): session.clear(); return jsonify(ok=True)

@app.post("/api/secure/overview")
def sec_overview():
    b = request.get_json(silent=True) or {}; u = current_user(); ip = client_ip(b)
    out = {"demo": DEMO_MODE, "zone": zone_of(ip), "ip": ip, "user": u, "streams": []}
    if DEMO_MODE and not u: out["demo_users"] = [{"name": n, "role": v["role"]} for n, v in USERS.items()]
    if u:
        for i, s in STREAMS.items():
            d = decide(u, i, b, ip)
            out["streams"].append(dict(id=i, name=s["name"], kind=s["kind"], level=s["level"],
                                       policy={"role": s["role"], "zones": s["zones"], "sites": s["sites"] or []},
                                       decision={"allowed": d["allowed"], "checks": public_checks(d)}))
    return jsonify(out)

@app.post("/api/secure/stream/<sid>")
def sec_stream(sid):
    u = current_user()
    if not u: return jsonify(error="Sign in required"), 401
    if sid not in STREAMS: return jsonify(error="Unknown stream"), 404
    b = request.get_json(silent=True) or {}; ip = client_ip(b); dec = decide(u, sid, b, ip)
    record(u, sid, dec, ip, bool(b.get("open")))
    if not dec["allowed"]: return jsonify(allowed=False, checks=public_checks(dec)), 403
    out = {"allowed": True, "checks": public_checks(dec)}
    if STREAMS[sid]["kind"] == "video": out["frame"] = cctv_svg(sid, u["name"])
    else:
        try: since = int(b.get("since", 0))
        except (TypeError, ValueError): since = 0
        with LOCK:
            _gen(sid)
            out["lines"] = [{"seq": q, "line": mask(l, u["role"])} for q, l in LOGBUF[sid] if q > since][-40:]; out["seq"] = LOGSEQ[sid]
    return jsonify(out)

@app.post("/api/secure/audit")
def sec_audit():
    u = current_user()
    if not u: return jsonify(error="Sign in required"), 401
    full = ROLE_RANK[u["role"]] >= 3
    with LOCK:
        rows = [dict(r) for r in DB.execute("SELECT * FROM access_log " + ("" if full else "WHERE user=? ") + "ORDER BY id DESC LIMIT 25", () if full else (u["name"],))]
    return jsonify(rows=rows, can_revoke=u["role"] == "admin", users=[n for n in USERS if n != u["name"]] if u["role"] == "admin" else [])

@app.post("/api/secure/revoke")
def sec_revoke():
    u = current_user()
    if not u or u["role"] != "admin": return jsonify(error="Admin only"), 403
    n = str((request.get_json(silent=True) or {}).get("user", ""))
    if n not in USERS: return jsonify(error="Unknown user"), 404
    REVOKED[n] = time.time()
    with LOCK:
        DB.execute("INSERT INTO access_log(ts,user,role,stream,allowed,ip,zone,loc,reasons) VALUES(?,?,?,?,?,?,?,?,?)",
                   (time.time(), u["name"], u["role"], "(admin)", 1, request.remote_addr, "-", "-", f"revoked all sessions of {n}")); DB.commit()
    return jsonify(ok=True)
# ====================== END ZERO-TRUST ======================

if __name__ == "__main__":
    if not os.path.exists(os.path.join(STATIC, "index.html")):
        sys.exit("Cannot find static/index.html next to app.py - put index.html, style.css and script.js inside a folder named 'static'.")
    ingest(demo_alerts())                       # start with the mixed demo alert set already loaded
    threading.Thread(target=feed, daemon=True).start()
    port = free_port()
    print(f"\n  ThreatLens is running  ->  open http://127.0.0.1:{port}  in Chrome (Ctrl+C to stop)\n")
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False, threaded=True)
