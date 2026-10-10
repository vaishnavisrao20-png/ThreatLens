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

if __name__ == "__main__":
    if not os.path.exists(os.path.join(STATIC, "index.html")):
        sys.exit("Cannot find static/index.html next to app.py - put index.html, style.css and script.js inside a folder named 'static'.")
    ingest(demo_alerts())                       # start with the mixed demo alert set already loaded
    threading.Thread(target=feed, daemon=True).start()
    port = free_port()
    print(f"\n  ThreatLens is running  ->  open http://127.0.0.1:{port}  in Chrome (Ctrl+C to stop)\n")
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False, threaded=True)