#!/usr/bin/env python3
"""JAMGROUP live server: licenses (one-PC-forever) + reviews + results. stdlib only.
Run: python server.py 8080
Env: PORT=10000 (Render), ADMIN_KEY=your-secret (for posting results)
Endpoints:
 GET  /check?key=JAM-..&hwid=..            -> ALLOW / DENY (EA)
 GET  /reviews                              -> [{name,ea,stars,message,created}]
 POST /review  {name,ea,stars,message}      -> {ok:true}
 GET  /results                              -> [{ea,title,profit,note,created}]
 POST /result  {admin_key,ea,title,profit,note} -> {ok:true} (you only)
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import sqlite3, os, sys, json
from datetime import datetime
DB = os.path.join(os.path.dirname(__file__), "licenses.db")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "JAM-ADMIN-CHANGE-ME")

def db():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS licenses(key TEXT PRIMARY KEY, product TEXT, customer TEXT, hwid TEXT, created TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, ea TEXT, stars INTEGER, message TEXT, created TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY AUTOINCREMENT, ea TEXT, title TEXT, profit TEXT, note TEXT, created TEXT)")
    return c

class H(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200); self._cors(); self.end_headers()

    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self._cors()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/check":
            q = parse_qs(u.query)
            key = q.get("key", [""])[0].strip()
            hwid = q.get("hwid", [""])[0].strip()
            c = db()
            row = c.execute("SELECT hwid FROM licenses WHERE key=?", (key,)).fetchone()
            if not row: ans = "DENY:bad-key"
            elif row[0] is None and hwid:
                c.execute("UPDATE licenses SET hwid=? WHERE key=?", (hwid, key)); c.commit()
                ans = "ALLOW:first-activation-locked"
            elif row[0] == hwid: ans = "ALLOW:ok"
            else: ans = "DENY:already-used-on-another-pc"
            c.close()
            return self._send(200, ans, "text/plain")
        if u.path == "/reviews":
            c = db()
            rows = c.execute("SELECT name,ea,stars,message,created FROM reviews ORDER BY id DESC LIMIT 100").fetchall()
            c.close()
            return self._send(200, json.dumps([{"name": r[0], "ea": r[1], "stars": r[2], "message": r[3], "created": r[4]} for r in rows]))
        if u.path == "/results":
            c = db()
            rows = c.execute("SELECT ea,title,profit,note,created FROM results ORDER BY id DESC LIMIT 100").fetchall()
            c.close()
            return self._send(200, json.dumps([{"ea": r[0], "title": r[1], "profit": r[2], "note": r[3], "created": r[4]} for r in rows]))
        return self._send(404, '{"error":"not-found"}')

    def do_POST(self):
        u = urlparse(self.path)
        try: n = int(self.headers.get("Content-Length", 0))
        except: n = 0
        raw = self.rfile.read(n).decode("utf-8", "ignore") if n else "{}"
        try: data = json.loads(raw)
        except: return self._send(400, '{"error":"bad-json"}')
        if u.path == "/review":
            name = str(data.get("name", ""))[:40].strip()
            ea = str(data.get("ea", ""))[:60].strip()
            msg = str(data.get("message", ""))[:500].strip()
            try: stars = max(1, min(5, int(data.get("stars", 5))))
            except: stars = 5
            if len(name) < 2 or len(msg) < 3:
                return self._send(400, '{"error":"name and message required"}')
            bad = ["http://", "https://", "www.", ".com", ".net"]
            if any(b in msg.lower() for b in bad) and len(msg) > 200:
                return self._send(400, '{"error":"no links allowed"}')
            c = db()
            c.execute("INSERT INTO reviews(name,ea,stars,message,created) VALUES(?,?,?,?,?)",
                      (name, ea, stars, msg, datetime.now().isoformat(timespec="seconds")))
            c.commit(); c.close()
            return self._send(200, '{"ok":true}')
        if u.path == "/result":
            if str(data.get("admin_key", "")) != ADMIN_KEY:
                return self._send(403, '{"error":"forbidden"}')
            ea = str(data.get("ea", ""))[:60]
            title = str(data.get("title", ""))[:120]
            profit = str(data.get("profit", ""))[:60]
            note = str(data.get("note", ""))[:800]
            if not title or not ea:
                return self._send(400, '{"error":"ea and title required"}')
            c = db()
            c.execute("INSERT INTO results(ea,title,profit,note,created) VALUES(?,?,?,?,?)",
                      (ea, title, profit, note, datetime.now().isoformat(timespec="seconds")))
            c.commit(); c.close()
            return self._send(200, '{"ok":true}')
        return self._send(404, '{"error":"not-found"}')

    def log_message(self, *a): pass

port = int(os.environ.get("PORT", sys.argv[1] if len(sys.argv) > 1 else 8080))
print(f"JAMGROUP live server on {port}")
HTTPServer(("0.0.0.0", port), H).serve_forever()
