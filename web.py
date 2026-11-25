"""Zero-dependency HTTP Web Dashboard for standalone TikTok Appealer (`python3 main.py web`)."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
import urllib.parse
from typing import Any, Dict, List

from appealer import AppealEngine
from models import AccountSpec
from scanner import AccountScanner
from session_mgr import SessionManager


class StandaloneWebHub:
    def __init__(self, base_dir: str, default_proxy: str | None = None, allow_direct: bool = False) -> None:
        self.base_dir = base_dir
        self.default_proxy = default_proxy or ""
        self.session_mgr = SessionManager(base_dir, allow_direct=allow_direct)
        self.lock = threading.Lock()
        self.specs: Dict[str, AccountSpec] = {}
        self.audits: Dict[str, Dict[str, Any]] = {}
        self.logs: List[Dict[str, str]] = []
        self._discover_saved_sessions()

    def _discover_saved_sessions(self) -> None:
        sroot = self.session_mgr.sessions_root
        if not os.path.isdir(sroot):
            return
        for entry in sorted(os.listdir(sroot)):
            full = os.path.join(sroot, entry)
            if os.path.isdir(full) and os.path.exists(os.path.join(full, "cookies.json")):
                self.specs[entry] = AccountSpec(username=entry, password="", proxy=self.default_proxy or None)
            elif entry.endswith(".json"):
                uname = entry[:-5]
                self.specs.setdefault(uname, AccountSpec(username=uname, password="", proxy=self.default_proxy or None))

    def log(self, text: str, level: str = "info") -> None:
        with self.lock:
            self.logs.append({"time": datetime.now().strftime("%H:%M:%S"), "level": level, "text": text})
            if len(self.logs) > 250:
                self.logs = self.logs[-250:]

    def audit_one(self, username: str) -> Dict[str, Any]:
        spec = self.specs[username]
        self.log(f"[@{username}] Запуск HTTP-аудита мобильного шлюза и Studio...", "info")
        sess, _, user_meta, gw = self.session_mgr.get_authenticated_session(spec)
        scanner = AccountScanner(sess, gw)
        aud = scanner.run_full_audit(username, user_meta)
        d = asdict(aud)
        has_act = any(v.can_appeal or v.status_code == 1 for v in aud.notice_violations) or any(
            p.appeal_status == 0 or p.v2_can_appeal for p in aud.post_penalties
        )
        has_app = any(v.status_code == 4 for v in aud.notice_violations) or any(
            p.appeal_status == 3 for p in aud.post_penalties
        )
        d["account_health"] = "action_required" if has_act else ("appealing" if has_app else "eligible")
        d["total_views"] = sum(p.play_count for p in aud.post_penalties)
        with self.lock:
            self.audits[username] = d
        self.log(f"[@{username}] Аудит готов: {d['account_health'].upper()} | постов={aud.total_posts}", "success")
        return d

    def appeal_one(self, username: str, hide_rejected: bool = True) -> Dict[str, Any]:
        spec = self.specs[username]
        self.log(f"[@{username}] Запуск 3-канального снятия огранов...", "info")
        sess, cookies, user_meta, gw = self.session_mgr.get_authenticated_session(spec)
        scanner = AccountScanner(sess, gw)
        aud = scanner.run_full_audit(username, user_meta)
        engine = AppealEngine(sess, cookies, gw, self.session_mgr, spec)
        summary = engine.process_audit(aud, hide_rejected=hide_rejected)
        self.audit_one(username)
        for line in summary["details"]:
            self.log(f"[@{username}] {line}", "success" if "[OK]" in line else "warn")
        return summary


STANDALONE_HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>TikTok Appealer // Restriction Control</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root { --bg:#06080d; --card:rgba(17,22,34,0.82); --border:rgba(255,255,255,0.08); --text:#f1f5f9; --muted:#8b9bb4; --accent:#6366f1; --ok:#10b981; --warn:#f59e0b; --err:#f43f5e; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:'Inter',sans-serif; background:radial-gradient(900px 450px at 15% -5%,rgba(99,102,241,0.16),transparent 65%),var(--bg); color:var(--text); min-height:100vh; padding-bottom:190px; }
  .mono { font-family:'JetBrains Mono',monospace; }
  .top { padding:16px 28px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; background:rgba(6,8,13,0.8); backdrop-filter:blur(16px); position:sticky; top:0; }
  .wrap { max-width:1280px; margin:0 auto; padding:24px 28px; }
  .kpis { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:20px; }
  .kpi, .card { background:var(--card); border:1px solid var(--border); border-radius:14px; padding:16px 18px; }
  .kpi-v { font-size:26px; font-weight:700; margin-top:4px; }
  .btn { border:1px solid rgba(255,255,255,0.14); background:var(--card); color:var(--text); padding:8px 14px; border-radius:10px; font-size:12.5px; font-weight:600; cursor:pointer; }
  .btn-p { background:linear-gradient(135deg,#6366f1,#4f46e5); color:#fff; border:0; }
  .badge { padding:3px 9px; border-radius:999px; font-size:11px; font-weight:600; }
  .b-ok { background:rgba(16,185,129,0.14); color:#34d399; }
  .b-warn { background:rgba(245,158,11,0.14); color:#fbbf24; }
  .b-err { background:rgba(244,63,94,0.14); color:#fb7185; }
  textarea, input[type="text"] { width:100%; background:#090c14; border:1px solid rgba(255,255,255,0.14); color:#fff; border-radius:10px; padding:10px; font-size:12.5px; margin-top:6px; }
  .dock { position:fixed; bottom:0; left:0; right:0; height:165px; background:rgba(7,9,15,0.95); border-top:1px solid var(--border); padding:10px 24px; overflow-y:auto; font-size:11.5px; }
</style>
</head>
<body>
<header class="top">
  <div><strong>TIKTOK APPEALER // RESTRICTION MANAGER</strong> <span style="color:var(--muted);font-size:12px;margin-left:8px;">Mobile IDC · Studio V1/V2 · Outlook Hub</span></div>
  <div style="display:flex;gap:8px;">
    <button class="btn" onclick="runAll('audit')">↻ HTTP-аудит всех</button>
    <button class="btn btn-p" onclick="runAll('appeal')">⚡ Снять все ограны</button>
  </div>
</header>
<main class="wrap">
  <div class="kpis">
    <div class="kpi"><div style="color:var(--muted);font-size:12px">Аккаунтов</div><div class="kpi-v" id="kTot">0</div></div>
    <div class="kpi"><div style="color:var(--muted);font-size:12px">Eligible / Restored</div><div class="kpi-v" style="color:var(--ok)" id="kOk">0</div></div>
    <div class="kpi"><div style="color:var(--muted);font-size:12px">На апелляции</div><div class="kpi-v" style="color:var(--warn)" id="kApp">0</div></div>
    <div class="kpi"><div style="color:var(--muted);font-size:12px">Просмотров Studio</div><div class="kpi-v mono" id="kViews">0</div></div>
  </div>
  <div class="card" style="margin-bottom:18px;">
    <div style="font-weight:600;font-size:13.5px;">Добавить строки аккаунтов (TOTP <code class="mono">|</code> или Outlook Hub <code class="mono">:</code>)</div>
    <textarea id="lines" rows="3" placeholder="user|pass|mail|TOTP|ip:port:user:pass&#10;login:pass:mail@outlook.com:pass:rec@polosmail.com:pass:2FA"></textarea>
    <div style="display:flex;gap:10px;margin-top:8px;">
      <input type="text" id="px" placeholder="Прокси по умолчанию (socks5://user:pass@host:port)" style="margin:0;" />
      <button class="btn btn-p" style="white-space:nowrap" onclick="addLines()">Добавить и проверить</button>
    </div>
  </div>
  <div id="list" style="display:grid;gap:12px;"></div>
</main>
<footer id="dock" class="dock mono"></footer>
<script>
async function refresh() {
  const r = await fetch('/api/state');
  const s = await r.json();
  const items = s.accounts || [];
  let ok=0, app=0, vw=0;
  items.forEach(x => {
    if (x.audit) {
      vw += (x.audit.total_views || 0);
      if (x.audit.account_health === 'eligible') ok++;
      else if (x.audit.account_health === 'appealing') app++;
    }
  });
  document.getElementById('kTot').textContent = items.length;
  document.getElementById('kOk').textContent = ok;
  document.getElementById('kApp').textContent = app;
  document.getElementById('kViews').textContent = vw.toLocaleString();
  document.getElementById('list').innerHTML = items.map(x => {
    const a = x.audit;
    const b = !a ? '<span class="badge">Не проверен</span>'
      : (a.account_health === 'eligible' ? '<span class="badge b-ok">ELIGIBLE</span>'
      : (a.account_health === 'appealing' ? '<span class="badge b-warn">APPEALING</span>' : '<span class="badge b-err">CAN APPEAL</span>'));
    return `<div class="card" style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;">
      <div>
        <div style="font-weight:700;font-size:15px;">@${x.username} ${b}</div>
        <div class="mono" style="font-size:12px;color:var(--muted);margin-top:4px;">
          ${a ? `UID: ${a.uid} · Гео: ${a.reg_country||'?'}→${a.current_region||'?'} · Постов: ${a.total_posts} · Views: ${a.total_views}` : 'Нажми Аудит для загрузки статуса'}
        </div>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="btn" onclick="act('${x.username}','audit')">↻ Аудит</button>
        <button class="btn btn-p" onclick="act('${x.username}','appeal')">⚡ Снять ограны</button>
      </div>
    </div>`;
  }).join('');
  document.getElementById('dock').innerHTML = (s.logs||[]).map(l => `<div><span style="color:#64748b">[${l.time}]</span> ${l.text}</div>`).join('');
}
async function act(u, mode) {
  await fetch(`/api/${mode}?u=` + encodeURIComponent(u), {method:'POST'});
  await refresh();
}
async function runAll(mode) {
  await fetch(`/api/${mode}-all`, {method:'POST'});
  await refresh();
}
async function addLines() {
  await fetch('/api/add', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({lines:document.getElementById('lines').value, proxy:document.getElementById('px').value})});
  document.getElementById('lines').value = '';
  await refresh();
}
refresh(); setInterval(refresh, 4000);
</script>
</body>
</html>
"""


def serve_web(base_dir: str, host: str = "127.0.0.1", port: int = 8085, default_proxy: str | None = None, allow_direct: bool = False) -> None:
    hub = StandaloneWebHub(base_dir, default_proxy=default_proxy, allow_direct=allow_direct)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _json(self, code: int, data: Any) -> None:
            raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path == "/":
                raw = STANDALONE_HTML.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            if parsed.path == "/api/state":
                with hub.lock:
                    accs = [{"username": u, "audit": hub.audits.get(u)} for u in sorted(hub.specs.keys())]
                    logs = list(hub.logs[-80:])
                self._json(200, {"accounts": accs, "logs": logs})
                return
            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
            try:
                if parsed.path == "/api/add":
                    px = body.get("proxy") or hub.default_proxy or None
                    for ln in str(body.get("lines") or "").splitlines():
                        s = ln.strip()
                        if not s or s.startswith("#"):
                            continue
                        sp = AccountSpec.parse(s, default_proxy=px)
                        hub.specs[sp.username] = sp
                    self._json(200, {"ok": True})
                    return
                if parsed.path == "/api/audit":
                    u = (qs.get("u") or [""])[0]
                    self._json(200, {"ok": True, "audit": hub.audit_one(u)})
                    return
                if parsed.path == "/api/appeal":
                    u = (qs.get("u") or [""])[0]
                    self._json(200, {"ok": True, "summary": hub.appeal_one(u)})
                    return
                if parsed.path in ("/api/audit-all", "/api/appeal-all"):
                    for u in list(hub.specs.keys()):
                        try:
                            if parsed.path == "/api/audit-all":
                                hub.audit_one(u)
                            else:
                                hub.appeal_one(u)
                        except Exception as exc:
                            hub.log(f"[@{u}] Ошибка: {exc}", "error")
                    self._json(200, {"ok": True})
                    return
                self._json(404, {"error": "not found"})
            except Exception as exc:
                hub.log(f"Ошибка: {exc}", "error")
                self._json(400, {"error": str(exc)})

    print(f"🚀 Веб-панель TikTok Appealer запущена: http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
