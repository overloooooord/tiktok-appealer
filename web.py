"""Zero-dependency HTTP Web Dashboard (v3.0 Farm OS UI) for standalone TikTok Appealer (`python3 main.py web`)."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import random
import threading
import time
import urllib.parse
from typing import Any, Dict, List

import httpx

from appealer import AppealEngine
from config import WATCH_POLL_SECONDS
from models import AccountSpec
from scanner import AccountScanner
from session_mgr import SessionManager, normalize_proxy_url


def _probe_proxy_sync(raw_proxy: str) -> Dict[str, Any]:
    norm = normalize_proxy_url(raw_proxy) or ""
    if not norm:
        raise RuntimeError("Пустой прокси")
    t0 = time.perf_counter()
    with httpx.Client(proxy=norm, timeout=10.0) as c:
        r = c.get("https://www.cloudflare.com/cdn-cgi/trace")
        ip_val, loc_val = "", ""
        for ln in r.text.splitlines():
            if ln.startswith("ip="):
                ip_val = ln.split("=", 1)[1].strip()
            elif ln.startswith("loc="):
                loc_val = ln.split("=", 1)[1].strip().upper()
    return {"ip": ip_val, "country": loc_val, "latency_ms": int((time.perf_counter() - t0) * 1000)}


def _mask_proxy(px: str | None) -> str:
    if not px or "@" not in px:
        return px or "—"
    parts = px.split("://", 1)
    if len(parts) != 2:
        return px
    scheme, rest = parts
    creds, host = rest.rsplit("@", 1)
    u = creds.split(":", 1)[0]
    return f"{scheme}://{u}:***@{host}"


class StandaloneWebHub:
    def __init__(self, base_dir: str, default_proxy: str | None = None, allow_direct: bool = False) -> None:
        self.base_dir = base_dir
        self.default_proxy = default_proxy or ""
        self.session_mgr = SessionManager(base_dir, allow_direct=allow_direct)
        self.lock = threading.Lock()
        self.specs: Dict[str, AccountSpec] = {}
        self.audits: Dict[str, Dict[str, Any]] = {}
        self.logs: List[Dict[str, str]] = []
        self.watchdog_on = False
        self.watchdog_cycles = 0
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
            if len(self.logs) > 300:
                self.logs = self.logs[-300:]

    def audit_one(self, username: str) -> Dict[str, Any]:
        spec = self.specs[username]
        self.log(f"[@{username}] Проверка прокси + HTTP-аудит мобильного шлюза и Studio...", "info")
        px_info = {"ip": "", "country": ""}
        if spec.proxy:
            try:
                px_info = _probe_proxy_sync(spec.proxy)
            except Exception as exc:
                self.log(f"[@{username}] Прокси не отвечает: {exc}", "warn")
        sess, _, user_meta, gw = self.session_mgr.get_authenticated_session(spec)
        scanner = AccountScanner(sess, gw)
        aud = scanner.run_full_audit(username, user_meta)
        d = asdict(aud)
        d["proxy_ip"] = px_info.get("ip", "")
        d["proxy_country"] = px_info.get("country", "")
        active_vios = [v for v in aud.notice_violations if v.status_code not in (2, 3, 6)]
        restored_vios = [v for v in aud.notice_violations if v.status_code in (2, 3, 6)]
        d["notice_violations"] = [asdict(v) for v in active_vios]
        d["restored_notices"] = [asdict(v) for v in restored_vios]
        has_act = any(v.can_appeal or v.status_code == 1 for v in active_vios) or any(
            p.appeal_status == 0 or p.v2_can_appeal for p in aud.post_penalties
        )
        has_app = any(v.status_code == 4 for v in active_vios) or any(
            p.appeal_status == 3 for p in aud.post_penalties
        )
        d["account_health"] = "action_required" if has_act else ("appealing" if has_app else "eligible")
        d["total_views"] = sum(p.play_count for p in aud.post_penalties)
        d["audited_at"] = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            self.audits[username] = d
        self.log(
            f"[@{username}] Аудит готов: {d['account_health'].upper()} | постов={aud.total_posts} (views={d['total_views']})",
            "success" if d["account_health"] == "eligible" else "warn",
        )
        return d

    def appeal_one(
        self,
        username: str,
        hide_rejected: bool = True,
        appeal_studio_posts: bool = False,
        settle: bool = False,
    ) -> Dict[str, Any]:
        spec = self.specs[username]
        self.log(
            f"[@{username}] Запуск снятия огранов Account updates"
            + (" (ожидание волны 0..10+)..." if settle else "..."),
            "info",
        )
        sess, cookies, user_meta, gw = self.session_mgr.get_authenticated_session(spec)
        scanner = AccountScanner(sess, gw)
        engine = AppealEngine(sess, cookies, gw, self.session_mgr, spec)
        if settle:
            summary = engine.wait_and_appeal_settle(
                username,
                user_meta,
                appeal_studio_posts=appeal_studio_posts,
                hide_rejected=hide_rejected,
            )
        else:
            aud = scanner.run_full_audit(username, user_meta)
            summary = engine.process_audit(
                aud,
                appeal_studio_posts=appeal_studio_posts,
                hide_rejected=hide_rejected,
            )
        self.audit_one(username)
        for line in summary["details"]:
            self.log(f"[@{username}] {line}", "success" if "[OK]" in line else "warn")
        return summary

    def set_post_private(self, username: str, item_id: str) -> str:
        spec = self.specs[username]
        sess, cookies, _, gw = self.session_mgr.get_authenticated_session(spec)
        engine = AppealEngine(sess, cookies, gw, self.session_mgr, spec)
        ok, msg = engine.set_post_private(item_id)
        self.log(f"[@{username}] {msg}", "success" if ok else "warn")
        if not ok:
            raise RuntimeError(msg)
        return msg

    def start_watchdog(self, hide_rejected: bool = True) -> None:
        if self.watchdog_on:
            return
        self.watchdog_on = True

        def _loop() -> None:
            self.log("Сторож 24/7 запущен (интервал 95–165с по кукам).", "success")
            while self.watchdog_on:
                self.watchdog_cycles += 1
                for u in list(self.specs.keys()):
                    if not self.watchdog_on:
                        break
                    try:
                        self.appeal_one(u, hide_rejected=hide_rejected)
                    except Exception as exc:
                        self.log(f"[@{u}] Ошибка сторожа: {exc}", "error")
                wait_s = random.uniform(*WATCH_POLL_SECONDS)
                end_t = time.time() + wait_s
                while self.watchdog_on and time.time() < end_t:
                    time.sleep(1.0)
            self.log("Сторож остановлен.", "warn")

        threading.Thread(target=_loop, daemon=True).start()


STANDALONE_HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>TikTok Appealer // Farm OS</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 36 36'%3E%3Crect width='36' height='36' rx='10' fill='%236366f1'/%3E%3Ctext x='18' y='24' text-anchor='middle' fill='%23fff' font-family='sans-serif' font-weight='800' font-size='18'%3EA%3C/text%3E%3C/svg%3E" />
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root { --bg:#05070c; --rail:rgba(9,12,20,0.92); --card:rgba(15,20,31,0.82); --border:rgba(255,255,255,0.08); --bstrong:rgba(255,255,255,0.15); --text:#f1f5f9; --dim:#94a3b8; --muted:#64748b; --accent:#6366f1; --ok:#10b981; --warn:#f59e0b; --err:#f43f5e; --cyan:#06b6d4; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:'Inter',sans-serif; background:radial-gradient(900px 480px at 18% -10%,rgba(99,102,241,0.16),transparent 65%),radial-gradient(740px 420px at 90% 0%,rgba(6,182,212,0.11),transparent 60%),var(--bg); color:var(--text); min-height:100vh; }
  .mono { font-family:'JetBrains Mono',monospace; }
  .hidden { display:none !important; }
  .shell { display:flex; min-height:100vh; }
  .rail { width:236px; position:fixed; top:0; bottom:0; left:0; background:var(--rail); border-right:1px solid var(--border); padding:18px 14px; display:flex; flex-direction:column; z-index:40; }
  .brand { display:flex; align-items:center; gap:10px; padding:2px 6px 16px; border-bottom:1px solid var(--border); margin-bottom:14px; }
  .mark { width:34px; height:34px; border-radius:10px; background:linear-gradient(135deg,#6366f1,#06b6d4); display:grid; place-items:center; font-weight:800; color:#fff; }
  .nav-btn { width:100%; border:0; background:transparent; color:var(--dim); display:flex; justify-content:space-between; align-items:center; padding:9px 11px; border-radius:10px; font-size:13px; font-weight:500; cursor:pointer; margin-bottom:4px; }
  .nav-btn:hover { background:rgba(255,255,255,0.05); color:#fff; }
  .nav-btn.active { background:rgba(99,102,241,0.2); color:#fff; font-weight:600; box-shadow:inset 0 0 0 1px rgba(99,102,241,0.4); }
  .main { margin-left:236px; flex:1; min-width:0; padding-bottom:190px; }
  .top { position:sticky; top:0; z-index:30; backdrop-filter:blur(18px); background:rgba(5,7,12,0.82); border-bottom:1px solid var(--border); padding:13px 26px; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; }
  .wrap { max-width:1320px; margin:0 auto; padding:22px 26px; }
  .kpis { display:grid; grid-template-columns:repeat(4,1fr); gap:13px; margin-bottom:18px; }
  .kpi, .card { background:var(--card); border:1px solid var(--border); border-radius:15px; padding:16px 18px; }
  .kpi-v { font-size:26px; font-weight:700; margin-top:6px; }
  .btn { display:inline-flex; align-items:center; gap:6px; white-space:nowrap; border:1px solid var(--bstrong); background:var(--card); color:var(--text); padding:8px 13px; border-radius:10px; font-size:12.5px; font-weight:600; cursor:pointer; transition:.15s; }
  .btn:hover { background:rgba(28,36,56,0.92); }
  .btn-p { background:linear-gradient(135deg,#6366f1,#4f46e5); color:#fff; border-color:rgba(129,140,248,0.45); }
  .btn-ok { background:rgba(16,185,129,0.15); border-color:rgba(16,185,129,0.4); color:#34d399; }
  .btn-sm { padding:5px 10px; font-size:11.5px; border-radius:8px; }
  .badge { padding:3px 9px; border-radius:999px; font-size:11px; font-weight:600; display:inline-flex; align-items:center; gap:4px; }
  .b-ok { background:rgba(16,185,129,0.14); color:#34d399; border:1px solid rgba(16,185,129,0.3); }
  .b-warn { background:rgba(245,158,11,0.14); color:#fbbf24; border:1px solid rgba(245,158,11,0.3); }
  .b-err { background:rgba(244,63,94,0.14); color:#fb7185; border:1px solid rgba(244,63,94,0.3); }
  .cards { display:grid; grid-template-columns:repeat(auto-fill,minmax(520px,1fr)); gap:13px; }
  textarea, input[type="text"] { width:100%; background:#080b13; border:1px solid var(--bstrong); color:#fff; border-radius:10px; padding:9px 12px; font-size:12.5px; outline:none; }
  textarea { font-family:'JetBrains Mono',monospace; min-height:110px; }
  .drawer-bg { position:fixed; inset:0; background:rgba(2,4,9,0.68); backdrop-filter:blur(5px); z-index:60; display:flex; justify-content:flex-end; }
  .drawer { width:min(680px,95vw); height:100%; background:#0b0f19; border-left:1px solid var(--bstrong); display:flex; flex-direction:column; }
  .drawer-body { flex:1; overflow-y:auto; padding:18px 22px; display:flex; flex-direction:column; gap:14px; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  th { text-align:left; color:var(--muted); padding:8px; border-bottom:1px solid var(--border); font-size:11px; }
  td { padding:8px; border-bottom:1px solid rgba(255,255,255,0.04); }
  .dock { position:fixed; bottom:0; left:236px; right:0; height:165px; background:rgba(6,9,16,0.95); border-top:1px solid var(--bstrong); padding:10px 22px; overflow-y:auto; font-size:11.5px; line-height:1.55; z-index:35; }
  .toasts { position:fixed; top:16px; right:18px; z-index:90; display:flex; flex-direction:column; gap:8px; }
  .toast { background:rgba(16,22,36,0.96); border:1px solid var(--bstrong); border-left:3px solid var(--accent); padding:10px 14px; border-radius:10px; font-size:12.5px; }
</style>
</head>
<body>
<div class="shell">
  <aside class="rail">
    <div class="brand">
      <div class="mark">A</div>
      <div><div style="font-weight:700;font-size:14px;">TIKTOK APPEALER</div><div class="mono" style="font-size:11px;color:var(--muted);">v3.0 Standalone</div></div>
    </div>
    <button class="nav-btn active" data-v="fleet" onclick="sw('fleet')"><span>🛡️ Флот и Ограны</span><span class="mono" id="nCnt">0</span></button>
    <button class="nav-btn" data-v="import" onclick="sw('import')"><span>📥 Импорт строк</span></button>
    <button class="nav-btn" data-v="proxy" onclick="sw('proxy')"><span>🧪 Тестер прокси</span></button>
    <div style="margin-top:auto;padding-top:14px;border-top:1px solid var(--border);">
      <div style="font-size:11.5px;color:var(--dim);margin-bottom:8px;">Сторож 24/7: <strong id="wdTxt" class="mono">OFF</strong></div>
      <button class="btn btn-sm" style="width:100%;" id="wdBtn" onclick="toggleWd()">Включить сторожа</button>
    </div>
  </aside>

  <div class="main">
    <header class="top">
      <strong style="font-size:15.5px;" id="topTitle">Мониторинг и 3-канальное снятие огранов</strong>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
        <label style="font-size:12px;color:var(--dim);display:flex;align-items:center;gap:6px;"><input type="checkbox" id="chkStudio" /> Также посты Studio</label>
        <label style="font-size:12px;color:var(--dim);display:flex;align-items:center;gap:6px;"><input type="checkbox" id="chkHide" checked /> FAILED → Private</label>
        <button class="btn" onclick="runAll('audit')">↻ HTTP-аудит</button>
        <button class="btn btn-ok" onclick="runAll('appeal', true)">⏳ Дождаться волны (0..10)</button>
        <button class="btn btn-p" onclick="runAll('appeal', false)">⚡ Снять все ограны</button>
      </div>
    </header>

    <div class="wrap">
      <div class="kpis">
        <div class="kpi"><div style="color:var(--dim);font-size:12px;">Аккаунтов</div><div class="kpi-v" id="kTot">0</div></div>
        <div class="kpi"><div style="color:var(--dim);font-size:12px;">Eligible / Restored</div><div class="kpi-v" style="color:var(--ok)" id="kOk">0</div></div>
        <div class="kpi"><div style="color:var(--dim);font-size:12px;">На апелляции</div><div class="kpi-v" style="color:var(--warn)" id="kApp">0</div></div>
        <div class="kpi"><div style="color:var(--dim);font-size:12px;">Просмотров Studio</div><div class="kpi-v mono" id="kVw">0</div></div>
      </div>

      <section id="v-fleet"><div id="cards" class="cards"></div></section>

      <section id="v-import" class="hidden">
        <div class="card">
          <div style="font-weight:700;margin-bottom:6px;">Импорт TOTP (<code>|</code>) и Outlook Hub (<code>:</code>) строк</div>
          <textarea id="lines" placeholder="user|pass|mail|BASE32TOTP|ip:port:user:pass&#10;login:pass:mail@outlook.com:pass:rec@polosmail.com:pass:HOTMAIL2FA"></textarea>
          <div style="display:flex;gap:10px;margin-top:10px;">
            <input type="text" id="px" placeholder="Прокси по умолчанию (socks5://user:pass@host:port)" />
            <button class="btn btn-p" onclick="addLines()">Добавить в пул</button>
          </div>
        </div>
      </section>

      <section id="v-proxy" class="hidden">
        <div class="card">
          <div style="font-weight:700;margin-bottom:6px;">Проверка прокси (Cloudflare Exit IP · GEO · Latency)</div>
          <textarea id="pxTest" placeholder="socks5://user:pass@host:port&#10;ip:port:user:pass"></textarea>
          <button class="btn btn-p" style="margin-top:10px;" onclick="testProxies()">🧪 Проверить</button>
          <div id="pxRes" style="margin-top:12px;"></div>
        </div>
      </section>
    </div>
  </div>
</div>

<div id="drBg" class="drawer-bg hidden" onclick="if(event.target===this) closeDr()">
  <div class="drawer">
    <div style="padding:16px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
      <strong id="drHead">Инспектор</strong>
      <button class="btn btn-sm" onclick="closeDr()">✕</button>
    </div>
    <div id="drBody" class="drawer-body"></div>
  </div>
</div>

<div id="toasts" class="toasts"></div>
<footer id="dock" class="dock mono"></footer>

<script>
let ST = { accounts: [], logs: [], watchdog: { enabled: false } };
let DR_USER = null;
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function toast(m){const d=document.createElement('div');d.className='toast';d.textContent=m;document.getElementById('toasts').appendChild(d);setTimeout(()=>d.remove(),3800);}
function sw(v){['fleet','import','proxy'].forEach(x=>document.getElementById('v-'+x).classList.toggle('hidden',x!==v));document.querySelectorAll('.nav-btn').forEach(b=>b.classList.toggle('active',b.dataset.v===v));}

async function refresh(){
  const r=await fetch('/api/state'); ST=await r.json();
  const items=ST.accounts||[];
  let ok=0,app=0,vw=0;
  items.forEach(x=>{if(x.audit){vw+=(x.audit.total_views||0);if(x.audit.account_health==='eligible')ok++;else if(x.audit.account_health==='appealing')app++;}});
  document.getElementById('kTot').textContent=items.length;
  document.getElementById('nCnt').textContent=items.length;
  document.getElementById('kOk').textContent=ok;
  document.getElementById('kApp').textContent=app;
  document.getElementById('kVw').textContent=vw.toLocaleString();
  document.getElementById('wdTxt').textContent=ST.watchdog?.enabled?`ON #${ST.watchdog.cycles}`:'OFF';
  document.getElementById('wdBtn').textContent=ST.watchdog?.enabled?'Остановить':'Включить сторожа';

  document.getElementById('cards').innerHTML=items.map(x=>{
    const a=x.audit;
    const b=!a?'<span class="badge">Не проверен</span>':(a.account_health==='eligible'?'<span class="badge b-ok">● ELIGIBLE</span>':(a.account_health==='appealing'?'<span class="badge b-warn">● APPEALING</span>':'<span class="badge b-err">● ACTION NEEDED</span>'));
    return `<div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;">
        <div><strong style="font-size:15px;">@${esc(x.username)}</strong> ${b}</div>
        <button class="btn btn-sm" onclick="openDr('${esc(x.username)}')">Инспектор ↗</button>
      </div>
      <div class="mono" style="font-size:11.5px;color:var(--dim);margin:8px 0 12px;">
        ${a?`UID: ${esc(a.uid)} · Гео: ${esc(a.reg_country||'?')}→${esc(a.current_region||'?')} · Exit: ${esc(a.proxy_country||'—')} · Постов: ${a.total_posts} · Views: ${a.total_views}`:'Прокси: '+esc(x.proxy_masked)}
      </div>
      <div style="display:flex;gap:7px;">
        <button class="btn btn-sm" onclick="act('${esc(x.username)}','audit')">↻ Аудит</button>
        <button class="btn btn-sm btn-ok" onclick="act('${esc(x.username)}','appeal',false)">⚡ Снять ограны</button>
        <button class="btn btn-sm" onclick="act('${esc(x.username)}','appeal',true)">⏳ Ждать волну</button>
      </div>
    </div>`;
  }).join('') || '<div class="card" style="color:var(--muted)">Нет аккаунтов — добавь строки во вкладке Импорт.</div>';

  document.getElementById('dock').innerHTML=(ST.logs||[]).map(l=>`<div><span style="color:#64748b">[${esc(l.time)}]</span> ${esc(l.text)}</div>`).join('');
  if(DR_USER) renderDr();
}

function openDr(u){DR_USER=u;document.getElementById('drBg').classList.remove('hidden');renderDr();}
function closeDr(){DR_USER=null;document.getElementById('drBg').classList.add('hidden');}
function renderDr(){
  const x=(ST.accounts||[]).find(z=>z.username===DR_USER); if(!x) return;
  const a=x.audit;
  document.getElementById('drHead').textContent='@'+x.username;
  document.getElementById('drBody').innerHTML=`
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      <button class="btn btn-sm" onclick="act('${esc(x.username)}','audit')">↻ Аудит</button>
      <button class="btn btn-sm btn-ok" onclick="act('${esc(x.username)}','appeal')">⚡ Снять ограны</button>
      <a class="btn btn-sm" href="/api/export?u=${encodeURIComponent(x.username)}" style="text-decoration:none;">⬇ cookies.json</a>
    </div>
    <div class="card">
      <div style="font-size:12px;font-weight:700;color:var(--dim);margin-bottom:8px;">ПОСТЫ STUDIO (${a?.total_posts||0})</div>
      ${a&&(a.post_penalties||[]).length?`<table><thead><tr><th>ID</th><th>Views</th><th>Статус</th><th></th></tr></thead><tbody>
        ${a.post_penalties.map(p=>`<tr><td class="mono">${esc(p.item_id)}</td><td class="mono">${p.play_count}</td><td>${esc(p.appeal_status_label)}</td><td><button class="btn btn-sm" onclick="priv('${esc(x.username)}','${esc(p.item_id)}')">Private</button></td></tr>`).join('')}
      </tbody></table>`:'<div style="color:var(--muted);font-size:12px;">Запусти аудит для загрузки постов.</div>'}
    </div>`;
}

async function act(u,m,settle=false){toast('Запущено: '+m+' @'+u);const st=document.getElementById('chkStudio').checked?1:0;const hd=document.getElementById('chkHide').checked?1:0;await fetch(`/api/${m}?u=${encodeURIComponent(u)}&hide=${hd}&studio=${st}&settle=${settle?1:0}`,{method:'POST'});await refresh();}
async function runAll(m,settle=false){toast('Запущено для всех: '+m);const st=document.getElementById('chkStudio').checked?1:0;const hd=document.getElementById('chkHide').checked?1:0;await fetch(`/api/${m}-all?hide=${hd}&studio=${st}&settle=${settle?1:0}`,{method:'POST'});await refresh();}
async function priv(u,id){await fetch(`/api/private?u=${encodeURIComponent(u)}&id=${encodeURIComponent(id)}`,{method:'POST'});toast('Пост переведён в Private');}
async function addLines(){await fetch('/api/add',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({lines:document.getElementById('lines').value,proxy:document.getElementById('px').value})});document.getElementById('lines').value='';toast('Строки добавлены');sw('fleet');await refresh();}
async function toggleWd(){await fetch('/api/watchdog',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({enabled:!ST.watchdog?.enabled,hide:document.getElementById('chkHide').checked})});await refresh();}
async function testProxies(){const r=await fetch('/api/test-proxies',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({text:document.getElementById('pxTest').value})});const d=await r.json();document.getElementById('pxRes').innerHTML=`<table><thead><tr><th>Прокси</th><th>GEO / IP</th><th>Пинг</th></tr></thead><tbody>${(d.results||[]).map(x=>`<tr><td class="mono">${esc(x.proxy)}</td><td class="mono">${x.ok?esc(x.country+' · '+x.ip):esc(x.error)}</td><td class="mono">${x.ok?x.latency_ms+'мс':'ERR'}</td></tr>`).join('')}</tbody></table>`;}
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

        def _json(self, code: int, data: Any, extra_headers: Dict[str, str] | None = None) -> None:
            raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
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
                    accs = [
                        {"username": u, "proxy_masked": _mask_proxy(hub.specs[u].proxy), "audit": hub.audits.get(u)}
                        for u in sorted(hub.specs.keys())
                    ]
                    logs = list(hub.logs[-80:])
                self._json(200, {"accounts": accs, "logs": logs, "watchdog": {"enabled": hub.watchdog_on, "cycles": hub.watchdog_cycles}})
                return
            if parsed.path == "/api/export":
                u = (qs.get("u") or [""])[0]
                cks = hub.session_mgr.load_saved_cookies(u)
                self._json(200, cks, {"Content-Disposition": f'attachment; filename="{u}_cookies.json"'})
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
                    hide = (qs.get("hide") or ["1"])[0] == "1"
                    studio = (qs.get("studio") or ["0"])[0] == "1"
                    settle = (qs.get("settle") or ["0"])[0] == "1"
                    self._json(200, {"ok": True, "summary": hub.appeal_one(u, hide_rejected=hide, appeal_studio_posts=studio, settle=settle)})
                    return
                if parsed.path == "/api/private":
                    u = (qs.get("u") or [""])[0]
                    iid = (qs.get("id") or [""])[0]
                    self._json(200, {"ok": True, "message": hub.set_post_private(u, iid)})
                    return
                if parsed.path == "/api/watchdog":
                    if body.get("enabled"):
                        hub.start_watchdog(hide_rejected=bool(body.get("hide", True)))
                    else:
                        hub.watchdog_on = False
                    self._json(200, {"ok": True, "enabled": hub.watchdog_on})
                    return
                if parsed.path == "/api/test-proxies":
                    out = []
                    for ln in str(body.get("text") or "").splitlines():
                        s = ln.strip()
                        if not s or s.startswith("#"):
                            continue
                        try:
                            res = _probe_proxy_sync(s)
                            out.append({"ok": True, "proxy": _mask_proxy(normalize_proxy_url(s)), **res})
                        except Exception as exc:
                            out.append({"ok": False, "proxy": _mask_proxy(s), "error": str(exc)[:80]})
                    self._json(200, {"ok": True, "results": out})
                    return
                if parsed.path in ("/api/audit-all", "/api/appeal-all"):
                    hide = (qs.get("hide") or ["1"])[0] == "1"
                    studio = (qs.get("studio") or ["0"])[0] == "1"
                    settle = (qs.get("settle") or ["0"])[0] == "1"
                    for u in list(hub.specs.keys()):
                        try:
                            if parsed.path == "/api/audit-all":
                                hub.audit_one(u)
                            else:
                                hub.appeal_one(u, hide_rejected=hide, appeal_studio_posts=studio, settle=settle)
                        except Exception as exc:
                            hub.log(f"[@{u}] Ошибка: {exc}", "error")
                    self._json(200, {"ok": True})
                    return
                self._json(404, {"error": "not found"})
            except Exception as exc:
                hub.log(f"Ошибка: {exc}", "error")
                self._json(400, {"error": str(exc)})

    print(f"🚀 Веб-панель TikTok Appealer v3.0 запущена: http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
