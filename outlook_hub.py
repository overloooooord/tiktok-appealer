"""
Integrated Outlook Hub reader (adapted from https://github.com/overloooooord/outlook-hub).

Provides automated Step-1 Microsoft OAuth2 PKCE login (headless Chromium + Stealth +
Hotmail TOTP 2FA + Firstmail/Recovery IMAP verification), persistent SQLite refresh_token
caching, and strict post-request TikTok 6-digit OTP polling via Microsoft Graph API.
"""

from __future__ import annotations

import base64
import datetime as dt
import email
import hashlib
import hmac
import html
import imaplib
import json
import os
import re
import secrets
import shutil
import sqlite3
import struct
import threading
import time
from email.header import decode_header
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

try:
    from playwright.sync_api import sync_playwright
    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False

try:
    from playwright_stealth.stealth import Stealth
    _HAS_STEALTH = True
except ImportError:
    _HAS_STEALTH = False


BASE_DIR = Path(__file__).resolve().parent
OUTLOOK_DB_PATH = BASE_DIR / "sessions" / "outlook_hub_tokens.db"

# Official Outlook Hub Graph API public client configuration
OUTLOOK_HUB_CLIENT_ID = os.environ.get(
    "OUTLOOK_HUB_CLIENT_ID", "a1c2e701-25ae-4029-b47e-655ea4919fea"
)
OUTLOOK_HUB_REDIRECT_URI = "http://localhost:8765/callback"
GRAPH_SCOPES = (
    "offline_access openid profile email "
    "https://graph.microsoft.com/User.Read "
    "https://graph.microsoft.com/Mail.Read"
)
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

KNOWN_RECOVERY_IMAP_HOSTS: Dict[str, str] = {
    "rambler.ru": "imap.rambler.ru",
    "lenta.ru": "imap.rambler.ru",
    "autorambler.ru": "imap.rambler.ru",
    "myrambler.ru": "imap.rambler.ru",
    "ro.ru": "imap.rambler.ru",
    "mail.ru": "imap.mail.ru",
    "inbox.ru": "imap.mail.ru",
    "list.ru": "imap.mail.ru",
    "bk.ru": "imap.mail.ru",
    "yandex.ru": "imap.yandex.ru",
    "ya.ru": "imap.yandex.ru",
    "gmx.com": "imap.gmx.com",
    "gmx.de": "imap.gmx.net",
}
DEFAULT_RECOVERY_IMAP_HOST = "imap.firstmail.ltd"

_NOISE_PHRASES = (
    "new app(s) connected",
    "security info was added",
    "updates to our terms",
    "new login detected",
    "thanks for verifying",
    "новые приложения подключены",
    "обновление условий",
)

_STYLE_SCRIPT_RE = re.compile(
    r"<(script|style|head|title)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL
)
_TAG_RE = re.compile(r"<[^>]+>")
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_CODE_NEAR_KEYWORD_RE = re.compile(
    r"(?:security\s*code|verification\s*code|single[- ]use\s*code|one[- ]time\s*code|"
    r"код\s*(?:безопасности|подтверждения)|code|код)[^0-9A-Za-z]{0,25}(\d{4,8})\b",
    re.IGNORECASE,
)
_STANDALONE_CODE_RE = re.compile(r"(?<!\d)(\d{6,7})(?!\d)")

_browser_semaphore = threading.Semaphore(2)
_db_lock = threading.Lock()
_callback_lock = threading.Lock()
_callback_codes_by_state: Dict[str, str] = {}
_callback_any_codes: List[str] = []
_callback_server_started = False


class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        code_val = (qs.get("code") or [""])[0]
        state_val = (qs.get("state") or [""])[0]
        if code_val:
            with _callback_lock:
                if state_val:
                    _callback_codes_by_state[state_val] = code_val
                _callback_any_codes.append(code_val)
        body = (
            "<!doctype html><html><head><meta charset='utf-8'><title>Outlook Hub</title></head>"
            "<body style='background:#0d1117;color:#4ade80;font-family:sans-serif;padding:32px;text-align:center;'>"
            "<h2>✔ Аккаунт подключён (Outlook Hub)</h2></body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _ensure_local_callback_server() -> None:
    global _callback_server_started
    with _callback_lock:
        if _callback_server_started:
            return
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", 8765), _OAuthCallbackHandler)
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            _callback_server_started = True
        except OSError:
            # Port 8765 may already be bound by standalone Outlook Hub; request listener still intercepts code
            _callback_server_started = True


class OutlookHubError(Exception):
    """Raised when Outlook Hub authentication or code polling fails."""


# ============================================================================
# SQLite Token Cache (persists rotated OAuth2 refresh_tokens across sessions)
# ============================================================================

def _init_token_db(db_path: Path = OUTLOOK_DB_PATH) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with _db_lock:
        conn = sqlite3.connect(str(db_path), timeout=15.0)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS outlook_tokens (
                    email TEXT PRIMARY KEY COLLATE NOCASE,
                    refresh_token TEXT NOT NULL,
                    access_token TEXT NOT NULL DEFAULT '',
                    expires_at REAL NOT NULL DEFAULT 0,
                    client_id TEXT NOT NULL DEFAULT '',
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.commit()
        finally:
            conn.close()


def _get_cached_tokens(email_addr: str, db_path: Path = OUTLOOK_DB_PATH) -> Optional[Dict[str, Any]]:
    _init_token_db(db_path)
    with _db_lock:
        conn = sqlite3.connect(str(db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT * FROM outlook_tokens WHERE email = ?", (email_addr.strip().lower(),)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def _save_cached_tokens(
    email_addr: str,
    refresh_token: str,
    access_token: str,
    expires_at: float,
    client_id: str = OUTLOOK_HUB_CLIENT_ID,
    db_path: Path = OUTLOOK_DB_PATH,
) -> None:
    _init_token_db(db_path)
    with _db_lock:
        conn = sqlite3.connect(str(db_path), timeout=15.0)
        try:
            conn.execute(
                """
                INSERT INTO outlook_tokens (email, refresh_token, access_token, expires_at, client_id, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    refresh_token = excluded.refresh_token,
                    access_token = excluded.access_token,
                    expires_at = excluded.expires_at,
                    client_id = excluded.client_id,
                    updated_at = excluded.updated_at
                """,
                (
                    email_addr.strip().lower(),
                    refresh_token,
                    access_token,
                    expires_at,
                    client_id,
                    time.time(),
                ),
            )
            conn.commit()
        finally:
            conn.close()


# ============================================================================
# TOTP + Recovery IMAP Helpers (from outlook-hub/vault_utils.py & imap_client.py)
# ============================================================================

def generate_hotmail_totp(secret: str, step: int = 30, digits: int = 6) -> Tuple[str, int]:
    cleaned = re.sub(r"[\s\-]+", "", (secret or "")).upper()
    if not cleaned:
        return "", 0
    padding = "=" * (-len(cleaned) % 8)
    try:
        key = base64.b32decode(cleaned + padding, casefold=True)
    except Exception:
        return "", 0
    now = time.time()
    counter = int(now // step)
    remaining = step - int(now % step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits), remaining


def _decode_mime_header(val: Optional[str]) -> str:
    if not val:
        return ""
    out: List[str] = []
    for chunk, charset in decode_header(val):
        if isinstance(chunk, bytes):
            enc = charset or "utf-8"
            try:
                out.append(chunk.decode(enc, errors="replace"))
            except LookupError:
                out.append(chunk.decode("utf-8", errors="replace"))
        else:
            out.append(str(chunk))
    return "".join(out).strip()


def _html_to_text(raw_html: str) -> str:
    cleaned = _STYLE_SCRIPT_RE.sub(" ", raw_html)
    cleaned = re.sub(r"<br\s*/?>", "\n", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"</(p|div|tr|li|h[1-6])>", "\n", cleaned, flags=re.IGNORECASE)
    cleaned = _TAG_RE.sub(" ", cleaned)
    cleaned = html.unescape(cleaned)
    return re.sub(r"[ \t]+", " ", cleaned).strip()


def _extract_email_body(msg: Message) -> str:
    plain_parts: List[str] = []
    html_parts: List[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            if "attachment" in str(part.get("Content-Disposition") or "").lower():
                continue
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except LookupError:
                decoded = payload.decode("utf-8", errors="replace")
            if part.get_content_type() == "text/plain":
                plain_parts.append(decoded)
            elif part.get_content_type() == "text/html":
                html_parts.append(decoded)
    else:
        payload = msg.get_payload(decode=True)
        if payload is not None:
            charset = msg.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except LookupError:
                decoded = payload.decode("utf-8", errors="replace")
            if msg.get_content_type() == "text/html":
                html_parts.append(decoded)
            else:
                plain_parts.append(decoded)
    if plain_parts:
        return "\n".join(p.strip() for p in plain_parts if p.strip())
    if html_parts:
        return _html_to_text("\n".join(html_parts))
    return ""


def fetch_recovery_imap_codes(
    recovery_email: str,
    recovery_password: str,
    limit: int = 5,
    timeout: int = 12,
) -> List[str]:
    """Reads Microsoft security code from Firstmail / Polosmail / Rambler recovery IMAP."""
    domain = recovery_email.strip().lower().split("@")[-1] if "@" in recovery_email else ""
    host = KNOWN_RECOVERY_IMAP_HOSTS.get(domain, DEFAULT_RECOVERY_IMAP_HOST)
    codes: List[str] = []
    client = imaplib.IMAP4_SSL(host, 993, timeout=timeout)
    try:
        client.login(recovery_email.strip(), recovery_password.strip())
        for folder in ("INBOX", "Junk", "Spam"):
            st, _ = client.select(folder, readonly=True)
            if st != "OK":
                continue
            st, sdata = client.search(None, "ALL")
            if st != "OK" or not sdata or not sdata[0]:
                continue
            nums = list(reversed(sdata[0].split()[-limit:]))
            for num in nums:
                fst, rdata = client.fetch(num, "(RFC822)")
                if fst != "OK" or not rdata:
                    continue
                raw_bytes = next(
                    (p[1] for p in rdata if isinstance(p, tuple) and len(p) >= 2 and isinstance(p[1], bytes)),
                    None,
                )
                if not raw_bytes:
                    continue
                parsed = email.message_from_bytes(raw_bytes)
                subj = _decode_mime_header(parsed.get("Subject"))
                body = _extract_email_body(parsed)
                combined = f"{subj}\n{_URL_RE.sub(' ', body)}"
                for m in _CODE_NEAR_KEYWORD_RE.finditer(combined):
                    if m.group(1) not in codes:
                        codes.append(m.group(1))
                if not codes:
                    for m in _STANDALONE_CODE_RE.finditer(combined):
                        if m.group(1) not in codes:
                            codes.append(m.group(1))
            if codes:
                break
    finally:
        try:
            client.logout()
        except Exception:
            pass
    return codes


# ============================================================================
# PKCE OAuth2 + Headless Chromium Step-1 Auto-Login (outlook-hub/auto_login.py)
# ============================================================================

def _generate_pkce_pair() -> Tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _find_chrome_executable() -> Optional[str]:
    for cand in (
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which("google-chrome") or shutil.which("chromium")


def _exchange_auth_code(code: str, code_verifier: str, client_id: str = OUTLOOK_HUB_CLIENT_ID) -> Dict[str, Any]:
    with httpx.Client(timeout=25.0) as http:
        resp = http.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            data={
                "client_id": client_id,
                "scope": GRAPH_SCOPES,
                "code": code,
                "redirect_uri": OUTLOOK_HUB_REDIRECT_URI,
                "grant_type": "authorization_code",
                "code_verifier": code_verifier,
            },
        )
        data = resp.json()
        if resp.status_code >= 400 or "access_token" not in data:
            err_desc = data.get("error_description") or data.get("error") or f"HTTP {resp.status_code}"
            raise OutlookHubError(f"Ошибка обмена OAuth2 кода Microsoft: {err_desc[:240]}")
        expires_in = int(data.get("expires_in") or 3600)
        return {
            "access_token": str(data["access_token"]),
            "refresh_token": str(data.get("refresh_token") or ""),
            "expires_at": time.time() + expires_in,
        }


def _refresh_graph_token(refresh_token: str, client_id: str = OUTLOOK_HUB_CLIENT_ID) -> Optional[Dict[str, Any]]:
    try:
        with httpx.Client(timeout=20.0) as http:
            resp = http.post(
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                data={
                    "client_id": client_id or OUTLOOK_HUB_CLIENT_ID,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "scope": GRAPH_SCOPES,
                },
            )
            if resp.status_code != 200:
                return None
            tok = resp.json()
            if "access_token" not in tok:
                return None
            return {
                "access_token": str(tok["access_token"]),
                "refresh_token": str(tok.get("refresh_token") or refresh_token),
                "expires_at": time.time() + int(tok.get("expires_in") or 3600),
            }
    except Exception:
        return None


def authorize_outlook_via_hub(
    *,
    outlook_email: str,
    outlook_login: str = "",
    outlook_password: str,
    recovery_email: str = "",
    recovery_password: str = "",
    hotmail_totp: str = "",
    timeout_sec: int = 75,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    Runs Outlook Hub's headless Chromium Step-1 OAuth2 flow for an Outlook/Hotmail mailbox,
    in-process intercepting `http://localhost:8765/callback` and returning Graph tokens.
    """
    if not _HAS_PLAYWRIGHT:
        raise OutlookHubError(
            "Для чтения Outlook через outlook-hub требуется пакет playwright (`pip install playwright playwright-stealth && playwright install chromium`)."
        )

    def log(msg: str) -> None:
        if log_fn:
            log_fn(f"[OutlookHub:{outlook_email}] {msg}")

    login_user = (outlook_login or outlook_email).strip()
    state = secrets.token_urlsafe(24)
    code_verifier, code_challenge = _generate_pkce_pair()
    auth_url = (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"
        + urlencode(
            {
                "client_id": OUTLOOK_HUB_CLIENT_ID,
                "response_type": "code",
                "redirect_uri": OUTLOOK_HUB_REDIRECT_URI,
                "response_mode": "query",
                "scope": GRAPH_SCOPES,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "prompt": "login",
                "login_hint": login_user,
            }
        )
    )

    chrome_exec = _find_chrome_executable()
    captured_auth_code: List[str] = []
    _ensure_local_callback_server()

    def _pop_captured_code() -> Optional[str]:
        if captured_auth_code:
            return captured_auth_code[0]
        with _callback_lock:
            if state in _callback_codes_by_state:
                return _callback_codes_by_state.pop(state)
        return None

    with _browser_semaphore:
        log("Запуск headless Chromium (Outlook Hub Step-1 OAuth2)...")
        with sync_playwright() as p:
            launch_kwargs: Dict[str, Any] = {
                "headless": True,
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--host-resolver-rules=MAP localhost 127.0.0.1",
                ],
            }
            if chrome_exec:
                launch_kwargs["executable_path"] = chrome_exec

            browser = p.chromium.launch(**launch_kwargs)
            try:
                context = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                    ),
                    viewport={"width": 1280, "height": 800},
                )
                page = context.new_page()
                if _HAS_STEALTH:
                    Stealth().apply_stealth_sync(page)

                def _inspect_req(req) -> None:
                    try:
                        u = req.url
                        if "code=" in u and ("localhost:8765" in u or "127.0.0.1:8765" in u or "nativeclient" in u):
                            parsed = urlparse(u)
                            qs = parse_qs(parsed.query or parsed.fragment)
                            c_val = (qs.get("code") or [""])[0]
                            if c_val and c_val not in captured_auth_code:
                                captured_auth_code.append(c_val)
                    except Exception:
                        pass

                page.on("request", _inspect_req)
                page.on("requestfailed", _inspect_req)

                log("Переход на страницу входа Microsoft...")
                page.goto(auth_url, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(1800)

                # 1. Email / Login input
                email_inp = page.query_selector('input[type="email"], input[name="loginfmt"]')
                if email_inp and email_inp.is_visible():
                    log(f"Ввод логина почты ({login_user})...")
                    email_inp.fill(login_user)
                    page.wait_for_timeout(300)
                    btn = page.query_selector('button[type="submit"], input[type="submit"], #idSIButton9')
                    if btn:
                        btn.click()
                    page.wait_for_timeout(2400)
                else:
                    tile = page.query_selector(f'div[data-test-id="{login_user}"]')
                    if tile and tile.is_visible():
                        tile.click()
                        page.wait_for_timeout(2200)

                # 2. Password input (handle passwordless / "Other ways to sign in")
                pwd_inp = None
                clicked_use_password = False
                clicked_other_ways = False

                for _ in range(20):
                    pwd_inp = page.query_selector('input[type="password"], input[name="passwd"]')
                    if pwd_inp and pwd_inp.is_visible():
                        break
                    if not clicked_use_password:
                        for txt in (
                            "Use your password",
                            "Sign in with your password",
                            "Use my password",
                            "Использовать пароль",
                            "Войти с помощью пароля",
                        ):
                            loc = page.get_by_text(txt)
                            if loc.count() and loc.first.is_visible():
                                log(f"Переключение на вход по паролю ({txt})...")
                                loc.first.click()
                                clicked_use_password = True
                                page.wait_for_timeout(1200)
                                break
                    if not clicked_use_password and not clicked_other_ways:
                        for txt in ("Other ways to sign in", "Другие способы входа"):
                            loc = page.get_by_text(txt)
                            if loc.count() and loc.first.is_visible():
                                loc.first.click()
                                clicked_other_ways = True
                                page.wait_for_timeout(1200)
                                break
                    page.wait_for_timeout(500)

                if pwd_inp and pwd_inp.is_visible():
                    log("Ввод пароля от Outlook...")
                    pwd_inp.fill(outlook_password)
                    page.wait_for_timeout(300)
                    btn = page.query_selector('button[type="submit"], input[type="submit"], #idSIButton9')
                    if btn:
                        btn.click()
                    page.wait_for_timeout(2800)
                else:
                    err_low = page.inner_text("body").lower()
                    if "account doesn't exist" in err_low or "учетная запись не существует" in err_low:
                        raise OutlookHubError(f"Почта {login_user} не существует в Microsoft.")
                    if not any(
                        k in err_low
                        for k in ("verify your email", "подтвердите адрес", "sent a code", "authenticator")
                    ):
                        raise OutlookHubError("Поле ввода пароля Microsoft не появилось.")

                # 3. 2FA / Recovery Email / Consent loop
                start_time = time.time()
                seen_email_verification = False
                last_code_entered = ""

                while time.time() - start_time < timeout_sec:
                    got_code = _pop_captured_code()
                    if got_code:
                        log("Получен OAuth2 code, обмен на Microsoft Graph токен...")
                        tokens = _exchange_auth_code(got_code, code_verifier)
                        if tokens.get("refresh_token"):
                            _save_cached_tokens(
                                outlook_email,
                                refresh_token=tokens["refresh_token"],
                                access_token=tokens["access_token"],
                                expires_at=tokens["expires_at"],
                            )
                        log("Почта успешно подключена к Microsoft Graph API!")
                        return tokens

                    try:
                        cur_url = page.url
                        body_text = page.inner_text("body").lower()
                        title = page.title().lower()
                    except Exception:
                        page.wait_for_timeout(400)
                        continue

                    if "incorrect" in body_text and ("password" in body_text or "account or password" in body_text):
                        raise OutlookHubError("Неверный пароль от почты Outlook.")
                    if "пароль неверен" in body_text:
                        raise OutlookHubError("Неверный пароль от почты Outlook.")
                    if "account has been locked" in body_text or "аккаунт заблокирован" in body_text:
                        raise OutlookHubError("Почта Outlook заблокирована Microsoft.")

                    # Authenticator / Hotmail 2FA TOTP
                    if (
                        "authenticator" in body_text
                        or "authenticator" in title
                        or ("enter code" in title and hotmail_totp and not seen_email_verification)
                        or ("verify your identity" in body_text and "verification code" in body_text and hotmail_totp)
                    ):
                        # Sometimes Microsoft asks to choose "Enter a code from a verification app"
                        totp_opt = page.query_selector('[data-value="PhoneAppOTP"]')
                        if totp_opt and totp_opt.is_visible():
                            totp_opt.click()
                            page.wait_for_timeout(1200)
                            continue

                        if not hotmail_totp:
                            if recovery_email:
                                alt_link = page.query_selector('#signInAnotherWay, a:has-text("Use a different verification option")')
                                if alt_link and alt_link.is_visible():
                                    alt_link.click()
                                    page.wait_for_timeout(1500)
                                    continue
                            raise OutlookHubError("Microsoft требует 2FA код от почты, но 2FA-ключ почты не указан.")

                        totp_code, rem = generate_hotmail_totp(hotmail_totp)
                        if rem < 4:
                            page.wait_for_timeout((rem + 1) * 1000)
                            totp_code, _ = generate_hotmail_totp(hotmail_totp)

                        if totp_code and totp_code != last_code_entered:
                            code_inp = None
                            for inp in page.query_selector_all("input"):
                                if (
                                    inp.is_visible()
                                    and inp.get_attribute("type") in ("text", "tel", "number", None)
                                    and inp.get_attribute("id") != "proof-confirmation-email-input"
                                ):
                                    code_inp = inp
                                    break
                            if code_inp:
                                log(f"Ввод 2FA TOTP кода от Hotmail ({totp_code})...")
                                code_inp.fill(totp_code)
                                last_code_entered = totp_code
                                page.wait_for_timeout(350)
                                btn = (
                                    page.query_selector('button[type="submit"]:visible, input[type="submit"]:visible, #idSIButton9')
                                    or page.query_selector('button[type="submit"], input[type="submit"]')
                                )
                                if btn:
                                    btn.click()
                                page.wait_for_timeout(3000)
                                continue

                    # Stay signed in?
                    if "stay signed in" in body_text or "оставаться в системе" in body_text:
                        btn = page.query_selector('#idSIButton9, button:has-text("Yes"), input[value="Yes"]')
                        if btn and btn.is_visible():
                            btn.click()
                            page.wait_for_timeout(2500)
                            continue

                    # Consent screen ("Let this app access your info?")
                    if (
                        "let this app access your info" in body_text
                        or "accept" in body_text
                        or "разрешения" in body_text
                        or "consent" in cur_url.lower()
                    ):
                        accept_btn = page.query_selector(
                            'button:has-text("Accept"), input[value="Accept"], #idBtn_Accept, '
                            'button:has-text("Да"), button:has-text("Yes")'
                        )
                        if accept_btn and accept_btn.is_visible():
                            log("Подтверждение разрешений OAuth2 (Consent)...")
                            accept_btn.click()
                            page.wait_for_timeout(2500)
                            continue

                    # Recovery email confirmation ("Verify your email" / "Help us protect your account")
                    if (
                        "verify your email" in body_text
                        or "подтвердите адрес" in body_text
                        or "help us protect" in body_text
                    ):
                        seen_email_verification = True
                        proof_inp = page.query_selector(
                            'input[id="proof-confirmation-email-input"], '
                            'input[name="otcConfirmationText"], input[id="proofConfirmationText"], '
                            'input[name="proofEmail"], input[type="email"]'
                        )
                        if proof_inp and proof_inp.is_visible():
                            if not recovery_email:
                                raise OutlookHubError("Microsoft просит резервную почту, но она не указана.")
                            log(f"Подтверждение резервной почты ({recovery_email})...")
                            proof_inp.fill(recovery_email)
                            page.wait_for_timeout(350)
                            btn = page.query_selector('button[type="submit"], input[type="submit"], #idSIButton9')
                            if btn:
                                btn.click()
                            page.wait_for_timeout(3200)
                            continue

                        email_option = page.query_selector('#iProofEmail, [data-value="Email"], div:has-text("Email")')
                        if email_option and email_option.is_visible():
                            email_option.click()
                            page.wait_for_timeout(1500)
                            continue

                    # Enter code sent to recovery email (Firstmail / Polosmail IMAP)
                    if "sent a code" in body_text or "мы отправили код" in body_text or "we've sent a code" in body_text:
                        if not recovery_email or not recovery_password:
                            raise OutlookHubError("Microsoft отправил код на доп. почту, но нет данных доп. почты.")
                        log(f"Чтение кода безопасности Microsoft с доп. почты {recovery_email}...")
                        rec_code = None
                        for _ in range(12):
                            page.wait_for_timeout(2500)
                            try:
                                found_codes = fetch_recovery_imap_codes(recovery_email, recovery_password, limit=4)
                                if found_codes and found_codes[0] != last_code_entered:
                                    rec_code = found_codes[0]
                                    break
                            except Exception:
                                pass
                        if not rec_code:
                            raise OutlookHubError(f"Код безопасности Microsoft не пришёл на {recovery_email}.")
                        log(f"Ввод кода с доп. почты ({rec_code})...")
                        for inp in page.query_selector_all("input"):
                            if inp.is_visible() and inp.get_attribute("type") in ("text", "tel", "number", None):
                                inp.fill(rec_code)
                                last_code_entered = rec_code
                                page.wait_for_timeout(350)
                                btn = page.query_selector('button[type="submit"], input[type="submit"], #idSIButton9')
                                if btn:
                                    btn.click()
                                page.wait_for_timeout(3200)
                                break
                        continue

                    # Skip Microsoft promo screens ("Protect your account", "Break free from passwords")
                    skip_btn = page.query_selector(
                        '#iShowSkip, #iCancel, a:has-text("Skip for now"), a:has-text("No thanks"), '
                        'button:has-text("No thanks"), button:has-text("Skip")'
                    )
                    if skip_btn and skip_btn.is_visible():
                        skip_btn.click()
                        page.wait_for_timeout(1800)
                        continue

                    page.wait_for_timeout(900)

                got_code = _pop_captured_code()
                if got_code:
                    tokens = _exchange_auth_code(got_code, code_verifier)
                    if tokens.get("refresh_token"):
                        _save_cached_tokens(
                            outlook_email,
                            refresh_token=tokens["refresh_token"],
                            access_token=tokens["access_token"],
                            expires_at=tokens["expires_at"],
                        )
                    return tokens

                raise OutlookHubError(f"Таймаут авторизации Outlook ({timeout_sec}с). URL: {page.url[:120]}")
            finally:
                browser.close()


# ============================================================================
# Graph API Polling — STRICTLY NEW TikTok OTP codes AFTER `min_timestamp`
# ============================================================================

def _parse_iso_ts(iso_str: str) -> float:
    if not iso_str:
        return 0.0
    try:
        return dt.datetime.fromisoformat(iso_str.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def _fetch_graph_messages(http: httpx.Client, access_token: str, top: int = 8) -> Tuple[str, List[Dict[str, Any]]]:
    resp = http.get(
        f"{GRAPH_BASE}/me/messages",
        params={
            "$top": str(top),
            "$orderby": "receivedDateTime desc",
            "$select": "id,subject,from,receivedDateTime,bodyPreview,body",
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if resp.status_code in (401, 403):
        return "unauthorized", []
    if resp.status_code != 200:
        return "error", []

    items = resp.json().get("value") or []
    out: List[Dict[str, Any]] = []
    for m in items:
        sender_obj = (m.get("from") or {}).get("emailAddress") or {}
        sender = f"{sender_obj.get('name') or ''} <{sender_obj.get('address') or ''}>".strip()
        rec_iso = str(m.get("receivedDateTime") or "")
        body_html = str((m.get("body") or {}).get("content") or "")
        out.append(
            {
                "id": str(m.get("id") or ""),
                "subject": str(m.get("subject") or ""),
                "sender": sender,
                "received_at": rec_iso,
                "received_ts": _parse_iso_ts(rec_iso),
                "preview": str(m.get("bodyPreview") or ""),
                "body_html": body_html,
            }
        )
    return "ok", out


def _extract_tiktok_otp(msg: Dict[str, Any]) -> Optional[str]:
    subject = str(msg.get("subject") or "")
    sender = str(msg.get("sender") or "")
    preview = str(msg.get("preview") or "")
    body_html = str(msg.get("body_html") or "")
    subj_low = subject.lower()
    combined_low = f"{sender} {subject} {preview}".lower()

    if any(p in subj_low or p in preview.lower() for p in _NOISE_PHRASES):
        return None
    if "tiktok" not in combined_low and "tiktok" not in body_html.lower():
        return None

    # 1) Strict word-bounded 6-digit numeric code (never matches inside hex hashes like #82dba...c252354b27...)
    plain_body = _html_to_text(body_html) if body_html else preview
    # Strip long hex tokens and URLs before scanning for standalone 6-digit code
    cleaned_body = _URL_RE.sub(" ", plain_body)
    cleaned_body = re.sub(r"#[0-9a-fA-F]{12,}", " ", cleaned_body)

    for text_src in (subject, cleaned_body):
        m = re.search(r"\b(\d{6})\b", text_src)
        if m:
            return m.group(1)

    # 2) Fallback: if TikTok sent 'Your TikTok login link' with `email_verification?...&code=<UUID>`
    if body_html and "email_verification" in body_html:
        for href in re.findall(r'href=["\']([^"\']+)["\']', body_html):
            u = html.unescape(href)
            if "email_verification" in u and "code=" in u:
                qs = parse_qs(urlparse(u).query)
                uuid_code = (qs.get("code") or [None])[0]
                if uuid_code:
                    return uuid_code

    return None


def ensure_outlook_access_token(
    *,
    outlook_email: str,
    outlook_login: str = "",
    outlook_password: str,
    recovery_email: str = "",
    recovery_password: str = "",
    hotmail_totp: str = "",
    log_fn: Optional[Callable[[str], None]] = None,
) -> str:
    """Returns a valid Microsoft Graph `access_token`, using cached `refresh_token` if available."""
    cached = _get_cached_tokens(outlook_email)
    if cached:
        if cached.get("access_token") and float(cached.get("expires_at") or 0) > time.time() + 90:
            with httpx.Client(timeout=12.0) as http:
                st, _ = _fetch_graph_messages(http, cached["access_token"], top=1)
                if st == "ok":
                    return str(cached["access_token"])
        if cached.get("refresh_token"):
            refreshed = _refresh_graph_token(
                str(cached["refresh_token"]),
                client_id=str(cached.get("client_id") or OUTLOOK_HUB_CLIENT_ID),
            )
            if refreshed:
                _save_cached_tokens(
                    outlook_email,
                    refresh_token=refreshed["refresh_token"],
                    access_token=refreshed["access_token"],
                    expires_at=refreshed["expires_at"],
                )
                return refreshed["access_token"]

    tokens = authorize_outlook_via_hub(
        outlook_email=outlook_email,
        outlook_login=outlook_login,
        outlook_password=outlook_password,
        recovery_email=recovery_email,
        recovery_password=recovery_password,
        hotmail_totp=hotmail_totp,
        log_fn=log_fn,
    )
    return tokens["access_token"]


def prepare_outlook_hub_mailbox(
    *,
    outlook_email: str,
    outlook_login: str = "",
    outlook_password: str,
    recovery_email: str = "",
    recovery_password: str = "",
    hotmail_totp: str = "",
    log_fn: Optional[Callable[[str], None]] = None,
) -> Tuple[str, Set[str]]:
    """
    Logs into Outlook/Hotmail FIRST (before requesting the TikTok code), verifies Graph API
    connectivity, and snapshots all existing message IDs currently in the mailbox so that
    only brand-new emails arriving AFTER the TikTok request will be accepted.
    """
    access_token = ensure_outlook_access_token(
        outlook_email=outlook_email,
        outlook_login=outlook_login,
        outlook_password=outlook_password,
        recovery_email=recovery_email,
        recovery_password=recovery_password,
        hotmail_totp=hotmail_totp,
        log_fn=log_fn,
    )
    existing_ids: Set[str] = set()
    with httpx.Client(timeout=15.0) as http:
        st, msgs = _fetch_graph_messages(http, access_token, top=15)
        if st == "ok":
            for m in msgs:
                if m.get("id"):
                    existing_ids.add(str(m["id"]))
    if log_fn:
        log_fn(
            f"Почта {outlook_email} готова (запомнено {len(existing_ids)} старых писем — ждём запрос в TikTok)"
        )
    return access_token, existing_ids


def wait_for_outlook_hub_code(
    *,
    outlook_email: str,
    outlook_login: str = "",
    outlook_password: str,
    recovery_email: str = "",
    recovery_password: str = "",
    hotmail_totp: str = "",
    min_timestamp: float,
    pre_access_token: str = "",
    known_old_ids: Optional[Set[str]] = None,
    timeout_sec: int = 90,
    poll_interval_sec: float = 1.0,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Optional[str]:
    """
    Polls Microsoft Graph API in real time (~1s interval) for a brand-new TikTok code
    (`id not in known_old_ids` and `received_ts >= min_timestamp - 3.0`).
    """
    def log(msg: str) -> None:
        if log_fn:
            log_fn(msg)

    access_token = pre_access_token or ensure_outlook_access_token(
        outlook_email=outlook_email,
        outlook_login=outlook_login,
        outlook_password=outlook_password,
        recovery_email=recovery_email,
        recovery_password=recovery_password,
        hotmail_totp=hotmail_totp,
        log_fn=log_fn,
    )

    old_ids: Set[str] = set(known_old_ids or set())
    strict_cutoff = min_timestamp - 3.0
    logged_old_ids: Set[str] = set()
    deadline = time.time() + timeout_sec

    log(
        f"Параллельное ожидание НОВОГО кода TikTok в {outlook_email} "
        f"(после {dt.datetime.fromtimestamp(min_timestamp, tz=dt.timezone.utc).strftime('%H:%M:%S')} UTC)..."
    )

    with httpx.Client(timeout=15.0) as http:
        while time.time() < deadline:
            status, msgs = _fetch_graph_messages(http, access_token, top=8)
            if status == "unauthorized":
                cached = _get_cached_tokens(outlook_email)
                if cached and cached.get("refresh_token"):
                    ref = _refresh_graph_token(str(cached["refresh_token"]))
                    if ref:
                        access_token = ref["access_token"]
                        _save_cached_tokens(
                            outlook_email,
                            refresh_token=ref["refresh_token"],
                            access_token=ref["access_token"],
                            expires_at=ref["expires_at"],
                        )
                        continue
                break

            if status == "ok":
                msgs.sort(key=lambda x: float(x.get("received_ts") or 0.0), reverse=True)
                for m in msgs:
                    mid = m.get("id") or ""
                    code = _extract_tiktok_otp(m)
                    if not code:
                        continue
                    rec_ts = float(m.get("received_ts") or 0.0)
                    is_new = (mid not in old_ids) and (rec_ts >= strict_cutoff)
                    if is_new:
                        log(
                            f"Получен НОВЫЙ код TikTok из Outlook Hub: {code} "
                            f"(время письма: {m.get('received_at')}, тема: {m.get('subject')!r})"
                        )
                        return code
                    elif mid not in logged_old_ids:
                        logged_old_ids.add(mid)
                        log(
                            f"Пропущено старое письмо с кодом {code} ({m.get('received_at')}), ждём новый код..."
                        )

            time.sleep(poll_interval_sec)

    return None
