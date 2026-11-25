"""Session management: sticky proxy validation, cookie persistence, Kintaro/cookies.json loader, and TOTP + Outlook Hub login."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import struct
import time
import urllib.parse
from typing import Any, Dict, Optional, Tuple

import httpx

try:
    import curl_cffi.requests as crequests
    _HAS_CURL_CFFI = True
except ImportError:
    crequests = None  # type: ignore[assignment]
    _HAS_CURL_CFFI = False

from config import FALLBACK_GATEWAYS, IDC_GATEWAY_MAP, WWW_BASE
from models import AccountSpec

CHROME_CANDIDATES = (
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
)

DESKTOP_CHROME_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def normalize_proxy_url(raw_proxy: Optional[str]) -> Optional[str]:
    """Support standard URLs (http/socks5://...) verbatim and 'host:port:user:pass' shorthand."""
    if not raw_proxy:
        return None
    raw = raw_proxy.strip()
    if "://" in raw:
        return raw
    parts = raw.split(":")
    if len(parts) == 4:
        host, port, user, pw = parts
        return f"http://{urllib.parse.quote(user, safe='-_')}:{urllib.parse.quote(pw, safe='-_')}@{host}:{port}"
    if len(parts) == 2:
        return f"http://{raw}"
    raise ValueError(f"Unrecognized proxy format: {raw_proxy!r}")


def playwright_proxy_dict(proxy_url: Optional[str], for_chromium: bool = False) -> Optional[Dict[str, str]]:
    """Convert proxy URL into Playwright/Camoufox proxy dictionary (auto-mapping bpproxy SOCKS5:1002 -> HTTP:1000 for Chromium)."""
    if not proxy_url:
        return None
    parsed = urllib.parse.urlsplit(proxy_url)
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname or ""
    port = parsed.port or 80

    if for_chromium and scheme.startswith("socks") and "bpproxy.at" in host and port == 1002:
        scheme = "http"
        port = 1000

    server = f"{scheme}://{host}:{port}"
    out: Dict[str, str] = {"server": server}
    if parsed.username:
        out["username"] = urllib.parse.unquote(parsed.username)
    if parsed.password:
        out["password"] = urllib.parse.unquote(parsed.password)
    return out


def generate_fresh_totp(secret: str) -> str:
    """Generate 6-digit RFC 6238 TOTP, waiting if <5s remain in the current 30s window."""
    rem = 30 - (int(time.time()) % 30)
    if rem < 5:
        time.sleep(rem + 1)
    clean = secret.strip().replace(" ", "").upper()
    pad = (-len(clean)) % 8
    key = base64.b32decode(clean + ("=" * pad), casefold=True)
    counter = int(time.time() // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code_int:06d}"


def find_chrome_executable() -> Optional[str]:
    for cand in CHROME_CANDIDATES:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


class SessionManager:
    def __init__(self, base_dir: str, allow_direct: bool = False):
        self.sessions_root = os.path.join(base_dir, "sessions")
        self.allow_direct = allow_direct
        os.makedirs(self.sessions_root, exist_ok=True)

    def account_dir(self, username: str) -> str:
        path = os.path.join(self.sessions_root, username)
        os.makedirs(path, exist_ok=True)
        return path

    def cookies_file(self, username: str) -> str:
        return os.path.join(self.account_dir(username), "cookies.json")

    def profile_dir(self, username: str) -> str:
        path = os.path.join(self.account_dir(username), "browser_profile")
        os.makedirs(path, exist_ok=True)
        return path

    def ensure_proxy_policy(self, spec: AccountSpec) -> Optional[str]:
        proxy_url = normalize_proxy_url(spec.proxy)
        if not proxy_url:
            # Check if a saved Kintaro session JSON has an embedded sticky proxy
            kintaro_fp = os.path.join(self.sessions_root, f"{spec.username}.json")
            if os.path.exists(kintaro_fp):
                try:
                    with open(kintaro_fp, "r", encoding="utf-8") as f:
                        kdata = json.load(f)
                        if kdata.get("proxy"):
                            proxy_url = normalize_proxy_url(kdata["proxy"])
                            spec.proxy = proxy_url
                except Exception:
                    pass
        if not proxy_url and not self.allow_direct:
            raise RuntimeError(
                f"[{spec.username}] Не указан прокси под гео аккаунта! "
                "Вход с чужого/серверного IP меняет SystemRegion, вешает 'Update your account region' "
                "и отправляет аккаунт в тень (bric_social / 0 просмотров). "
                "Передай --proxy <url> (или 5-м полем в строке аккаунта), либо --allow-direct только для тестового расходника."
            )
        return proxy_url

    def build_http_session(self, cookies: Dict[str, str], proxy_url: Optional[str]) -> Any:
        if _HAS_CURL_CFFI:
            proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
            sess = crequests.Session(impersonate="chrome124", proxies=proxies, timeout=22)
            sess.cookies.update(cookies)
            return sess
        return httpx.Client(
            proxy=proxy_url,
            cookies=cookies,
            headers={
                "user-agent": DESKTOP_CHROME_UA,
                "accept": "application/json, text/plain, */*",
            },
            timeout=22.0,
            follow_redirects=True,
        )

    def load_saved_cookies(self, username: str) -> Dict[str, str]:
        cfile = self.cookies_file(username)
        if os.path.exists(cfile):
            with open(cfile, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return {str(k): str(v) for k, v in data.items() if v is not None and str(v) != ""}

        # Support Kintaro `sessions/<username>.json` (`device.cookies` or `x_device`)
        kintaro_fp = os.path.join(self.sessions_root, f"{username}.json")
        if os.path.exists(kintaro_fp):
            try:
                with open(kintaro_fp, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                dev = raw.get("device") or (json.loads(raw["x_device"]) if isinstance(raw.get("x_device"), str) else None)
                if isinstance(dev, str):
                    dev = json.loads(dev)
                cks = (dev or {}).get("cookies") if isinstance(dev, dict) else None
                if isinstance(cks, dict) and (cks.get("sessionid") or cks.get("sid_tt")):
                    clean_cks = {str(k): str(v) for k, v in cks.items() if v is not None and str(v) != ""}
                    self.save_cookies(username, clean_cks)
                    return clean_cks
            except Exception:
                pass

        # Fallback: extract from Firefox cookies.sqlite inside browser_profile if present
        sqlite_path = os.path.join(self.profile_dir(username), "cookies.sqlite")
        if os.path.exists(sqlite_path):
            return self._extract_sqlite_cookies(sqlite_path, username)
        return {}

    def _extract_sqlite_cookies(self, sqlite_path: str, username: str) -> Dict[str, str]:
        tmp_copy = os.path.join(self.account_dir(username), "_tmp_cookies.sqlite")
        shutil.copy(sqlite_path, tmp_copy)
        try:
            conn = sqlite3.connect(tmp_copy)
            rows = conn.execute("SELECT host, name, value FROM moz_cookies").fetchall()
            conn.close()
        finally:
            if os.path.exists(tmp_copy):
                os.remove(tmp_copy)
        cookies = {name: val for host, name, val in rows if "tiktok" in host}
        if cookies.get("sessionid") or cookies.get("sid_tt"):
            self.save_cookies(username, cookies)
        return cookies

    def save_cookies(self, username: str, cookies: Dict[str, str]) -> None:
        with open(self.cookies_file(username), "w", encoding="utf-8") as f:
            json.dump(cookies, f, indent=2, ensure_ascii=False)

    def verify_cookies(
        self, cookies: Dict[str, str], proxy_url: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Validate session without triggering passport login; returns user metadata if alive."""
        if not (cookies.get("sessionid") or cookies.get("sid_tt")):
            return None
        sess = self.build_http_session(cookies, proxy_url)
        try:
            resp = sess.get(
                f"{WWW_BASE}/tiktokstudio/api/web/user",
                params={"needIsVerified": "true", "needProfileBio": "true"},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            uid = str(data.get("userId") or "")
            if data.get("statusCode") == 0 and uid and uid != "0":
                return data
        except Exception:
            return None
        return None

    def resolve_idc_gateway(self, cookies: Dict[str, str], sess: Any) -> str:
        for key in ("store-idc", "tt-target-idc"):
            val = (cookies.get(key) or "").lower().strip()
            if val in IDC_GATEWAY_MAP:
                return IDC_GATEWAY_MAP[val]
        for gw in FALLBACK_GATEWAYS:
            try:
                r = sess.get(
                    f"{gw}/aweme/v1/notice/count/",
                    params={"aid": "1233", "app_name": "musical_ly", "device_platform": "iphone", "source": "1"},
                    timeout=8,
                )
                if r.status_code == 200 and r.json().get("groups_in_filters") is not None:
                    return gw
            except Exception:
                continue
        return FALLBACK_GATEWAYS[0]

    def get_authenticated_session(
        self, spec: AccountSpec
    ) -> Tuple[Any, Dict[str, str], Dict[str, Any], str]:
        """Return (http_session, cookies, user_meta, idc_gateway), logging in only if no valid cookies exist."""
        proxy_url = self.ensure_proxy_policy(spec)
        cookies = self.load_saved_cookies(spec.username)
        user_meta = self.verify_cookies(cookies, proxy_url)

        if user_meta:
            sess = self.build_http_session(cookies, proxy_url)
            gw = self.resolve_idc_gateway(cookies, sess)
            return sess, cookies, user_meta, gw

        if not spec.password:
            raise RuntimeError(
                f"[{spec.username}] Живые куки не найдены в sessions/{spec.username}/cookies.json и пароль для входа не передан."
            )

        cookies = self._login_with_browser(spec, proxy_url)
        user_meta = self.verify_cookies(cookies, proxy_url)
        if not user_meta:
            raise RuntimeError(f"[{spec.username}] Не удалось подтвердить сессию после входа (проверь лог/капчу/2FA).")
        sess = self.build_http_session(cookies, proxy_url)
        gw = self.resolve_idc_gateway(cookies, sess)
        return sess, cookies, user_meta, gw

    def _login_with_browser(self, spec: AccountSpec, proxy_url: Optional[str]) -> Dict[str, str]:
        pre_outlook_tok = ""
        known_old_ids: Optional[set] = None
        if spec.use_outlook_hub and spec.email and spec.mail_password:
            from outlook_hub import prepare_outlook_hub_mailbox

            pre_outlook_tok, known_old_ids = prepare_outlook_hub_mailbox(
                outlook_email=spec.email,
                outlook_login=spec.mail_login or spec.email,
                outlook_password=spec.mail_password,
                recovery_email=spec.recovery_email,
                recovery_password=spec.recovery_password,
                hotmail_totp=spec.mail_totp,
            )

        try:
            import camoufox.sync_api  # noqa: F401
            has_camoufox = True
        except ImportError:
            has_camoufox = False

        if has_camoufox:
            from camoufox.sync_api import Camoufox

            prof_dir = self.profile_dir(spec.username)
            pw_proxy = playwright_proxy_dict(proxy_url, for_chromium=False)
            kwargs: Dict[str, Any] = {
                "headless": True,
                "humanize": True,
                "persistent_context": True,
                "user_data_dir": prof_dir,
                "locale": "en-US",
            }
            if pw_proxy:
                kwargs["proxy"] = pw_proxy
                kwargs["geoip"] = True
            with Camoufox(**kwargs) as context:
                cookies = self._drive_web_login(context, spec, pre_outlook_tok, known_old_ids)
        else:
            from playwright.sync_api import sync_playwright

            exe = find_chrome_executable()
            pw_proxy = playwright_proxy_dict(proxy_url, for_chromium=True)
            with sync_playwright() as p:
                launch_kw: Dict[str, Any] = {
                    "headless": True,
                    "args": ["--disable-blink-features=AutomationControlled", "--no-sandbox"],
                }
                if exe:
                    launch_kw["executable_path"] = exe
                if pw_proxy:
                    launch_kw["proxy"] = pw_proxy
                browser = p.chromium.launch(**launch_kw)
                try:
                    context = browser.new_context(user_agent=DESKTOP_CHROME_UA, locale="en-US")
                    cookies = self._drive_web_login(context, spec, pre_outlook_tok, known_old_ids)
                finally:
                    browser.close()

        if not (cookies.get("sessionid") or cookies.get("sid_tt")):
            raise RuntimeError(f"[{spec.username}] Cookie sessionid не получена после логина (возможна капча или неверный пароль).")

        self.save_cookies(spec.username, cookies)
        return cookies

    def _drive_web_login(
        self,
        context: Any,
        spec: AccountSpec,
        pre_outlook_tok: str,
        known_old_ids: Optional[set],
    ) -> Dict[str, str]:
        page = context.pages[0] if context.pages else context.new_page()
        signin_ts = time.time()
        page.goto(f"{WWW_BASE}/login/phone-or-email/email", wait_until="domcontentloaded", timeout=45000)
        page.wait_for_timeout(5000)

        if "/login" in page.url:
            u_in = page.locator('input[name="username"]')
            p_in = page.locator('input[type="password"]')
            if u_in.count() == 0 or p_in.count() == 0:
                raise RuntimeError(f"[{spec.username}] Поля логина не отрендерились (URL={page.url}).")

            login_val = spec.email if (spec.use_outlook_hub and spec.email) else spec.username
            u_in.click()
            u_in.fill(login_val)
            page.wait_for_timeout(450)
            p_in.click()
            p_in.fill(spec.password)
            page.wait_for_timeout(650)
            signin_ts = time.time()
            page.locator('button[data-e2e="login-button"], button[type="submit"]').first.click()
            page.wait_for_timeout(6500)

            code_loc = page.locator('input[placeholder*="6-digit" i], input[placeholder*="code" i]')
            if "2sv" in page.url or code_loc.count() > 0:
                code = ""
                if spec.totp_secret:
                    code = generate_fresh_totp(spec.totp_secret)
                elif spec.use_outlook_hub and spec.email and spec.mail_password:
                    from outlook_hub import wait_for_outlook_hub_code

                    code = wait_for_outlook_hub_code(
                        outlook_email=spec.email,
                        outlook_login=spec.mail_login or spec.email,
                        outlook_password=spec.mail_password,
                        recovery_email=spec.recovery_email,
                        recovery_password=spec.recovery_password,
                        hotmail_totp=spec.mail_totp,
                        min_timestamp=signin_ts,
                        pre_access_token=pre_outlook_tok,
                        known_old_ids=known_old_ids,
                        timeout_sec=90,
                    )
                if not code:
                    raise RuntimeError(f"[{spec.username}] Аккаунт требует 6-значный код (2FA/Email), но TOTP или Outlook Hub не заданы.")
                t_in = code_loc.first if code_loc.count() > 0 else page.locator("input").first
                t_in.click()
                t_in.fill(code)
                page.wait_for_timeout(600)
                page.locator('button:has-text("Next"), button[type="submit"]').first.click()

            for _ in range(15):
                cks = {c["name"]: c["value"] for c in context.cookies()}
                if cks.get("sessionid") or cks.get("sid_tt"):
                    break
                page.wait_for_timeout(1000)

        return {c["name"]: c["value"] for c in context.cookies() if "tiktok" in c.get("domain", "")}
