"""Multi-channel appeal submission & verification engine with anti-shadowban pacing."""

from __future__ import annotations

import json
import random
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

from config import APPEAL_STAGGER_SECONDS, WWW_BASE
from models import AccountAuditResult, AccountSpec, NoticeViolation, PostPenalty
from scanner import AccountScanner
from session_mgr import (
    DESKTOP_CHROME_UA,
    SessionManager,
    find_chrome_executable,
    normalize_proxy_url,
    playwright_proxy_dict,
)

ANDROID_WEBVIEW_UA = (
    "Mozilla/5.0 (Linux; Android 16; SM-A546E Build/BP2A.250605.031.A3; wv) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.0.0 Mobile Safari/537.36 "
    "musical_ly_2024102030 JsSdk/1.0 NetType/WIFI Channel/googleplay AppName/musical_ly "
    "app_version/41.2.3 ByteLocale/en ByteFullLocale/en_US Region/US AppId/1233 "
    "Spark/1.5.9.1-bugfix BytedanceWebview/d8a21c6"
)


class AppealEngine:
    def __init__(
        self,
        sess: Any,
        cookies: Dict[str, str],
        idc_gateway: str,
        session_mgr: SessionManager,
        spec: AccountSpec,
    ):
        self.sess = sess
        self.cookies = cookies
        self.idc_gateway = idc_gateway.rstrip("/")
        self.session_mgr = session_mgr
        self.spec = spec
        self.scanner = AccountScanner(sess, idc_gateway)
        self.mobile_params = {
            "aid": "1233",
            "app_name": "musical_ly",
            "version_code": "37.1.0",
            "build_number": "371014",
            "device_platform": "iphone",
            "os_version": "17.5.1",
            "app_language": "en",
            "language": "en",
        }

    def process_audit(
        self,
        audit: AccountAuditResult,
        dry_run: bool = False,
        hide_rejected: bool = False,
        appeal_text: str = "",
    ) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            "notice_appeals_attempted": 0,
            "notice_appeals_verified": 0,
            "post_appeals_attempted": 0,
            "post_appeals_verified": 0,
            "posts_hidden": 0,
            "details": [],
        }

        appealable_notices = [
            v for v in audit.notice_violations if v.can_appeal or v.status_code == 1
        ]
        for idx, vio in enumerate(appealable_notices):
            if idx > 0 and not dry_run:
                delay = random.uniform(*APPEAL_STAGGER_SECONDS)
                print(f"  [~] Пауза {delay:.1f}с перед следующей апелляцией...")
                time.sleep(delay)

            if dry_run:
                summary["details"].append(
                    f"[DRY-RUN] Можно подать апелляцию на уведомление punish_id={vio.punish_id} (type={vio.punish_type}, title={vio.title!r})"
                )
                continue

            summary["notice_appeals_attempted"] += 1
            ok, msg = self.submit_notice_appeal(vio, audit.uid, appeal_text=appeal_text)
            if ok:
                summary["notice_appeals_verified"] += 1
            summary["details"].append(msg)

        appealable_posts = [
            p for p in audit.post_penalties if p.appeal_status == 0 or p.v2_can_appeal
        ]
        for idx, pp in enumerate(appealable_posts):
            if (idx > 0 or summary["notice_appeals_attempted"] > 0) and not dry_run:
                delay = random.uniform(*APPEAL_STAGGER_SECONDS)
                print(f"  [~] Пауза {delay:.1f}с перед апелляцией поста {pp.item_id}...")
                time.sleep(delay)

            if dry_run:
                summary["details"].append(
                    f"[DRY-RUN] Можно подать апелляцию на пост item_id={pp.item_id} (reasons={pp.reason_labels})"
                )
                continue

            summary["post_appeals_attempted"] += 1
            ok, msg = self.submit_post_appeal(pp)
            if ok:
                summary["post_appeals_verified"] += 1
            summary["details"].append(msg)

        if hide_rejected:
            rejected_posts = [p for p in audit.post_penalties if p.appeal_status == 5]
            for pp in rejected_posts:
                if dry_run:
                    summary["details"].append(
                        f"[DRY-RUN] Скрыл бы отклонённый пост item_id={pp.item_id} в Private"
                    )
                    continue
                ok, msg = self.set_post_private(pp.item_id)
                if ok:
                    summary["posts_hidden"] += 1
                summary["details"].append(msg)

        return summary

    def _fetch_appeal_reasons(self, object_id: str, appeal_type: int) -> List[Dict[str, Any]]:
        try:
            resp = self.sess.get(
                f"{self.idc_gateway}/tiktok/v1/appeal/reason/",
                params={**self.mobile_params, "object_id": object_id, "appeal_type": str(appeal_type)},
            )
            if resp.status_code == 200:
                return resp.json().get("appeal_reasons") or []
        except Exception:
            pass
        return []

    def submit_notice_appeal(
        self, vio: NoticeViolation, uid: str, appeal_text: str = ""
    ) -> Tuple[bool, str]:
        reasons = self._fetch_appeal_reasons(vio.object_id, vio.punish_type)
        selected_code = (reasons[0].get("code") or reasons[0].get("id")) if reasons else None

        body: Dict[str, Any] = {
            "ViolationId": vio.punish_id,
            "ViolationType": vio.punish_type,
            "UserId": uid,
            "ObjectId": vio.object_id,
            "appeal_type": vio.punish_type,
            "object_id": vio.object_id,
            "punish_key": vio.punish_id,
            "appeal_uri": "",
            "extra": "",
        }
        if selected_code is not None:
            body["AppealReasons"] = [str(selected_code)]
            body["reason"] = json.dumps(
                {"type": 2, "options": [selected_code], "description": appeal_text},
                separators=(",", ":"),
                ensure_ascii=False,
            )
        elif appeal_text:
            body["reason"] = json.dumps(
                {"file_uri": "", "description": appeal_text},
                separators=(",", ":"),
                ensure_ascii=False,
            )
        if appeal_text:
            body["AppealDescription"] = appeal_text

        # Attempt 1: New Violation Platform V2 (/api/violation/v1/commit_appeal)
        api_err = ""
        try:
            r1 = self.sess.post(
                f"{self.idc_gateway}/api/violation/v1/commit_appeal",
                params=self.mobile_params,
                json=body,
            )
            if r1.status_code == 200:
                j1 = r1.json()
                sc = j1.get("status_code", (j1.get("BaseResp") or {}).get("StatusCode", -1))
                if sc == 0:
                    time.sleep(1.5)
                    self.scanner.enrich_violation_detail(vio, uid)
                    if vio.status_code in (4, 6) or not vio.can_appeal:
                        return True, (
                            f"[OK] Апелляция принята через commit_appeal: punish_id={vio.punish_id} -> {vio.status_label} (AppealId={vio.appeal_id})"
                        )
                api_err = f"commit_appeal code={sc}"
        except Exception as e:
            api_err = str(e)

        # Attempt 2: Legacy mobile endpoint (/aweme/v2/appeal/commit/)
        try:
            legacy_params = {
                **self.mobile_params,
                "appeal_type": str(vio.punish_type),
                "object_id": vio.object_id,
                "punish_key": vio.punish_id,
                "appeal_uri": "",
                "extra": "",
            }
            if "reason" in body:
                legacy_params["reason"] = body["reason"]
            r2 = self.sess.post(f"{self.idc_gateway}/aweme/v2/appeal/commit/", params=legacy_params)
            if r2.status_code == 200 and r2.json().get("status_code", -1) == 0:
                time.sleep(1.5)
                self.scanner.enrich_violation_detail(vio, uid)
                if vio.status_code in (4, 6) or not vio.can_appeal:
                    return True, (
                        f"[OK] Апелляция принята через aweme/v2/appeal/commit: punish_id={vio.punish_id} -> {vio.status_label}"
                    )
        except Exception:
            pass

        # Attempt 3: Signed BytedanceWebview /tns-api/appeal/post-commit via Playwright Chrome or Camoufox
        ok_web, web_msg = self._submit_notice_via_browser_tns(vio, selected_code, appeal_text)
        if ok_web:
            time.sleep(1.5)
            self.scanner.enrich_violation_detail(vio, uid)
            return True, (
                f"[OK] Апелляция принята через WebView tns-api: punish_id={vio.punish_id} -> {vio.status_label} ({web_msg})"
            )

        return False, f"[FAIL] Не удалось подать апелляцию punish_id={vio.punish_id}: {api_err} | {web_msg}"

    def _browser_cookie_list(self) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        for k, v in self.cookies.items():
            if not v:
                continue
            for dom in (".tiktok.com", ".tiktokv.com", ".tiktokv.eu", ".tiktokw.eu"):
                out.append({"name": str(k), "value": str(v), "domain": dom, "path": "/"})
        return out

    def _submit_notice_via_browser_tns(
        self, vio: NoticeViolation, selected_code: Any, appeal_text: str
    ) -> Tuple[bool, str]:
        from playwright.sync_api import sync_playwright

        proxy_url = normalize_proxy_url(self.spec.proxy)
        pw_proxy = playwright_proxy_dict(proxy_url, for_chromium=True)
        exe = find_chrome_executable()

        target_url = vio.web_schema_url or vio.schema_url
        if not target_url or not target_url.startswith("http"):
            target_url = (
                f"{WWW_BASE}/violation-appeal?enter_from=1&hide_nav_bar=1&is_new_vio_platform=1"
                f"&object_id={vio.object_id}&object_type={vio.object_type}"
                f"&punish_key={vio.punish_id}&punish_type={vio.punish_type}"
            )

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
                ctx = browser.new_context(
                    viewport={"width": 430, "height": 932},
                    user_agent=ANDROID_WEBVIEW_UA,
                )
                ctx.add_cookies(self._browser_cookie_list())
                wpage = ctx.new_page()

                common_qs = "aid=1988&app_language=en&app_name=tiktok_web&channel=tiktok_web&device_platform=web_mobile&os=android"

                def _on_resp(resp: Any) -> None:
                    nonlocal common_qs
                    if "/tns-api/appeal/violation-detail" in resp.url:
                        raw_qs = parse_qs(urlparse(resp.url).query, keep_blank_values=True)
                        filtered = {
                            k: v[0]
                            for k, v in raw_qs.items()
                            if k not in ("object_id", "object_type", "punish_key", "msToken", "X-Bogus", "X-Gnarly")
                        }
                        if filtered:
                            common_qs = urlencode(filtered)

                wpage.on("response", _on_resp)
                wpage.goto(target_url, wait_until="domcontentloaded", timeout=40000)
                wpage.wait_for_timeout(4500)

                low_txt = wpage.inner_text("body").lower()
                if "appeal submitted" in low_txt or "request received" in low_txt or "appeal approved" in low_txt:
                    return True, "already_submitted"

                payload: Dict[str, Any] = {
                    "object_id": vio.object_id,
                    "appeal_type": vio.punish_type,
                    "punish_key": vio.punish_id,
                    "punish_id": vio.punish_id,
                    "appeal_uri": "",
                    "extra": "",
                }
                if selected_code is not None:
                    payload["reason"] = json.dumps(
                        {"type": 2, "options": [selected_code], "description": appeal_text},
                        separators=(",", ":"),
                        ensure_ascii=False,
                    )
                elif appeal_text:
                    payload["reason"] = json.dumps(
                        {"file_uri": "", "description": appeal_text},
                        separators=(",", ":"),
                        ensure_ascii=False,
                    )
                else:
                    payload["reason"] = ""

                last_resp: Any = {}
                for _ in range(3):
                    last_resp = wpage.evaluate(
                        """async ({payload, qs}) => {
                            const r = await fetch(`/tns-api/appeal/post-commit?${qs}`, {
                                method: 'POST',
                                headers: {'content-type': 'application/json'},
                                body: JSON.stringify(payload),
                                credentials: 'include'
                            });
                            return await r.json().catch(() => ({status_code: -1}));
                        }""",
                        {"payload": payload, "qs": common_qs},
                    )
                    if isinstance(last_resp, dict) and last_resp.get("status_code") == 0:
                        return True, "status_code=0"
                    wpage.wait_for_timeout(1500)
                return False, f"tns_resp={last_resp}"
            finally:
                browser.close()

    def submit_post_appeal(self, pp: PostPenalty) -> Tuple[bool, str]:
        """Submit Studio V2 or V1 appeal for an individual FYP-restricted post."""
        if pp.v2_can_appeal and pp.v2_appeal_details is not None:
            try:
                r = self.sess.post(
                    f"{WWW_BASE}/api/moderation/penalties/submitappeal",
                    params={"aid": "1988"},
                    json={"appealDetails": pp.v2_appeal_details, "itemId": pp.item_id},
                )
                if r.status_code == 200 and (r.json().get("BaseResp") or {}).get("StatusCode") == 0:
                    return True, f"[OK] Studio V2 апелляция отправлена для поста {pp.item_id}"
            except Exception:
                pass

        details = [
            {
                "issuer": p.get("issuer"),
                "penalty_id": (p.get("penalty_id") or {}).get("id")
                if isinstance(p.get("penalty_id"), dict)
                else p.get("penalty_id"),
            }
            for p in pp.penalties
            if p.get("penalty_id")
        ]
        params = {
            "aid": "1988",
            "app_name": "tiktok_creator_center",
            "vid": pp.item_id,
            "appeal_details": json.dumps(details, separators=(",", ":")),
        }
        try:
            r1 = self.sess.post(f"{WWW_BASE}/mod/v1/submitAppeals", params=params)
            if r1.status_code == 200 and r1.json().get("status_code") == 0:
                time.sleep(1.5)
                self.scanner._check_single_post_penalty(pp)
                return True, f"[OK] Studio V1 апелляция отправлена для поста {pp.item_id} -> {pp.appeal_status_label}"
        except Exception:
            pass

        ok_browser, msg_browser = self._submit_post_via_browser_studio(pp, params)
        if ok_browser:
            return True, f"[OK] Studio браузерная апелляция отправлена для поста {pp.item_id} ({msg_browser})"
        return False, f"[FAIL] Не удалось подать апелляцию на пост {pp.item_id}: {msg_browser}"

    def _submit_post_via_browser_studio(
        self, pp: PostPenalty, v1_params: Dict[str, str]
    ) -> Tuple[bool, str]:
        from playwright.sync_api import sync_playwright

        proxy_url = normalize_proxy_url(self.spec.proxy)
        pw_proxy = playwright_proxy_dict(proxy_url, for_chromium=True)
        exe = find_chrome_executable()

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
                ctx = browser.new_context(user_agent=DESKTOP_CHROME_UA, viewport={"width": 1440, "height": 900})
                ctx.add_cookies(self._browser_cookie_list())
                page = ctx.new_page()
                page.goto(
                    f"{WWW_BASE}/tiktokstudio/analytics/{pp.item_id}",
                    wait_until="domcontentloaded",
                    timeout=45000,
                )
                page.wait_for_timeout(5000)

                res_json = page.evaluate(
                    """async (params) => {
                        const qs = new URLSearchParams(params).toString();
                        const r = await fetch('https://www.tiktok.com/mod/v1/submitAppeals?' + qs, {
                            method: 'POST',
                            credentials: 'include'
                        });
                        return await r.json().catch(() => ({status_code: -1}));
                    }""",
                    v1_params,
                )
                if isinstance(res_json, dict) and res_json.get("status_code") == 0:
                    return True, "status_code=0"
                return False, str(res_json)[:200]
            finally:
                browser.close()

    def set_post_private(self, item_id: str) -> Tuple[bool, str]:
        """Switch a rejected FYP-ineligible post to Private (visibility_type=2) so it stops hurting account status."""
        try:
            r = self.sess.post(
                f"{WWW_BASE}/tiktokstudio/api/web/item/visibility",
                params={"aid": "1988"},
                json={"item_id": item_id, "visibility_type": 2},
            )
            if r.status_code == 200 and r.json().get("statusCode", r.json().get("status_code", -1)) == 0:
                return True, f"[CLEANUP] Отклонённый пост {item_id} переведён в Private"
            return False, f"[CLEANUP-WARN] Ответ смены приватности {item_id}: {r.text[:160]}"
        except Exception as e:
            return False, f"[CLEANUP-ERR] {item_id}: {e}"
