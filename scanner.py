"""Pure-HTTP (curl_cffi / httpx) scanner for Mobile Account Updates (group=47/661/filter=33) and Studio post penalties."""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, List, Set, Tuple

from config import (
    CORE_SYSTEM_NOTICE_GROUPS,
    STUDIO_APPEAL_STATUS,
    STUDIO_REASON_CODES,
    VIOLATION_V1_STATUS,
    WWW_BASE,
)
from models import AccountAuditResult, NoticeViolation, PostPenalty


def _extract_query_from_schema(schema_url: str) -> Tuple[str, Dict[str, str]]:
    """Unwrap aweme://webview?url=... or direct https://... URL and return (inner_url, query_dict)."""
    if not schema_url:
        return "", {}
    raw = schema_url.strip()
    if raw.startswith(("aweme://", "sslocal://")):
        outer_q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(raw).query))
        inner = outer_q.get("url", "")
        if inner:
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(inner).query))
            return inner, q
        return raw, outer_q
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(raw).query))
    return raw, q


class AccountScanner:
    def __init__(self, sess: Any, idc_gateway: str):
        self.sess = sess
        self.idc_gateway = idc_gateway.rstrip("/")
        self.mobile_base_params = {
            "aid": "1233",
            "app_name": "musical_ly",
            "version_code": "37.1.0",
            "build_number": "371014",
            "device_platform": "iphone",
            "os_version": "17.5.1",
            "app_language": "en",
            "language": "en",
        }

    def run_full_audit(self, username: str, user_meta: Dict[str, Any]) -> AccountAuditResult:
        uid = str(user_meta.get("userId") or "")
        reg_info = (
            user_meta.get("userBaseInfo", {})
            .get("UserProfile", {})
            .get("UserBase", {})
            .get("Region", {})
        )
        audit = AccountAuditResult(
            username=username,
            uid=uid,
            reg_country=reg_info.get("RegistrationCountry", ""),
            current_region=reg_info.get("Region", ""),
            idc_gateway=self.idc_gateway,
        )

        self._scan_mobile_notices(audit)
        self._scan_studio_posts(audit)
        return audit

    def _discover_notice_groups(self) -> List[int]:
        groups: Set[int] = set(CORE_SYSTEM_NOTICE_GROUPS)
        try:
            resp = self.sess.get(
                f"{self.idc_gateway}/aweme/v1/notice/count/",
                params={**self.mobile_base_params, "source": "1"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for flt in data.get("groups_in_filters") or []:
                    if flt.get("filter_type") in (33, 41, 6, 14):
                        for g in flt.get("groups") or []:
                            groups.add(int(g))
        except Exception:
            pass
        return sorted(groups)

    def _scan_mobile_notices(self, audit: AccountAuditResult) -> None:
        groups = self._discover_notice_groups()
        raw_items: List[Tuple[int, Dict[str, Any]]] = []

        for i in range(0, len(groups), 20):
            chunk = groups[i : i + 20]
            group_list = json.dumps(
                [{"count": 25, "group": g, "is_mark_read": 0, "max_time": 0, "min_time": 0} for g in chunk],
                separators=(",", ":"),
            )
            try:
                resp = self.sess.get(
                    f"{self.idc_gateway}/aweme/v1/notice/multi/",
                    params={**self.mobile_base_params, "group_list": group_list},
                )
                if resp.status_code != 200:
                    continue
                payload = resp.json()
                for nl in payload.get("notice_lists") or []:
                    g = int(nl.get("group") or 0)
                    for item in nl.get("notice_list") or []:
                        if isinstance(item, dict):
                            raw_items.append((g, item))
            except Exception:
                continue

        raw_items.sort(
            key=lambda pair: int(
                pair[1].get("create_time")
                or (pair[1].get("template_notice") or {}).get("create_time")
                or 0
            ),
            reverse=True,
        )

        seen_punish_ids: Set[str] = set()
        seen_objects: Set[str] = set()
        for g, item in raw_items:
            self._process_notice_item(audit, g, item, seen_punish_ids, seen_objects)

    def _process_notice_item(
        self,
        audit: AccountAuditResult,
        group: int,
        item: Dict[str, Any],
        seen_punish_ids: Set[str],
        seen_objects: Set[str],
    ) -> None:
        nid = str(item.get("nid_str") or item.get("nid") or "")
        ctime = int(
            item.get("create_time")
            or (item.get("template_notice") or {}).get("create_time")
            or 0
        )
        tn = item.get("template_notice") or {}
        txt = item.get("text") or {}
        ann = item.get("announcement") or {}
        notice_body = tn.get("notice") or {}

        title = str(
            (notice_body.get("title") or {}).get("title")
            or txt.get("title")
            or ann.get("title")
            or ""
        )
        content = str(
            notice_body.get("content")
            or txt.get("content")
            or ann.get("content")
            or ""
        )

        low_title = title.lower()
        if "update your account region" in low_title:
            audit.region_warning_present = True

        if "logged in from a new device" in low_title and content:
            if content not in audit.recent_device_logins and len(audit.recent_device_logins) < 5:
                audit.recent_device_logins.append(content)

        raw_schema = str(
            tn.get("schema_url")
            or notice_body.get("right_schema_url")
            or txt.get("schema_url")
            or ann.get("schema_url")
            or ""
        )
        web_schema = ""
        msg_extra_raw = tn.get("message_extra") or ""
        if msg_extra_raw:
            try:
                me = json.loads(msg_extra_raw)
                be_raw = me.get("business_extra") or ""
                if be_raw:
                    be = json.loads(be_raw) if isinstance(be_raw, str) else be_raw
                    web_schema = str(be.get("web_schema_url") or "")
            except Exception:
                pass

        falcon_url, q_falcon = _extract_query_from_schema(raw_schema)
        _, q_web = _extract_query_from_schema(web_schema)
        merged_q = {**q_web, **q_falcon}

        punish_id = merged_q.get("punish_id") or merged_q.get("punish_key") or ""
        object_id = merged_q.get("object_id") or ""
        punish_type_str = merged_q.get("punish_type") or "0"
        object_type = merged_q.get("object_type") or ""

        if not punish_id or not object_id:
            return
        if punish_id in seen_punish_ids:
            return
        seen_punish_ids.add(punish_id)

        eff_obj_type = object_type or ("4" if object_id == audit.uid else "1")
        obj_dedup = f"{eff_obj_type}:{object_id}"
        if obj_dedup in seen_objects:
            return
        seen_objects.add(obj_dedup)

        try:
            punish_type = int(punish_type_str)
        except ValueError:
            punish_type = 0

        vio = NoticeViolation(
            nid=nid,
            group=group,
            create_time=ctime,
            title=title or "Moderation Notice",
            content=content,
            object_id=object_id,
            object_type=eff_obj_type,
            punish_id=punish_id,
            punish_type=punish_type,
            schema_url=falcon_url or raw_schema,
            web_schema_url=web_schema,
        )
        if "eligible" in low_title and "ineligible" not in low_title:
            vio.can_appeal = False
            vio.status_code = 6
            vio.status_label = VIOLATION_V1_STATUS[6]
        else:
            self.enrich_violation_detail(vio, audit.uid)
        audit.notice_violations.append(vio)

    def enrich_violation_detail(self, vio: NoticeViolation, uid: str) -> None:
        """Query /api/violation/v1/get_violation_detail for exact appealability and status."""
        params = {
            **self.mobile_base_params,
            "ViolationId": vio.punish_id,
            "UserId": uid,
            "ObjectId": vio.object_id,
            "ViolationType": str(vio.punish_type),
            "enter_from": "1",
        }
        try:
            resp = self.sess.get(f"{self.idc_gateway}/api/violation/v1/get_violation_detail", params=params)
            if resp.status_code != 200:
                return
            data = resp.json()
            if (data.get("BaseResp") or {}).get("StatusCode", -1) != 0:
                return
            vio.can_appeal = bool(data.get("CanAppeal", False))
            vinfo = data.get("ViolationInfo") or {}
            status_int = int(vinfo.get("Status") or 0)
            vio.status_code = status_int
            vio.status_label = VIOLATION_V1_STATUS.get(status_int, f"Status({status_int})")
            vio.appeal_id = str(vinfo.get("AppealId") or "")
            vio.punish_source = str(vinfo.get("PunishFromSource") or "")
            vio.punish_end_time = int(vinfo.get("PunishEndTime") or 0)
            reasons = data.get("ViolationReasons") or []
            if reasons and isinstance(reasons[0], dict):
                vio.reason_title = str(reasons[0].get("Title") or "")
        except Exception:
            pass

    def _scan_studio_posts(self, audit: AccountAuditResult, max_posts: int = 50) -> None:
        body = {
            "cursor": 0,
            "size": max_posts,
            "query": {
                "sort_orders": [{"field_name": "post_time", "order": 2}],
                "conditions": [],
                "is_recent_posts": False,
            },
        }
        try:
            resp = self.sess.post(
                f"{WWW_BASE}/tiktok/creator/manage/item_list/v1/",
                params={"aid": "1988", "app_name": "tiktok_creator_center", "device_platform": "web_pc"},
                json=body,
            )
            if resp.status_code != 200:
                return
            items = resp.json().get("item_list") or []
        except Exception:
            return

        audit.total_posts = len(items)
        for it in items:
            vid = str(it.get("item_id") or "")
            if not vid:
                continue
            pp = PostPenalty(
                item_id=vid,
                create_time=int(it.get("create_time") or 0),
                desc=str(it.get("desc") or ""),
                play_count=int(it.get("play_count") or 0),
            )
            self._check_single_post_penalty(pp)
            audit.post_penalties.append(pp)

    def _check_single_post_penalty(self, pp: PostPenalty) -> None:
        try:
            r1 = self.sess.get(
                f"{WWW_BASE}/mod/v1/getPenaltyDetails/",
                params={"aid": "1988", "app_name": "tiktok_creator_center", "vid": pp.item_id},
            )
            if r1.status_code == 200:
                d1 = r1.json()
                st = int(d1.get("appeal_status", 2))
                pp.appeal_status = st
                pp.appeal_status_label = STUDIO_APPEAL_STATUS.get(st, f"UNKNOWN({st})")
                pp.penalties = d1.get("penalties") or []
                codes: List[str] = []
                for pen in pp.penalties:
                    for rc in pen.get("reason_codes") or []:
                        codes.append(STUDIO_REASON_CODES.get(int(rc), f"CODE_{rc}"))
                pp.reason_labels = codes
        except Exception:
            pass

        try:
            r2 = self.sess.get(
                f"{WWW_BASE}/api/moderation/penalties/gettransparencypagecontent",
                params={"aid": "1988", "entityId": pp.item_id, "enterFrom": ""},
            )
            if r2.status_code == 200:
                d2 = r2.json()
                if d2.get("showAppealBtn"):
                    pp.v2_can_appeal = True
                    pp.v2_appeal_details = d2.get("appealDetails")
        except Exception:
            pass
