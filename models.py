"""Data structures for accounts, session state, notices, and moderation penalties."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

_EMAIL_TOKEN_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _clean_markdown_links(raw: str) -> str:
    s = html.unescape(raw.strip())
    s = re.sub(r"\[\+\+([^\]]+?)\+\+\]\([^)]+\)", r"\1", s)
    s = re.sub(r"\[([^\]]+)\]\((?:mailto:|https?://)[^)]+\)", r"\1", s)
    s = re.sub(r"\+\+(.+?)\+\+", r"\1", s)
    return s


@dataclass
class AccountSpec:
    username: str
    password: str
    email: str = ""
    totp_secret: str = ""
    proxy: Optional[str] = None
    mail_login: str = ""
    mail_password: str = ""
    recovery_email: str = ""
    recovery_password: str = ""
    mail_totp: str = ""
    use_outlook_hub: bool = False

    @classmethod
    def parse(cls, raw_line: str, default_proxy: Optional[str] = None) -> "AccountSpec":
        """
        Parse supported account formats:
          1) Pipe format: `username|password|email|totp_secret[|proxy]`
          2) Outlook-Hub colon format (5/7/8 fields):
             `login:pass:outlook_email:outlook_pass:rec_email:rec_pass:hotmail_2fa`
        """
        cleaned = _clean_markdown_links(raw_line)
        if "|" in cleaned:
            parts = [p.strip() for p in cleaned.split("|")]
            if len(parts) < 2 or not parts[0]:
                raise ValueError(f"Expected 'username|password[|email|totp|proxy]', got: {raw_line!r}")
            username = parts[0].lstrip("@")
            password = parts[1]
            email = parts[2] if len(parts) > 2 else ""
            totp = parts[3].replace(" ", "") if len(parts) > 3 else ""
            proxy = parts[4] if len(parts) > 4 and parts[4] else default_proxy
            return cls(
                username=username,
                password=password,
                email=email,
                totp_secret=totp,
                proxy=proxy,
            )

        raw_parts = [p.strip() for p in cleaned.split(":") if p.strip()]
        email_idxs = [i for i, tok in enumerate(raw_parts) if _EMAIL_TOKEN_RE.match(tok)]
        if email_idxs and email_idxs[0] == 2 and len(raw_parts) >= 5:
            tt_u = raw_parts[0].lstrip("@")
            tt_p = raw_parts[1]
            primary_email = raw_parts[2].lower()
            mail_login = primary_email
            mail_pw = ""
            rec_email = ""
            rec_pw = ""
            hotmail_2fa = ""

            if len(email_idxs) >= 3 and email_idxs[1] == 3 and email_idxs[2] == 5:
                mail_login = raw_parts[3]
                mail_pw = raw_parts[4]
                rec_email = raw_parts[5].lower()
                rec_pw = raw_parts[6] if len(raw_parts) > 6 else ""
                hotmail_2fa = raw_parts[7] if len(raw_parts) > 7 else ""
            elif len(email_idxs) >= 2 and email_idxs[1] == 5:
                mail_login = raw_parts[3]
                mail_pw = raw_parts[4]
                rec_email = raw_parts[5].lower()
                rec_pw = raw_parts[6] if len(raw_parts) > 6 else ""
                hotmail_2fa = raw_parts[7] if len(raw_parts) > 7 else ""
            elif len(email_idxs) >= 2 and email_idxs[1] == 4:
                mail_pw = raw_parts[3]
                rec_email = raw_parts[4].lower()
                rec_pw = raw_parts[5] if len(raw_parts) > 5 else ""
                hotmail_2fa = raw_parts[6] if len(raw_parts) > 6 else ""
            else:
                mail_pw = raw_parts[3] if len(raw_parts) > 3 else ""
                hotmail_2fa = raw_parts[4] if len(raw_parts) > 4 else ""

            return cls(
                username=tt_u or primary_email.split("@")[0],
                password=tt_p,
                email=primary_email,
                totp_secret="",
                proxy=default_proxy,
                mail_login=mail_login,
                mail_password=mail_pw,
                recovery_email=rec_email,
                recovery_password=rec_pw,
                mail_totp=hotmail_2fa,
                use_outlook_hub=True,
            )

        if len(raw_parts) == 1 and raw_parts[0]:
            # Existing session username shorthand (e.g. `python3 main.py check my_account`)
            return cls(username=raw_parts[0].lstrip("@"), password="", proxy=default_proxy)

        raise ValueError(
            f"Expected 'username|password|email|totp[|proxy]' or 'login:pass:outlook:mail_pass:rec:rec_pass:2fa', got: {raw_line!r}"
        )


@dataclass
class NoticeViolation:
    nid: str
    group: int
    create_time: int
    title: str
    content: str
    object_id: str
    object_type: str
    punish_id: str
    punish_type: int
    schema_url: str = ""
    web_schema_url: str = ""
    can_appeal: bool = False
    status_code: int = 0
    status_label: str = "Unknown"
    appeal_id: str = ""
    punish_source: str = ""
    punish_end_time: int = 0
    reason_title: str = ""


@dataclass
class PostPenalty:
    item_id: str
    create_time: int
    desc: str
    play_count: int
    appeal_status: int = 2
    appeal_status_label: str = "NO_PENALTY"
    penalties: List[Dict[str, Any]] = field(default_factory=list)
    reason_labels: List[str] = field(default_factory=list)
    v2_can_appeal: bool = False
    v2_appeal_details: Any = None


@dataclass
class AccountAuditResult:
    username: str
    uid: str = ""
    reg_country: str = ""
    current_region: str = ""
    idc_gateway: str = ""
    region_warning_present: bool = False
    recent_device_logins: List[str] = field(default_factory=list)
    notice_violations: List[NoticeViolation] = field(default_factory=list)
    post_penalties: List[PostPenalty] = field(default_factory=list)
    total_posts: int = 0
