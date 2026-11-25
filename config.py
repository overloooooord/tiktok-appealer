"""Configuration, TikTok IDC gateway mapping, and moderation protocol enums."""

from typing import Dict, Tuple

# Regional mobile API gateways mapped from store-idc / tt-target-idc cookies.
# Cookie-authenticated GET/POST requests to /aweme/v1/notice/* and /api/violation/v1/*
# work directly against the account's home cluster without mobile X-Gorgon/X-Argus headers.
IDC_GATEWAY_MAP: Dict[str, str] = {
    "no1a": "https://api16-normal-no1a.tiktokv.eu",
    "useast2b": "https://api16-normal-no1a.tiktokv.eu",
    "us-eastred": "https://api16-normal-no1a.tiktokv.eu",
    "euttp": "https://api16-normal-no1a.tiktokv.eu",
    "useast1a": "https://api16-normal-c-useast1a.tiktokv.com",
    "useast2a": "https://api16-normal-c-useast2a.tiktokv.com",
    "useast5": "https://api16-normal-us.tiktokv.us",
    "maliva": "https://api16-normal-c-useast1a.tiktokv.com",
    "alisg": "https://api16-normal-c-alisg.tiktokv.com",
    "sg1": "https://api16-normal-c-alisg.tiktokv.com",
}

FALLBACK_GATEWAYS = [
    "https://api16-normal-no1a.tiktokv.eu",
    "https://api16-normal-c-useast1a.tiktokv.com",
    "https://api16-normal-c-useast2a.tiktokv.com",
    "https://api16-normal-c-alisg.tiktokv.com",
]

WWW_BASE = "https://www.tiktok.com"

# Notice filter_type=33 corresponds to "Account updates" in System notifications;
# group=47 is the primary official violation/account-update channel; group=46 is announcements/region prompts.
CORE_SYSTEM_NOTICE_GROUPS = [47, 46, 84, 210, 214, 69, 13, 226, 227, 228, 229, 661, 702]

# /api/violation/v1/get_violation_detail Status enum (from communitysafety module 9057)
VIOLATION_V1_STATUS: Dict[int, str] = {
    1: "Effecting (Active / Appealable)",
    2: "ViolationExpired",
    3: "ViolationRecovered",
    4: "Appealing (Under Review)",
    5: "AppealExpired",
    6: "AppealSuccess (Restored)",
    7: "AppealFailed (Rejected)",
    8: "AppealInterrupted",
}

# /tns-api/appeal/violation-detail appeal_status enum (from communitysafety module 96147)
TNS_APPEAL_STATUS: Dict[int, str] = {
    0: "CAN_NOT_SUBMIT",
    1: "CAN_SUBMIT",
    2: "REVIEWING",
    3: "SUCCEEDED",
    4: "FAILED",
    5: "EXPIRED",
    6: "TIMEOUT",
    7: "PENDING",
    8: "PUNISH_FINISHED",
}

# TikTok Studio /mod/v1/getPenaltyDetails/ appeal_status enum (from creator-center-web module 61954)
STUDIO_APPEAL_STATUS: Dict[int, str] = {
    0: "CAN_SUBMIT",
    1: "CANNOT_SUBMIT",
    2: "NO_PENALTY",
    3: "REVIEWING",
    4: "SUCCEEDED",
    5: "FAILED",
    6: "TIMEOUT",
}

STUDIO_REASON_CODES: Dict[int, str] = {
    0: "OTHER",
    1: "COMMUNITY_GUIDELINES",
    2: "TOBACCO",
    3: "VIOLENT",
    4: "DANGEROUS",
    5: "OVERLY_SEXUALIZED",
    6: "SPAM",
    7: "UNORIGINAL",
    8: "MINOR_SAFETY",
    9: "UNORIGINAL_NR",
    10: "REPRODUCED_ACCOUNT",
    11: "CLICKBAIT_NFF",
}

PUNISH_TYPE_NAMES: Dict[int, str] = {
    1030: "VideoNotRecommend (FYP Ineligible - Video)",
    1039: "PhotoNotRecommend (FYP Ineligible - Photo/Carousel)",
    1052: "VideoUMNotRecommend (Unoriginal/Low-Quality FYP Ineligible)",
    2004: "AccountOriginal (Unoriginal Account Restriction)",
    2048: "AccountIneligibleForRecommendation (Account FYP Restriction)",
}

# Anti-shadowban pacing rules (seconds)
APPEAL_STAGGER_SECONDS: Tuple[float, float] = (8.5, 17.5)
WATCH_POLL_SECONDS: Tuple[float, float] = (95.0, 165.0)
