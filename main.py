#!/usr/bin/env python3
"""CLI entrypoint for inspecting and appealing TikTok FYP / Account eligibility restrictions."""

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
import random
import sys
import time
from typing import List

from appealer import AppealEngine
from config import PUNISH_TYPE_NAMES, WATCH_POLL_SECONDS
from models import AccountAuditResult, AccountSpec
from scanner import AccountScanner
from session_mgr import SessionManager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _fmt_ts(ts: int) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def load_accounts(target: str, is_file: bool, default_proxy: str | None) -> List[AccountSpec]:
    specs: List[AccountSpec] = []
    if is_file:
        with open(target, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                specs.append(AccountSpec.parse(s, default_proxy=default_proxy))
    else:
        specs.append(AccountSpec.parse(target, default_proxy=default_proxy))
    return specs


def print_audit_report(audit: AccountAuditResult) -> None:
    print(f"\n{'=' * 72}")
    print(
        f"Аккаунт: @{audit.username} (UID: {audit.uid}) | "
        f"RegCountry: {audit.reg_country or '?'} | CurrentRegion: {audit.current_region or '?'} | "
        f"IDC: {audit.idc_gateway}"
    )
    print(f"{'=' * 72}")

    if audit.region_warning_present:
        print(
            "  [!] ВНИМАНИЕ: В системных уведах висит 'Update your account region' — "
            "на аккаунт уже заходили не с его родного гео прокси!"
        )
    if audit.recent_device_logins:
        print("  [*] Последние входы в системных уведах:")
        for lg in audit.recent_device_logins[:3]:
            print(f"      - {lg}")

    print(f"\n  [1] Ограничения из вкладки Уведомлений (Account updates / group=47): {len(audit.notice_violations)}")
    if not audit.notice_violations:
        print("      Чисто — активных карточек нарушений в системных уведах не найдено.")
    for v in audit.notice_violations:
        ptype_name = PUNISH_TYPE_NAMES.get(v.punish_type, f"Type({v.punish_type})")
        print(f"      • [{_fmt_ts(v.create_time)}] {v.title}")
        print(f"        punish_id={v.punish_id} | object_type={v.object_type} | {ptype_name}")
        print(
            f"        Статус: {v.status_label} | CanAppeal={v.can_appeal} | "
            f"Source={v.punish_source or '-'} | До={_fmt_ts(v.punish_end_time)}"
        )
        if v.appeal_id and v.appeal_id != "0":
            print(f"        AppealId={v.appeal_id}")
        if v.reason_title:
            print(f"        Причина TNS: {v.reason_title}")

    flagged_posts = [p for p in audit.post_penalties if p.appeal_status != 2 or p.v2_can_appeal]
    print(
        f"\n  [2] Посты в TikTok Studio: всего {audit.total_posts}, "
        f"с ограничениями FYP / модерации: {len(flagged_posts)}"
    )
    for p in audit.post_penalties[:10]:
        flag_tag = (
            f" [{p.appeal_status_label} | {','.join(p.reason_labels) or 'V2'}]"
            if (p.appeal_status != 2 or p.v2_can_appeal)
            else " [OK]"
        )
        short_desc = (p.desc[:42] + "...") if len(p.desc) > 45 else (p.desc or "<без описания>")
        print(
            f"      • {p.item_id} | {_fmt_ts(p.create_time)} | views={p.play_count:<5d} | {short_desc}{flag_tag}"
        )


def run_once_for_account(
    spec: AccountSpec,
    session_mgr: SessionManager,
    do_appeal: bool,
    dry_run: bool,
    hide_rejected: bool,
    appeal_text: str,
    as_json: bool,
) -> dict:
    sess, cookies, user_meta, gw = session_mgr.get_authenticated_session(spec)
    scanner = AccountScanner(sess, gw)
    audit = scanner.run_full_audit(spec.username, user_meta)

    result_payload = {"audit": asdict(audit)}
    if not as_json:
        print_audit_report(audit)

    if do_appeal:
        engine = AppealEngine(sess, cookies, gw, session_mgr, spec)
        summary = engine.process_audit(
            audit,
            dry_run=dry_run,
            hide_rejected=hide_rejected,
            appeal_text=appeal_text,
        )
        result_payload["appeal_summary"] = summary
        if not as_json:
            print("\n  [3] Результат снятия ограничений:")
            if not summary["details"]:
                print("      Нет ограничений со статусом CanAppeal=True / CAN_SUBMIT (ничего подавать не нужно).")
            for line in summary["details"]:
                print(f"      {line}")

    return result_payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TikTok Account Updates & Studio FYP Restriction Inspector / Appealer"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_common_args(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "target",
            help="Строка 'login|pass|email|totp[|proxy]' или путь к файлу со списком (с флагом --file)",
        )
        p.add_argument("--file", action="store_true", help="Читать список аккаунтов построчно из файла target")
        p.add_argument("--proxy", default=None, help="Прокси по умолчанию (http://user:pass@ip:port или ip:port:user:pass)")
        p.add_argument(
            "--allow-direct",
            action="store_true",
            help="Разрешить вход без прокси (ТОЛЬКО для тестового расходника!)",
        )
        p.add_argument("--json", action="store_true", help="Вывести результат строго в JSON")

    p_check = sub.add_parser("check", help="Проверить системные уведы и посты без отправки апелляций")
    add_common_args(p_check)

    p_appeal = sub.add_parser("appeal", help="Найти и подать апелляции на ограничения аккаунта и постов")
    add_common_args(p_appeal)
    p_appeal.add_argument("--dry-run", action="store_true", help="Показать доступные апелляции без отправки POST")
    p_appeal.add_argument(
        "--hide-rejected",
        action="store_true",
        help="Переводить посты с отклонённой апелляцией (FAILED) в Private, чтобы не ловить бан аккаунта 2048",
    )
    p_appeal.add_argument("--reason-text", default="", help="Опциональный текст пояснения для апелляции")

    p_watch = sub.add_parser(
        "watch",
        help="Циклически проверять аккаунт(ы) после залива по сохранённым кукам и сразу снимать прилетающие флаги",
    )
    add_common_args(p_watch)
    p_watch.add_argument("--cycles", type=int, default=12, help="Количество циклов проверки (0 = бесконечно)")
    p_watch.add_argument("--interval-min", type=float, default=WATCH_POLL_SECONDS[0], help="Мин. пауза между циклами (сек)")
    p_watch.add_argument("--interval-max", type=float, default=WATCH_POLL_SECONDS[1], help="Макс. пауза между циклами (сек)")
    p_watch.add_argument("--hide-rejected", action="store_true", help="Скрывать отклонённые посты в Private")
    p_watch.add_argument("--reason-text", default="", help="Опциональный текст пояснения")

    args = parser.parse_args()
    specs = load_accounts(args.target, args.file, args.proxy)
    session_mgr = SessionManager(BASE_DIR, allow_direct=args.allow_direct)

    if args.cmd in ("check", "appeal"):
        outputs = []
        had_err = False
        for spec in specs:
            try:
                out = run_once_for_account(
                    spec=spec,
                    session_mgr=session_mgr,
                    do_appeal=(args.cmd == "appeal"),
                    dry_run=getattr(args, "dry_run", False),
                    hide_rejected=getattr(args, "hide_rejected", False),
                    appeal_text=getattr(args, "reason_text", ""),
                    as_json=args.json,
                )
                outputs.append(out)
            except Exception as exc:
                had_err = True
                print(f"[ERR] {exc}", file=sys.stderr)
        if args.json and outputs:
            print(json.dumps(outputs if len(outputs) > 1 else outputs[0], indent=2, ensure_ascii=False))
        return 1 if had_err and not outputs else 0

    if args.cmd == "watch":
        cycle = 0
        while args.cycles == 0 or cycle < args.cycles:
            cycle += 1
            if not args.json:
                print(f"\n>>> Цикл мониторинга #{cycle} ({datetime.now().strftime('%H:%M:%S')}) <<<")
            for spec in specs:
                try:
                    out = run_once_for_account(
                        spec=spec,
                        session_mgr=session_mgr,
                        do_appeal=True,
                        dry_run=False,
                        hide_rejected=args.hide_rejected,
                        appeal_text=args.reason_text,
                        as_json=args.json,
                    )
                    if args.json:
                        print(json.dumps({"cycle": cycle, **out}, ensure_ascii=False), flush=True)
                except Exception as exc:
                    print(f"[ERR] @{spec.username}: {exc}", file=sys.stderr)
            if args.cycles == 0 or cycle < args.cycles:
                wait_s = random.uniform(args.interval_min, args.interval_max)
                if not args.json:
                    print(f"\n[~] Следующая проверка через {wait_s:.0f}с (лёгкий HTTP-опрос по кукам без повторного входа)...")
                time.sleep(wait_s)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
