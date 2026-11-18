#!/usr/bin/env python3
"""
Cyber & Cloud Watch — Automated Cybersecurity and Cloud Outage Watcher.
Zero external dependencies (Python 3.11+ standard library only).

Channels:
- Telegram Bot API (TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)
- Notion Database API (optional: NOTION_TOKEN + NOTION_DATABASE_ID)
- Markdown digest files in digests/
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import html
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config" / "sources.json"
STATE_PATH = ROOT / "state" / "seen.json"
DIGESTS_DIR = ROOT / "digests"
USER_AGENT = "cyber-cloud-watch/1.0 (+https://github.com/Franck2040/cyber-cloud-watch)"
MAX_SEEN_IDS = 2000


@dataclass
class AlertItem:
    uid: str
    source_id: str
    source_name: str
    mode: str
    severity: str
    title: str
    summary: str
    link: str
    published: str
    matched_keywords: list[str]


def fetch_url(url: str, timeout: int = 20) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_with_fallback(source: dict) -> bytes:
    primary = source["url"]
    try:
        return fetch_url(primary)
    except Exception as primary_err:
        fallback = source.get("fallback_url")
        if fallback:
            print(f"[WARN] {source['id']}: primary failed ({primary_err}), trying fallback...")
            return fetch_url(fallback)
        raise


def strip_html(raw: str) -> str:
    text = re.sub(r"<[^>]+>", " ", raw or "")
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def parse_date(raw: str) -> datetime | None:
    if not raw:
        return None
    raw = raw.strip()
    # ISO 8601
    try:
        iso = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
    # RFC 2822 (RSS)
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        pass
    # Simple YYYY-MM-DD
    try:
        dt = datetime.strptime(raw[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def make_uid(source_id: str, key: str) -> str:
    digest = hashlib.sha256(f"{source_id}:{key}".encode("utf-8")).hexdigest()[:16]
    return f"{source_id}-{digest}"


def match_keywords(text: str, keywords: list[str]) -> list[str]:
    low = text.lower()
    found = []
    for kw in keywords:
        if kw.lower() in low:
            found.append(kw)
    return found


def parse_rss_items(
    raw_bytes: bytes,
    source: dict,
    keywords: list[str],
    cutoff: datetime,
) -> list[AlertItem]:
    root = ET.fromstring(raw_bytes)
    items: list[AlertItem] = []

    # Support RSS 2.0 (<item>) and Atom (<entry>)
    rss_nodes = root.findall(".//item")
    atom_ns = "{http://www.w3.org/2005/Atom}"
    atom_nodes = root.findall(f".//{atom_ns}entry")

    if rss_nodes:
        for node in rss_nodes:
            title = strip_html(node.findtext("title") or "")
            link = (node.findtext("link") or "").strip()
            desc = strip_html(node.findtext("description") or "")
            guid = (node.findtext("guid") or link or title).strip()
            pub_raw = node.findtext("pubDate") or node.findtext("{http://purl.org/dc/elements/1.1/}date") or ""
            dt = parse_date(pub_raw)
            if dt and dt < cutoff:
                continue
            matched = match_keywords(f"{title} {desc}", keywords)
            if not source.get("always_include", False) and not matched:
                continue
            sev = source.get("default_severity", "INFO")
            if source["id"] == "certfr-avis" and any(w in f"{title} {desc}".lower() for w in ("critique", "exécution de code arbitraire", "elevation de privilèges", "élévation de privilèges")):
                sev = "CRITIQUE"
            items.append(
                AlertItem(
                    uid=make_uid(source["id"], guid),
                    source_id=source["id"],
                    source_name=source["name"],
                    mode=source["mode"],
                    severity=sev,
                    title=title[:200],
                    summary=desc[:280],
                    link=link,
                    published=(dt.strftime("%Y-%m-%d %H:%M UTC") if dt else pub_raw[:25]),
                    matched_keywords=matched[:5],
                )
            )
    elif atom_nodes:
        for node in atom_nodes:
            title = strip_html(node.findtext(f"{atom_ns}title") or "")
            link_el = node.find(f"{atom_ns}link")
            link = (link_el.attrib.get("href", "") if link_el is not None else "").strip()
            desc = strip_html(
                node.findtext(f"{atom_ns}summary")
                or node.findtext(f"{atom_ns}content")
                or ""
            )
            guid = (node.findtext(f"{atom_ns}id") or link or title).strip()
            pub_raw = node.findtext(f"{atom_ns}updated") or node.findtext(f"{atom_ns}published") or ""
            dt = parse_date(pub_raw)
            if dt and dt < cutoff:
                continue
            matched = match_keywords(f"{title} {desc}", keywords)
            if not source.get("always_include", False) and not matched:
                continue
            items.append(
                AlertItem(
                    uid=make_uid(source["id"], guid),
                    source_id=source["id"],
                    source_name=source["name"],
                    mode=source["mode"],
                    severity=source.get("default_severity", "INFO"),
                    title=title[:200],
                    summary=desc[:280],
                    link=link,
                    published=(dt.strftime("%Y-%m-%d %H:%M UTC") if dt else pub_raw[:25]),
                    matched_keywords=matched[:5],
                )
            )
    return items


def parse_cisa_kev(
    raw_bytes: bytes,
    source: dict,
    keywords: list[str],
    cutoff: datetime,
) -> list[AlertItem]:
    data = json.loads(raw_bytes.decode("utf-8"))
    vulns = data.get("vulnerabilities", [])
    items: list[AlertItem] = []

    for v in vulns:
        date_added = v.get("dateAdded", "")
        dt = parse_date(date_added)
        if not dt or dt < cutoff:
            continue
        cve = v.get("cveID", "CVE-UNKNOWN")
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        name = v.get("vulnerabilityName", "")
        action = v.get("requiredAction", "")
        ransom = v.get("knownRansomwareCampaignUse", "Unknown")
        title = f"{cve} - {vendor} {product} : {name}".strip()
        summary = f"Action : {action} | Ransomware : {ransom}"
        matched = match_keywords(f"{title} {v.get('shortDescription', '')}", keywords)
        items.append(
            AlertItem(
                uid=make_uid(source["id"], cve),
                source_id=source["id"],
                source_name=source["name"],
                mode=source["mode"],
                severity="CRITIQUE",
                title=title[:200],
                summary=summary[:280],
                link=f"https://nvd.nist.gov/vuln/detail/{cve}",
                published=date_added,
                matched_keywords=matched[:5],
            )
        )
    return items


def parse_statuspage(
    raw_bytes: bytes,
    source: dict,
    keywords: list[str],
    cutoff: datetime,
) -> list[AlertItem]:
    data = json.loads(raw_bytes.decode("utf-8"))
    incidents = data.get("incidents", [])
    items: list[AlertItem] = []

    for inc in incidents:
        inc_id = inc.get("id", "")
        name = inc.get("name", "Incident sans titre")
        status = inc.get("status", "investigating")
        impact = inc.get("impact", "minor")
        link = inc.get("shortlink") or source["url"]
        updated = inc.get("updated_at") or inc.get("created_at") or ""
        dt = parse_date(updated)
        if dt and dt < cutoff:
            continue
        updates = inc.get("incident_updates") or []
        latest_body = strip_html(updates[0].get("body", "")) if updates else ""
        sev = "CRITIQUE" if impact in ("critical", "major") else "HAUTE"
        matched = match_keywords(f"{name} {latest_body}", keywords)
        items.append(
            AlertItem(
                uid=make_uid(source["id"], f"{inc_id}:{status}"),
                source_id=source["id"],
                source_name=source["name"],
                mode=source["mode"],
                severity=sev,
                title=f"[{impact.upper()} / {status}] {name}"[:200],
                summary=latest_body[:280],
                link=link,
                published=(dt.strftime("%Y-%m-%d %H:%M UTC") if dt else updated[:25]),
                matched_keywords=matched[:5],
            )
        )
    return items


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"seen_ids": [], "last_run_utc": None}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"seen_ids": [], "last_run_utc": None}


def save_state(path: Path, seen_ids: list[str], now: datetime) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    trimmed = seen_ids[-MAX_SEEN_IDS:]
    payload = {
        "last_run_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(trimmed),
        "seen_ids": trimmed,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def format_telegram_messages(items: list[AlertItem], mode: str, now: datetime) -> list[str]:
    header = (
        f"<b>VEILLE {mode.upper()} · {now.strftime('%d/%m/%Y %H:%M UTC')}</b>\n"
        f"<i>{len(items)} nouvelle(s) alerte(s) filtree(s)</i>\n"
    )
    blocks = []
    for item in items:
        tags = f" | Stack: {', '.join(item.matched_keywords)}" if item.matched_keywords else ""
        title_esc = html.escape(item.title)
        source_esc = html.escape(item.source_name)
        summary_esc = html.escape(item.summary) if item.summary else ""
        link_line = f'\n<a href="{html.escape(item.link, quote=True)}">Ouvrir la source</a>' if item.link else ""
        block = (
            f"\n<b>[{html.escape(item.severity)}] {title_esc}</b>\n"
            f"Source : {source_esc} ({html.escape(item.published)}){html.escape(tags)}"
            + (f"\n{summary_esc}" if summary_esc else "")
            + link_line
        )
        blocks.append(block)

    messages: list[str] = []
    current = header
    for b in blocks:
        if len(current) + len(b) > 3800:
            messages.append(current)
            current = f"<b>VEILLE {mode.upper()} (suite)</b>\n" + b
        else:
            current += b
    if current:
        messages.append(current)
    return messages


def send_telegram(messages: list[str], token: str, chat_id: str) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for msg in messages:
        payload = json.dumps(
            {
                "chat_id": chat_id,
                "text": msg,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                if resp.status >= 300:
                    raise RuntimeError(f"Telegram HTTP {resp.status}")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"Telegram API error HTTP {e.code}: {body[:200]}") from None


def build_notion_payload(item: AlertItem, database_id: str) -> dict:
    date_iso = item.published[:10] if re.match(r"^\d{4}-\d{2}-\d{2}", item.published) else datetime.now(timezone.utc).strftime("%Y-%m-%d")
    properties: dict = {
        "Titre": {"title": [{"text": {"content": item.title[:200]}}]},
        "Source": {"select": {"name": item.source_name[:100]}},
        "Catégorie": {"select": {"name": "Cybersécurité" if item.mode == "cyber" else "Panne Cloud"}},
        "Priorité": {"select": {"name": item.severity}},
        "Date": {"date": {"start": date_iso}},
    }
    if item.link:
        properties["Lien"] = {"url": item.link}
    return {
        "parent": {"database_id": database_id},
        "properties": properties,
        "children": [
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {
                    "rich_text": [
                        {
                            "type": "text",
                            "text": {"content": (item.summary or item.title)[:1800]},
                        }
                    ]
                },
            }
        ],
    }


def send_notion(items: list[AlertItem], token: str, database_id: str) -> int:
    url = "https://api.notion.com/v1/pages"
    created = 0
    for item in items:
        payload = json.dumps(build_notion_payload(item, database_id)).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Notion-Version": "2022-06-28",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                if resp.status < 300:
                    created += 1
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            print(f"[WARN] Notion API HTTP {e.code} on {item.uid}: {body[:200]}")
    return created


def write_digest(items: list[AlertItem], mode: str, now: datetime, errors: list[str]) -> Path:
    DIGESTS_DIR.mkdir(parents=True, exist_ok=True)
    day_file = DIGESTS_DIR / f"{now.strftime('%Y-%m-%d')}.md"
    latest_file = DIGESTS_DIR / "latest.md"

    lines = [
        f"# Veille Cyber & Cloud ({now.strftime('%Y-%m-%d %H:%M UTC')})",
        "",
        f"Mode : `{mode}` | Nouvelles alertes : **{len(items)}**",
        "",
    ]
    if not items:
        lines.append("Aucune nouvelle alerte critique ou pertinente sur cette fenetre.")
    else:
        lines.append("| Priorité | Source | Titre | Date |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for it in items:
            safe_title = it.title.replace("|", "/")
            title_col = f"[{safe_title}]({it.link})" if it.link else safe_title
            lines.append(f"| **{it.severity}** | {it.source_name} | {title_col} | {it.published} |")

    if errors:
        lines.append("")
        lines.append("## Sources en erreur lors de ce run")
        for err in errors:
            lines.append(f"- {err}")

    content = "\n".join(lines) + "\n"
    latest_file.write_text(content, encoding="utf-8")

    # Append or create daily file
    if day_file.exists():
        existing = day_file.read_text(encoding="utf-8")
        if items:
            day_file.write_text(existing + "\n" + content, encoding="utf-8")
    else:
        day_file.write_text(content, encoding="utf-8")
    return latest_file


def run(mode: str, dry_run: bool, lookback_days: int | None, max_items: int | None) -> int:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    keywords: list[str] = config.get("stack_keywords", [])
    days = lookback_days if lookback_days is not None else config.get("lookback_days_default", 7)
    cap = max_items if max_items is not None else config.get("max_items_per_run", 15)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    state = load_state(STATE_PATH)
    seen_set = set(state.get("seen_ids", []))
    seen_list = list(state.get("seen_ids", []))

    collected: list[AlertItem] = []
    errors: list[str] = []

    for source in config.get("sources", []):
        if mode != "all" and source.get("mode") != mode:
            continue
        try:
            raw = fetch_with_fallback(source)
            stype = source["type"]
            if stype == "rss":
                parsed = parse_rss_items(raw, source, keywords, cutoff)
            elif stype == "cisa_kev_json":
                parsed = parse_cisa_kev(raw, source, keywords, cutoff)
            elif stype == "statuspage_json":
                parsed = parse_statuspage(raw, source, keywords, cutoff)
            else:
                raise ValueError(f"Unknown source type: {stype}")

            for item in parsed:
                if item.uid not in seen_set:
                    collected.append(item)
            print(f"[OK] {source['id']}: {len(parsed)} parsed")
        except Exception as exc:
            msg = f"{source['id']}: {exc}"
            errors.append(msg)
            print(f"[WARN] {msg}")

    # Sort: CRITIQUE first, then HAUTE, then INFO
    rank = {"CRITIQUE": 0, "HAUTE": 1, "INFO": 2}
    collected.sort(key=lambda x: (rank.get(x.severity, 9), x.published), reverse=False)
    selected = collected[:cap]

    print(f"[INFO] New unique alerts selected: {len(selected)} (dry_run={dry_run})")
    for it in selected:
        print(f"  - [{it.severity}] {it.source_name}: {it.title}")

    if dry_run:
        return 0

    write_digest(selected, mode, now, errors)

    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if selected and tg_token and tg_chat:
        msgs = format_telegram_messages(selected, mode, now)
        send_telegram(msgs, tg_token, tg_chat)
        print(f"[OK] Telegram: sent {len(msgs)} message(s).")
    elif selected:
        print("[INFO] Telegram secrets not configured yet -> skipped Telegram notification.")

    notion_token = os.environ.get("NOTION_TOKEN", "").strip()
    notion_db = os.environ.get("NOTION_DATABASE_ID", "").strip()
    if selected and notion_token and notion_db:
        created = send_notion(selected, notion_token, notion_db)
        print(f"[OK] Notion: created {created}/{len(selected)} page(s).")
    elif selected:
        print("[INFO] Notion secrets not configured yet -> skipped Notion archive.")

    for it in selected:
        if it.uid not in seen_set:
            seen_set.add(it.uid)
            seen_list.append(it.uid)
    save_state(STATE_PATH, seen_list, now)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Cyber & Cloud Watch engine")
    parser.add_argument("--mode", choices=["all", "cyber", "cloud"], default="all")
    parser.add_argument("--dry-run", action="store_true", help="Do not update state or send notifications")
    parser.add_argument("--lookback-days", type=int, default=None)
    parser.add_argument("--max-items", type=int, default=None)
    args = parser.parse_args()
    return run(args.mode, args.dry_run, args.lookback_days, args.max_items)


if __name__ == "__main__":
    sys.exit(main())
