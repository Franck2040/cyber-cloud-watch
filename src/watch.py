#!/usr/bin/env python3
"""
Cyber & Cloud Watch — Automated Cybersecurity & Cloud Outage Briefing Engine.
Zero external dependencies (Python 3.11+ standard library only).

Features:
- Real cyber news (IT-Connect FR, CERT-FR CTI, BleepingComputer, The Hacker News)
- Critical vulnerabilities (CERT-FR Alertes/Avis, CISA KEV) with automatic deduplication & grouping
- Cloud outage status (Azure, GitHub, Cloudflare)
- Oral-ready Telegram briefing (Top 6 max, grouped, clean Fait/Risque/Reflexe format)
- Optional AI journalistic French rewrite via GEMINI_API_KEY (free Google AI Studio tier)
- Optional Notion database archiving + versioned Markdown digests
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
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
USER_AGENT = "cyber-cloud-watch/2.0 (+https://github.com/Franck2040/cyber-cloud-watch)"
MAX_SEEN_IDS = 2000


@dataclass
class AlertItem:
    uid: str
    source_id: str
    source_name: str
    mode: str
    kind: str  # "news" | "vuln" | "cloud"
    severity: str
    title: str
    summary: str
    link: str
    published: str
    matched_keywords: list[str] = field(default_factory=list)
    recommendation: str = ""
    grouped_uids: list[str] = field(default_factory=list)


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
    try:
        iso = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.strptime(raw[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def make_uid(source_id: str, key: str) -> str:
    digest = hashlib.sha256(f"{source_id}:{key}".encode("utf-8")).hexdigest()[:16]
    return f"{source_id}-{digest}"


def match_keywords(text: str, keywords: list[str]) -> list[str]:
    low = text.lower()
    return [kw.strip() for kw in keywords if kw.lower() in low]


def clean_certfr_summary(title: str, desc: str) -> tuple[str, str]:
    """Turn verbose CERT-FR boilerplate into concise risk + recommendation."""
    low = desc.lower()
    risks = []
    if "exécution de code arbitraire" in low or "execution de code arbitraire" in low:
        risks.append("prise de contrôle à distance (RCE)")
    if "élévation de privilèges" in low or "elevation de privileges" in low:
        risks.append("élévation de privilèges")
    if "contournement de la politique de sécurité" in low or "contournement" in low:
        risks.append("contournement de sécurité")
    if "atteinte à la confidentialité" in low:
        risks.append("vol ou fuite de données")
    if "déni de service" in low:
        risks.append("coupure de service (DoS)")

    if risks:
        risk_str = "Risque : " + ", ".join(risks[:3]) + "."
    else:
        cleaned = re.sub(
            r"^(De multiples vulnérabilités ont été découvertes|Une vulnérabilité a été découverte)[^.]*\.\s*",
            "",
            desc,
            flags=re.IGNORECASE,
        ).strip()
        risk_str = cleaned[:190] if cleaned else desc[:190]

    rec = "Appliquer les correctifs éditeur dès que possible et vérifier l'exposition."
    return risk_str, rec


def clean_cisa_action(action: str, ransom: str) -> str:
    """Remove repetitive BOD 26-04 legal boilerplate from CISA KEV."""
    short = re.sub(
        r",?\s*ensuring compliance with CISA.*$",
        "",
        action or "",
        flags=re.IGNORECASE,
    ).strip(" .")
    if not short or "apply mitigations" in short.lower():
        rec = "Appliquer immédiatement le correctif éditeur (faille déjà exploitée activement)."
    else:
        rec = short[:160] + "."
    if ransom and ransom.lower() == "known":
        rec += " Lien ransomware avéré."
    return rec


def parse_rss_items(
    raw_bytes: bytes,
    source: dict,
    stack_keywords: list[str],
    cutoff: datetime,
    news_keywords: list[str] | None = None,
) -> list[AlertItem]:
    root = ET.fromstring(raw_bytes)
    items: list[AlertItem] = []
    kind = source.get("kind", "vuln" if source.get("mode") == "cyber" else "cloud")
    active_keywords = (news_keywords or []) + stack_keywords if kind == "news" else stack_keywords

    rss_nodes = root.findall(".//item")
    atom_ns = "{http://www.w3.org/2005/Atom}"
    atom_nodes = root.findall(f".//{atom_ns}entry")

    raw_entries = []
    if rss_nodes:
        for node in rss_nodes:
            raw_entries.append(
                (
                    strip_html(node.findtext("title") or ""),
                    (node.findtext("link") or "").strip(),
                    strip_html(node.findtext("description") or ""),
                    (node.findtext("guid") or node.findtext("link") or node.findtext("title") or "").strip(),
                    node.findtext("pubDate") or node.findtext("{http://purl.org/dc/elements/1.1/}date") or "",
                )
            )
    elif atom_nodes:
        for node in atom_nodes:
            link_el = node.find(f"{atom_ns}link")
            link = (link_el.attrib.get("href", "") if link_el is not None else "").strip()
            raw_entries.append(
                (
                    strip_html(node.findtext(f"{atom_ns}title") or ""),
                    link,
                    strip_html(node.findtext(f"{atom_ns}summary") or node.findtext(f"{atom_ns}content") or ""),
                    (node.findtext(f"{atom_ns}id") or link or node.findtext(f"{atom_ns}title") or "").strip(),
                    node.findtext(f"{atom_ns}updated") or node.findtext(f"{atom_ns}published") or "",
                )
            )

    for title, link, desc, guid, pub_raw in raw_entries:
        if not title:
            continue
        dt = parse_date(pub_raw)
        if dt and dt < cutoff:
            continue
        matched = match_keywords(f"{title} {desc}", active_keywords)
        if not source.get("always_include", False) and not matched:
            continue

        sev = source.get("default_severity", "INFO")
        summary = desc[:240]
        rec = ""

        if source["id"].startswith("certfr-") and kind == "vuln":
            summary, rec = clean_certfr_summary(title, desc)
            if any(
                w in f"{title} {desc}".lower()
                for w in ("critique", "exécution de code arbitraire", "élévation de privilèges")
            ):
                sev = "CRITIQUE"
        elif kind == "news":
            if any(w in f"{title} {desc}".lower() for w in ("zero-day", "0-day", "ransomware", "rançongiciel", "ddos", "massive", "france")):
                sev = "ACTU CLÉ"
            rec = "À retenir pour ta veille et tes entretiens techniques."

        items.append(
            AlertItem(
                uid=make_uid(source["id"], guid),
                source_id=source["id"],
                source_name=source["name"],
                mode=source["mode"],
                kind=kind,
                severity=sev,
                title=title[:180],
                summary=summary,
                link=link,
                published=(dt.strftime("%Y-%m-%d %H:%M UTC") if dt else pub_raw[:25]),
                matched_keywords=matched[:4],
                recommendation=rec,
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
        vendor = v.get("vendorProject", "").strip()
        product = v.get("product", "").strip()
        name = v.get("vulnerabilityName", "").strip()
        short_desc = (v.get("shortDescription") or name).strip()
        action = v.get("requiredAction", "")
        ransom = v.get("knownRansomwareCampaignUse", "Unknown")

        product_label = vendor if vendor.lower() == product.lower() else f"{vendor} {product}".strip()
        title = f"{product_label} ({cve}) : faille activement exploitée"
        summary = short_desc[:220]
        rec = clean_cisa_action(action, ransom)
        matched = match_keywords(f"{title} {short_desc}", keywords)
        items.append(
            AlertItem(
                uid=make_uid(source["id"], cve),
                source_id=source["id"],
                source_name=source["name"],
                mode=source["mode"],
                kind="vuln",
                severity="CRITIQUE",
                title=title[:180],
                summary=summary,
                link=f"https://nvd.nist.gov/vuln/detail/{cve}",
                published=date_added,
                matched_keywords=matched[:4],
                recommendation=rec,
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
                kind="cloud",
                severity=sev,
                title=f"Panne {source['name']} ({status}) : {name}"[:180],
                summary=latest_body[:220],
                link=link,
                published=(dt.strftime("%Y-%m-%d %H:%M UTC") if dt else updated[:25]),
                matched_keywords=matched[:4],
                recommendation="Suivre la page statut officielle et prévenir l'équipe si service utilisé.",
            )
        )
    return items


def group_related_items(items: list[AlertItem]) -> list[AlertItem]:
    """Merge noisy same-family advisories (ex. Linux kernel across Red Hat/Ubuntu/Debian/SUSE)."""
    linux_group: list[AlertItem] = []
    others: list[AlertItem] = []

    for it in items:
        if it.source_id == "certfr-avis" and "noyau linux" in it.title.lower():
            linux_group.append(it)
        else:
            others.append(it)

    if len(linux_group) >= 2:
        distros = []
        for g in linux_group:
            m = re.search(r"noyau linux\s+(?:de|d['’])\s*([A-Za-z0-9\s]+?)(?:\s*\(|$)", g.title, re.IGNORECASE)
            if m:
                distros.append(m.group(1).strip())
        distro_label = ", ".join(dict.fromkeys(distros)) or f"{len(linux_group)} distributions"
        top = linux_group[0]
        merged = AlertItem(
            uid=top.uid,
            source_id=top.source_id,
            source_name=top.source_name,
            mode=top.mode,
            kind=top.kind,
            severity="CRITIQUE" if any(x.severity == "CRITIQUE" for x in linux_group) else "HAUTE",
            title=f"Noyau Linux ({distro_label}) : vague de correctifs critiques ({len(linux_group)} avis regroupés)",
            summary=top.summary,
            link=top.link,
            published=top.published,
            matched_keywords=["linux"],
            recommendation="Mettre à jour les serveurs Linux concernés (Red Hat, Ubuntu, Debian, SUSE).",
            grouped_uids=[x.uid for x in linux_group],
        )
        others.append(merged)
    else:
        others.extend(linux_group)

    return others


def select_balanced_briefing(
    items: list[AlertItem],
    max_total: int = 6,
    max_news: int = 3,
    max_vulns: int = 3,
) -> list[AlertItem]:
    """Pick a concise, balanced Top N: cloud outages first, then news + top vulns."""
    sev_rank = {"CRITIQUE": 0, "ACTU CLÉ": 1, "HAUTE": 2, "ACTU": 3, "INFO": 4}
    ordered = sorted(items, key=lambda x: (sev_rank.get(x.severity, 9), x.published), reverse=False)

    clouds = [x for x in ordered if x.kind == "cloud"]
    news = [x for x in ordered if x.kind == "news"]
    vulns = [x for x in ordered if x.kind == "vuln"]

    selected: list[AlertItem] = []
    selected.extend(clouds[:2])
    selected.extend(news[:max_news])
    selected.extend(vulns[:max_vulns])

    # Fill remaining slots up to max_total if one category had fewer items
    used = {x.uid for x in selected}
    for x in ordered:
        if len(selected) >= max_total:
            break
        if x.uid not in used:
            selected.append(x)
            used.add(x.uid)

    return selected[:max_total]


def generate_gemini_briefing(items: list[AlertItem], mode: str, now: datetime, api_key: str) -> list[str] | None:
    """Optional free-tier Gemini API rewrite into a fluent, oral-ready French cyber briefing."""
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash").strip() or "gemini-2.5-flash"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

    facts = [
        {
            "categorie": "Actualité / Attaque" if it.kind == "news" else ("Panne Cloud" if it.kind == "cloud" else "Faille critique"),
            "niveau": it.severity,
            "source": it.source_name,
            "date": it.published,
            "titre": it.title,
            "details": it.summary,
            "recommandation": it.recommendation,
            "lien": it.link,
        }
        for it in items
    ]

    prompt = (
        "Tu es un analyste cybersécurité senior qui prépare un briefing matinal Telegram en français pour un étudiant en Mastère Cybersécurité & Cloud.\n"
        "Objectif : il doit pouvoir lire le message en 45 secondes dans les transports et être capable de RACONTER chaque sujet clairement à l'oral à quelqu'un.\n"
        "Règles strictes :\n"
        "1. Utilise UNIQUEMENT les faits présents dans le JSON ci-dessous. N'invente JAMAIS un pays, une heure, un auteur ou une victime non mentionnés.\n"
        "2. Pas d'émojis, pas de tirets de séparation '---', pas de blabla d'introduction.\n"
        "3. Format HTML Telegram UNIQUEMENT (balises autorisées : <b>, <i>, <a href=\"...\">). Échappe &, < et > dans le texte.\n"
        "4. Pour chaque sujet (numéroté 1, 2, 3...), écris 3 lignes courtes :\n"
        "   - <b>N. Titre clair en français</b> (Source)\n"
        "   - 2 phrases fluides prêtes à raconter (ce qui s'est passé / qui est touché / faille ou cause).\n"
        "   - <b>Réflexe :</b> 1 recommandation concrète · <a href=\"LIEN\">Source</a>\n"
        f"En-tête exact : <b>BRIEFING CYBER & CLOUD · {now.strftime('%d/%m/%Y')}</b>\n\n"
        f"Données sources JSON :\n{json.dumps(facts, ensure_ascii=False)}"
    )

    body = json.dumps(
        {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1800},
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        if not text:
            return None
        # Split safely under Telegram's 4096 char limit
        if len(text) <= 3900:
            return [text]
        chunks, cur = [], ""
        for para in text.split("\n\n"):
            if len(cur) + len(para) + 2 > 3800:
                if cur:
                    chunks.append(cur.strip())
                cur = para
            else:
                cur = (cur + "\n\n" + para).strip()
        if cur:
            chunks.append(cur.strip())
        return chunks
    except Exception as exc:
        print(f"[WARN] Gemini briefing unavailable ({exc}) -> fallback to local clean briefing.")
        return None


def format_telegram_messages(items: list[AlertItem], mode: str, now: datetime) -> list[str]:
    """Clean, oral-ready local French briefing (works with 0 AI key)."""
    news = [x for x in items if x.kind == "news"]
    tech = [x for x in items if x.kind != "news"]

    header = (
        f"<b>BRIEFING CYBER &amp; CLOUD · {now.strftime('%d/%m/%Y')}</b>\n"
        f"<i>Top {len(items)} à retenir (lecture 45 s)</i>\n"
    )

    blocks: list[str] = []
    idx = 1

    if news:
        blocks.append("\n<b>ACTUS &amp; ATTAQUES À RACONTER</b>")
        for it in news:
            title_esc = html.escape(it.title)
            src_esc = html.escape(it.source_name)
            sum_esc = html.escape(it.summary) if it.summary else ""
            rec_esc = html.escape(it.recommendation) if it.recommendation else ""
            link_part = f' · <a href="{html.escape(it.link, quote=True)}">Lire</a>' if it.link else ""
            blocks.append(
                f"\n<b>{idx}. {title_esc}</b> ({src_esc})\n"
                + (f"{sum_esc}\n" if sum_esc else "")
                + f"<b>À retenir :</b> {rec_esc}{link_part}"
            )
            idx += 1

    if tech:
        blocks.append("\n<b>FAILLES &amp; PANNES CRITIQUES</b>")
        for it in tech:
            title_esc = html.escape(it.title)
            src_esc = html.escape(it.source_name)
            sum_esc = html.escape(it.summary) if it.summary else ""
            rec_esc = html.escape(it.recommendation or "Vérifier les correctifs éditeur.")
            link_part = f' · <a href="{html.escape(it.link, quote=True)}">Source</a>' if it.link else ""
            blocks.append(
                f"\n<b>{idx}. [{html.escape(it.severity)}] {title_esc}</b> ({src_esc})\n"
                + (f"{sum_esc}\n" if sum_esc else "")
                + f"<b>Réflexe :</b> {rec_esc}{link_part}"
            )
            idx += 1

    messages: list[str] = []
    current = header
    for b in blocks:
        if len(current) + len(b) > 3800:
            messages.append(current)
            current = f"<b>BRIEFING CYBER &amp; CLOUD (suite)</b>\n" + b
        else:
            current += b
    if current:
        messages.append(current)
    return messages


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
    date_iso = (
        item.published[:10]
        if re.match(r"^\d{4}-\d{2}-\d{2}", item.published)
        else datetime.now(timezone.utc).strftime("%Y-%m-%d")
    )
    category_map = {"news": "Actu Cyber", "vuln": "Faille Critique", "cloud": "Panne Cloud"}
    properties: dict = {
        "Titre": {"title": [{"text": {"content": item.title[:200]}}]},
        "Source": {"select": {"name": item.source_name[:100]}},
        "Catégorie": {"select": {"name": category_map.get(item.kind, "Cybersécurité")}},
        "Priorité": {"select": {"name": item.severity}},
        "Date": {"date": {"start": date_iso}},
    }
    if item.link:
        properties["Lien"] = {"url": item.link}
    detail = f"{item.summary}\nRéflexe : {item.recommendation}".strip()
    return {
        "parent": {"database_id": database_id},
        "properties": properties,
        "children": [
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {"rich_text": [{"type": "text", "text": {"content": detail[:1800]}}]},
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
        f"# Briefing Cyber & Cloud ({now.strftime('%Y-%m-%d %H:%M UTC')})",
        "",
        f"Mode : `{mode}` | Sujets retenus : **{len(items)}**",
        "",
    ]
    if not items:
        lines.append("Aucune nouvelle alerte ou actu majeure sur cette fenêtre.")
    else:
        lines.append("| Niveau | Type | Source | Sujet | Date |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for it in items:
            safe_title = it.title.replace("|", "/")
            title_col = f"[{safe_title}]({it.link})" if it.link else safe_title
            lines.append(f"| **{it.severity}** | {it.kind} | {it.source_name} | {title_col} | {it.published} |")

    if errors:
        lines.append("")
        lines.append("## Sources en erreur lors de ce run")
        for err in errors:
            lines.append(f"- {err}")

    content = "\n".join(lines) + "\n"
    latest_file.write_text(content, encoding="utf-8")

    if day_file.exists():
        existing = day_file.read_text(encoding="utf-8")
        if items:
            day_file.write_text(existing + "\n" + content, encoding="utf-8")
    else:
        day_file.write_text(content, encoding="utf-8")
    return latest_file


def run(mode: str, dry_run: bool, lookback_days: int | None, max_items: int | None) -> int:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    stack_kw: list[str] = config.get("stack_keywords", [])
    news_kw: list[str] = config.get("news_keywords", [])
    days = lookback_days if lookback_days is not None else config.get("lookback_days_default", 4)
    cap = max_items if max_items is not None else config.get("max_items_per_run", 15)
    tg_cap = config.get("telegram_max_items", 6)
    tg_news = config.get("telegram_max_news", 3)
    tg_vulns = config.get("telegram_max_vulns", 3)

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
                parsed = parse_rss_items(raw, source, stack_kw, cutoff, news_kw)
            elif stype == "cisa_kev_json":
                parsed = parse_cisa_kev(raw, source, stack_kw, cutoff)
            elif stype == "statuspage_json":
                parsed = parse_statuspage(raw, source, stack_kw, cutoff)
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

    grouped = group_related_items(collected)
    briefing_items = select_balanced_briefing(grouped, max_total=tg_cap, max_news=tg_news, max_vulns=tg_vulns)
    archive_items = grouped[:cap]

    print(f"[INFO] Grouped items: {len(grouped)} | Telegram Top briefing: {len(briefing_items)} (dry_run={dry_run})")
    for it in briefing_items:
        print(f"  - [{it.severity} / {it.kind}] {it.source_name}: {it.title}")

    if dry_run:
        return 0

    write_digest(archive_items, mode, now, errors)

    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()

    if briefing_items and tg_token and tg_chat:
        msgs = None
        if gemini_key:
            msgs = generate_gemini_briefing(briefing_items, mode, now, gemini_key)
            if msgs:
                print("[OK] Generated journalistic French briefing via Gemini API.")
        if not msgs:
            msgs = format_telegram_messages(briefing_items, mode, now)
        send_telegram(msgs, tg_token, tg_chat)
        print(f"[OK] Telegram: sent {len(msgs)} message(s).")
    elif briefing_items:
        print("[INFO] Telegram secrets not configured yet -> skipped Telegram notification.")

    notion_token = os.environ.get("NOTION_TOKEN", "").strip()
    notion_db = os.environ.get("NOTION_DATABASE_ID", "").strip()
    if archive_items and notion_token and notion_db:
        created = send_notion(archive_items, notion_token, notion_db)
        print(f"[OK] Notion: created {created}/{len(archive_items)} page(s).")

    # Mark all collected/grouped items as seen so grouped advisories don't reappear next run
    for it in archive_items:
        ids_to_mark = it.grouped_uids if it.grouped_uids else [it.uid]
        for uid in ids_to_mark:
            if uid not in seen_set:
                seen_set.add(uid)
                seen_list.append(uid)
    save_state(STATE_PATH, seen_list, now)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Cyber & Cloud Watch briefing engine")
    parser.add_argument("--mode", choices=["all", "cyber", "cloud"], default="all")
    parser.add_argument("--dry-run", action="store_true", help="Do not update state or send notifications")
    parser.add_argument("--lookback-days", type=int, default=None)
    parser.add_argument("--max-items", type=int, default=None)
    args = parser.parse_args()
    return run(args.mode, args.dry_run, args.lookback_days, args.max_items)


if __name__ == "__main__":
    sys.exit(main())
