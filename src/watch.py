#!/usr/bin/env python3
"""
Cyber & Cloud Watch — Automated Cybersecurity & Cloud Outage Briefing Engine (v3).
Zero external dependencies (Python 3.11+ standard library only).

Features:
- Real cyber news (IT-Connect FR, CERT-FR Menaces, BleepingComputer, The Hacker News)
- Critical vulnerabilities (CERT-FR Alertes/Avis, CISA KEV) with automatic deduplication & grouping
- Cloud outage status (Azure, GitHub, Cloudflare)
- Full-article HTML text extraction for the Top 5 selected stories
- Anti-noise filtering (excludes recaps, gaming fluff, deals, emojis, WordPress footers)
- "Journal du 20h" 100% French journalistic synthesis via Gemini 3.x free tier (with resilient model chain)
- 100% French clean fallback if AI is unavailable, with generous blank-line spacing and inline source links
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import html
from html.parser import HTMLParser
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
USER_AGENT = "cyber-cloud-watch/3.0 (+https://github.com/Franck2040/cyber-cloud-watch)"
ARTICLE_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
MAX_SEEN_IDS = 2000

DEFAULT_GEMINI_MODELS = [
    "gemini-3.5-flash-lite",
    "gemini-3.8-flash",
    "gemini-3.6-flash",
    "gemini-3.1-flash-lite",
]

EMOJI_RE = re.compile(
    "["
    "\U0001F1E0-\U0001F1FF"
    "\U0001F300-\U0001F5FF"
    "\U0001F600-\U0001F64F"
    "\U0001F680-\U0001F6FF"
    "\U0001F700-\U0001F77F"
    "\U0001F780-\U0001F7FF"
    "\U0001F800-\U0001F8FF"
    "\U0001F900-\U0001F9FF"
    "\U0001FA00-\U0001FAFF"
    "\u2600-\u27BF"
    "\u2300-\u23FF"
    "\u2B00-\u2BFF"
    "\uFE0E\uFE0F\u200D"
    "]+",
    flags=re.UNICODE,
)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

KEY_CYBER_SIGNALS = (
    "zero-day",
    "0-day",
    "ransomware",
    "rançongiciel",
    "ddos",
    "cyberattaque",
    "cyberattack",
    "fuite de données",
    "data breach",
    "dérobés",
    "piraté",
    "compromis",
    "activement exploitée",
    "exploited in attacks",
    "faille critique",
    "critical flaw",
    "rce",
    "exécution de code",
    "backdoor",
    "botnet",
)


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
    lang: str = "fr"
    published_ts: float = 0.0
    matched_keywords: list[str] = field(default_factory=list)
    recommendation: str = ""
    grouped_uids: list[str] = field(default_factory=list)
    article_text: str = ""


class ArticleTextExtractor(HTMLParser):
    """Lightweight stdlib HTML paragraph extractor preferring <article>/<main> content."""

    SKIP_TAGS = {"script", "style", "nav", "header", "footer", "aside", "noscript", "form", "svg", "iframe"}
    BLOCK_TAGS = {"p", "li", "h2", "h3"}
    NOISE_HINTS = (
        "cookies",
        "newsletter",
        "abonnez-vous",
        "s'abonner",
        "suivez-nous",
        "partager cet article",
        "est apparu en premier sur",
        "appeared first on",
        "all rights reserved",
        "tous droits réservés",
        "politique de confidentialité",
        "mentions légales",
        "accept all",
        "sign up for",
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.skip_depth = 0
        self.in_main = 0
        self.in_block = False
        self.cur_buf: list[str] = []
        self.main_blocks: list[str] = []
        self.all_blocks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if t in self.SKIP_TAGS:
            self.skip_depth += 1
            return
        if self.skip_depth > 0:
            return
        if t in ("article", "main"):
            self.in_main += 1
        if t in self.BLOCK_TAGS:
            self._flush()
            self.in_block = True

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in self.SKIP_TAGS:
            if self.skip_depth > 0:
                self.skip_depth -= 1
            return
        if self.skip_depth > 0:
            return
        if t in self.BLOCK_TAGS:
            self._flush()
            self.in_block = False
        if t in ("article", "main") and self.in_main > 0:
            self.in_main -= 1

    def handle_data(self, data: str) -> None:
        if self.skip_depth == 0 and self.in_block:
            self.cur_buf.append(data)

    def _flush(self) -> None:
        if not self.cur_buf:
            return
        txt = strip_emojis(re.sub(r"\s+", " ", "".join(self.cur_buf)).strip())
        self.cur_buf.clear()
        if len(txt) < 35:
            return
        low = txt.lower()
        if any(h in low for h in self.NOISE_HINTS):
            return
        self.all_blocks.append(txt)
        if self.in_main > 0:
            self.main_blocks.append(txt)

    def get_text(self, max_chars: int = 2800) -> str:
        self._flush()
        chosen = self.main_blocks if len(" ".join(self.main_blocks)) >= 280 else self.all_blocks
        seen: set[str] = set()
        out: list[str] = []
        total = 0
        for blk in chosen:
            if blk in seen:
                continue
            seen.add(blk)
            if total + len(blk) + 1 > max_chars:
                break
            out.append(blk)
            total += len(blk) + 1
        return "\n".join(out)


def fetch_url(url: str, timeout: int = 20, user_agent: str = USER_AGENT) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
        },
    )
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


def strip_emojis(text: str) -> str:
    cleaned = EMOJI_RE.sub("", text or "")
    return re.sub(r"[ \t]{2,}", " ", cleaned).strip()


def clean_rss_boilerplate(text: str) -> str:
    cleaned = text or ""
    cleaned = re.sub(r"\bLe post\s+.*?\s+est apparu en premier sur\s+[^.]+\.?", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\bThe post\s+.*?\s+appeared first on\s+[^.]+\.?", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\[\s*(?:\.\.\.|…)\s*\]", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def strip_html(raw: str) -> str:
    text = re.sub(r"<[^>]+>", " ", raw or "")
    text = html.unescape(text)
    text = strip_emojis(text)
    text = clean_rss_boilerplate(text)
    return text


def trim_to_sentence(text: str, max_chars: int = 380) -> str:
    """Cut text cleanly on a sentence boundary (or word boundary), never mid-word."""
    txt = re.sub(r"\s+", " ", (text or "")).strip()
    if len(txt) <= max_chars:
        return txt

    window = txt[: max_chars + 1]
    # Prefer cutting after a full sentence ending
    matches = list(re.finditer(r"[.!?](?:\s|$)", window))
    for m in reversed(matches):
        if m.end() >= int(max_chars * 0.45):
            return window[: m.end()].strip()

    # Fallback: cut at last complete word
    cut = window[:max_chars].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return (cut + "...") if cut else txt[:max_chars]


def is_excluded(text: str, exclude_patterns: list[str]) -> bool:
    low = (text or "").lower()
    return any(pat.lower() in low for pat in exclude_patterns if pat)


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


def extract_article_text_from_html(raw_html: str, max_chars: int = 2800) -> str:
    parser = ArticleTextExtractor()
    try:
        parser.feed(raw_html)
        parser.close()
    except Exception:
        pass
    return parser.get_text(max_chars=max_chars)


def fetch_article_text(url: str, max_chars: int = 2800) -> str:
    if not url or not url.startswith(("http://", "https://")):
        return ""
    try:
        raw = fetch_url(url, timeout=10, user_agent=ARTICLE_USER_AGENT)
        decoded = raw.decode("utf-8", errors="ignore")
        return extract_article_text_from_html(decoded, max_chars=max_chars)
    except Exception as exc:
        print(f"[INFO] Article fetch skipped for {url[:70]} ({exc})")
        return ""


def enrich_items_with_article_text(items: list[AlertItem]) -> None:
    """Fetch full webpage text only for the selected Top N briefing items."""
    for it in items:
        if it.article_text or not it.link:
            continue
        extracted = fetch_article_text(it.link)
        if extracted:
            it.article_text = extracted


def clean_certfr_summary(title: str, desc: str) -> tuple[str, str]:
    """Turn verbose CERT-FR boilerplate into concise risk + recommendation."""
    low = desc.lower()
    risks = []
    if "exécution de code arbitraire" in low or "execution de code arbitraire" in low:
        risks.append("prise de contrôle à distance (exécution de code arbitraire)")
    if "élévation de privilèges" in low or "elevation de privileges" in low:
        risks.append("élévation de privilèges")
    if "contournement de la politique de sécurité" in low or "contournement" in low:
        risks.append("contournement de la politique de sécurité")
    if "atteinte à la confidentialité" in low:
        risks.append("fuite ou vol de données")
    if "déni de service" in low:
        risks.append("interruption de service (déni de service)")

    if risks:
        risk_str = "Les vulnérabilités exposent les systèmes concernés à : " + ", ".join(risks[:3]) + "."
    else:
        cleaned = re.sub(
            r"^(De multiples vulnérabilités ont été découvertes|Une vulnérabilité a été découverte)[^.]*\.\s*",
            "",
            desc,
            flags=re.IGNORECASE,
        ).strip()
        risk_str = trim_to_sentence(cleaned or desc, 260)

    rec = "Se référer au bulletin de sécurité de l'éditeur pour installer les correctifs sans délai."
    return risk_str, rec


def clean_cisa_action(action: str, ransom: str) -> str:
    """Remove repetitive BOD legal boilerplate from CISA KEV."""
    short = re.sub(
        r",?\s*ensuring compliance with CISA.*$",
        "",
        action or "",
        flags=re.IGNORECASE,
    ).strip(" .")
    if not short or "apply mitigations" in short.lower():
        rec = "Appliquer immédiatement le correctif éditeur, cette faille étant déjà exploitée activement."
    else:
        rec = trim_to_sentence(short, 180)
    if ransom and ransom.lower() == "known":
        rec += " Exploitation confirmée dans des campagnes de rançongiciel."
    return rec


def parse_rss_items(
    raw_bytes: bytes,
    source: dict,
    stack_keywords: list[str],
    cutoff: datetime,
    news_keywords: list[str] | None = None,
    exclude_patterns: list[str] | None = None,
) -> list[AlertItem]:
    root = ET.fromstring(raw_bytes)
    items: list[AlertItem] = []
    kind = source.get("kind", "vuln" if source.get("mode") == "cyber" else "cloud")
    lang = source.get("lang", "fr")
    active_keywords = (news_keywords or []) + stack_keywords if kind == "news" else stack_keywords
    excludes = exclude_patterns or []

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
        if is_excluded(f"{title} {desc}", excludes):
            continue
        dt = parse_date(pub_raw)
        if dt and dt < cutoff:
            continue
        matched = match_keywords(f"{title} {desc}", active_keywords)
        if not source.get("always_include", False) and not matched:
            continue

        sev = source.get("default_severity", "INFO")
        summary = trim_to_sentence(desc, 360)
        rec = ""

        if source["id"].startswith("certfr-") and kind == "vuln":
            summary, rec = clean_certfr_summary(title, desc)
            if any(
                w in f"{title} {desc}".lower()
                for w in ("critique", "exécution de code arbitraire", "execution de code arbitraire", "élévation de privilèges", "elevation de privileges")
            ):
                sev = "CRITIQUE"
        elif kind == "news":
            low_all = f"{title} {desc}".lower()
            if any(w in low_all for w in KEY_CYBER_SIGNALS):
                sev = "ACTU CLÉ"

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
                lang=lang,
                published_ts=(dt.timestamp() if dt else 0.0),
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
        summary = trim_to_sentence(short_desc, 300)
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
                lang=source.get("lang", "en"),
                published_ts=(dt.timestamp() if dt else 0.0),
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
        name = strip_emojis(inc.get("name", "Incident sans titre"))
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
                summary=trim_to_sentence(latest_body, 300),
                link=link,
                published=(dt.strftime("%Y-%m-%d %H:%M UTC") if dt else updated[:25]),
                lang=source.get("lang", "en"),
                published_ts=(dt.timestamp() if dt else 0.0),
                matched_keywords=matched[:4],
                recommendation="Suivre la page statut officielle et prévenir l'équipe si le service est utilisé.",
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
        top = max(linux_group, key=lambda x: x.published_ts)
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
            lang=top.lang,
            published_ts=top.published_ts,
            matched_keywords=["linux"],
            recommendation="Mettre à jour les serveurs Linux concernés (Red Hat, Ubuntu, Debian, SUSE).",
            grouped_uids=[x.uid for x in linux_group],
        )
        others.append(merged)
    else:
        others.extend(linux_group)

    return others


def _topic_keys(item: AlertItem) -> set[str]:
    text = f"{item.title} {item.summary}"
    keys = {m.upper() for m in CVE_RE.findall(text)}
    # Catch named flaws/brands like Java4Shell, NoisyTCP, Maileva, Optimizely
    for tok in re.findall(r"[A-Za-z0-9]{6,}", item.title):
        low = tok.lower()
        if low not in {
            "multiples",
            "vulnérabilités",
            "vulnerabilites",
            "vulnerabilite",
            "vulnerability",
            "security",
            "securite",
            "sécurité",
            "critical",
            "critique",
            "update",
            "attacks",
            "attack",
            "cyberattaque",
            "faille",
            "server",
            "windows",
            "microsoft",
            "google",
            "oracle",
            "mozilla",
            "apache",
        }:
            keys.add(low)
    return keys


def deduplicate_similar_stories(items: list[AlertItem]) -> list[AlertItem]:
    """Avoid showing the exact same story twice (e.g. FR + EN article on the same CVE or named flaw)."""
    kept: list[AlertItem] = []
    kept_keys: list[set[str]] = []

    for it in items:
        cur_keys = _topic_keys(it)
        cves = {k for k in cur_keys if k.startswith("CVE-")}
        is_dup = False
        for prev_keys in kept_keys:
            if cves and (cves & prev_keys):
                is_dup = True
                break
            shared = cur_keys & prev_keys
            if len(shared) >= 2:
                is_dup = True
                break
        if not is_dup:
            kept.append(it)
            kept_keys.append(cur_keys)
    return kept


def select_balanced_briefing(
    items: list[AlertItem],
    max_total: int = 5,
    max_news: int = 3,
    max_vulns: int = 2,
) -> list[AlertItem]:
    """Pick a concise, balanced Top N sorted by severity then MOST RECENT first."""
    sev_rank = {"CRITIQUE": 0, "ACTU CLÉ": 1, "HAUTE": 2, "ACTU": 3, "INFO": 4}
    ordered = sorted(
        items,
        key=lambda x: (sev_rank.get(x.severity, 9), -x.published_ts, 0 if x.lang == "fr" else 1),
    )
    ordered = deduplicate_similar_stories(ordered)

    clouds = [x for x in ordered if x.kind == "cloud"]
    news = [x for x in ordered if x.kind == "news"]
    vulns = [x for x in ordered if x.kind == "vuln"]

    selected: list[AlertItem] = []
    selected.extend(clouds[:2])
    selected.extend(news[:max_news])
    selected.extend(vulns[:max_vulns])

    used = {x.uid for x in selected}
    for x in ordered:
        if len(selected) >= max_total:
            break
        if x.uid not in used:
            selected.append(x)
            used.add(x.uid)

    return selected[:max_total]


def discover_gemini_flash_models(api_key: str) -> list[str]:
    """Query Gemini ListModels API to auto-discover available Flash models if hardcoded IDs change."""
    url = "https://generativelanguage.googleapis.com/v1beta/models"
    req = urllib.request.Request(
        url,
        headers={"x-goog-api-key": api_key, "User-Agent": USER_AGENT},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        discovered: list[str] = []
        for m in data.get("models", []):
            name = (m.get("name") or "").replace("models/", "")
            methods = m.get("supportedGenerationMethods") or []
            if "generateContent" not in methods:
                continue
            low = name.lower()
            if "gemini" in low and "flash" in low and not any(
                bad in low for bad in ("tts", "image", "live", "audio", "exp", "2.0", "1.5")
            ):
                discovered.append(name)
        discovered.sort(reverse=True)
        return discovered
    except Exception as exc:
        print(f"[INFO] Gemini model discovery skipped ({exc})")
        return []


def clean_gemini_telegram_output(raw_text: str) -> str:
    """Clean LLM output so Telegram HTML is spotless, emoji-free, and well-spaced."""
    text = (raw_text or "").strip()
    # Strip markdown code fences if the model wrapped its HTML
    text = re.sub(r"^```(?:html|HTML)?\s*\n?", "", text)
    text = re.sub(r"\n?```\s*$", "", text)
    text = strip_emojis(text)
    # Remove horizontal rules and em-dashes per style rules
    text = re.sub(r"(?m)^\s*[-_*]{3,}\s*$", "", text)
    text = text.replace(" — ", " : ").replace("—", " - ")
    # Guarantee 2 visible blank lines before every numbered item (1., 2., 3., ...)
    text = re.sub(r"\n{1,4}(<b>\d+\.)", r"\n\n\n\1", text)
    # Collapse excessive >3 consecutive newlines
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.strip()


def split_telegram_text(text: str, limit: int = 3900) -> list[str]:
    if len(text) <= limit:
        return [text]
    chunks: list[str] = []
    cur = ""
    for block in text.split("\n\n\n"):
        sep = "\n\n\n" if cur else ""
        if len(cur) + len(sep) + len(block) > limit:
            if cur:
                chunks.append(cur.strip())
            cur = block
        else:
            cur = cur + sep + block
    if cur:
        chunks.append(cur.strip())
    return chunks


def _call_gemini_model(model: str, prompt: str, api_key: str) -> str:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    gen_cfg: dict = {"maxOutputTokens": 4096}
    # Gemini 3.6/3.8 Flash support thinkingLevel ("low" avoids burning tokens on reasoning)
    if any(tag in model for tag in ("3.8-flash", "3.7-flash", "3.6-flash")) and "lite" not in model:
        gen_cfg["thinkingConfig"] = {"thinkingLevel": "low"}

    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": gen_cfg,
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    candidates = data.get("candidates") or []
    if not candidates:
        raise RuntimeError(f"empty candidates from {model}")
    parts = (candidates[0].get("content") or {}).get("parts") or []
    visible_parts = [p.get("text", "") for p in parts if not p.get("thought") and p.get("text")]
    return "".join(visible_parts).strip()


def generate_gemini_briefing(items: list[AlertItem], mode: str, now: datetime, api_key: str) -> list[str] | None:
    """Free-tier Gemini 3.x rewrite into a serious 'Journal du 20h' 100% French briefing."""
    facts = [
        {
            "numero": idx,
            "categorie": "Actualité cyber" if it.kind == "news" else ("Panne Cloud" if it.kind == "cloud" else "Faille critique"),
            "niveau": it.severity,
            "source": it.source_name,
            "date": it.published,
            "titre_original": it.title,
            "resume_rss": it.summary,
            "texte_article": it.article_text[:2400] if it.article_text else "",
            "recommandation_source": it.recommendation,
            "lien": it.link,
        }
        for idx, it in enumerate(items, start=1)
    ]

    prompt = (
        "Tu es le rédacteur en chef du Journal de 20h, spécialisé en cybersécurité et cloud.\n"
        "Ta mission : rédiger un bulletin Telegram en FRANÇAIS UNIQUEMENT pour un étudiant en Mastère Cybersécurité & Cloud.\n"
        "Objectif : chaque point doit lui donner la vraie substance de l'information pour qu'il puisse la raconter clairement et naturellement à une autre personne.\n\n"
        "RÈGLES STRICTES :\n"
        "1. LANGUE : 100 % français impeccable. Traduis et adapte naturellement tous les titres et faits venant de sources anglaises. Aucune phrase en anglais.\n"
        "2. TON : journalistique sérieux, clair, posé et informatif (style présentateur du 20h). INTERDICTION absolue du style familier, jeune, raccoleur ou des phrases creuses (jamais de 'À retenir pour ta veille', jamais de teaser vague).\n"
        "3. FAITS UNIQUEMENT : appuie-toi uniquement sur 'texte_article', 'resume_rss' et 'recommandation_source'. N'invente JAMAIS un chiffre, une victime, une date ou un auteur absent des données.\n"
        "4. CONTENU PAR POINT : 3 à 4 phrases fluides et précises couvrant concrètement :\n"
        "   - Qui est touché ou quel produit/service est concerné.\n"
        "   - Ce qui s'est passé exactement (attaque, vecteur, ou faille CVE précise).\n"
        "   - L'impact concret et la mesure de protection ou le correctif recommandé.\n"
        "   - Si deux entrées du JSON traitent exactement de la même faille CVE (ex. un article et une alerte CERT-FR), fusionne-les en un seul point complet en mentionnant les deux sources.\n"
        "5. MISE EN PAGE TELEGRAM HTML UNIQUEMENT (balises autorisées : <b>, <i>, <a href=\"...\">). Échappe & en &amp; dans le texte. Zéro émoji, zéro '---', zéro tiret cadratin '—', zéro bloc ```html.\n"
        "6. STRUCTURE EXACTE À RESPECTER :\n\n"
        f"<b>JOURNAL CYBER &amp; CLOUD · {now.strftime('%d/%m/%Y')}</b>\n"
        f"<i>Les {len(items)} faits majeurs à connaître aujourd'hui</i>\n\n\n"
        "<b>1. Titre clair et factuel en français</b> (Source)\n"
        "3 à 4 phrases fluides style journal de 20h donnant les faits complets et la recommandation concrète. (<a href=\"LIEN_EXACT\">Article complet</a>)\n\n\n"
        "<b>2. Titre clair et factuel en français</b> (Source)\n"
        "...\n\n"
        "IMPORTANT : laisse bien DEUX lignes vides entre chaque point numéroté et place toujours (<a href=\"LIEN_EXACT\">Article complet</a>) directement à la fin du paragraphe.\n\n"
        f"Données sources JSON :\n{json.dumps(facts, ensure_ascii=False)}"
    )

    env_model = os.environ.get("GEMINI_MODEL", "").strip()
    candidates = ([env_model] if env_model else []) + [m for m in DEFAULT_GEMINI_MODELS if m != env_model]

    attempted: set[str] = set()
    for phase in (candidates, None):
        model_list = phase if phase is not None else [m for m in discover_gemini_flash_models(api_key) if m not in attempted]
        for model in model_list:
            attempted.add(model)
            try:
                raw_out = _call_gemini_model(model, prompt, api_key)
                cleaned = clean_gemini_telegram_output(raw_out)
                if cleaned and len(cleaned) >= 120:
                    print(f"[OK] Gemini briefing generated with model '{model}'.")
                    return split_telegram_text(cleaned)
                print(f"[WARN] Gemini model '{model}' returned empty/short output, trying next...")
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="ignore")[:220].replace("\n", " ")
                print(f"[WARN] Gemini model '{model}' failed (HTTP {e.code}: {err_body})")
            except Exception as exc:
                print(f"[WARN] Gemini model '{model}' failed ({exc})")

    print("[WARN] All Gemini models unavailable -> fallback to 100% French local briefing.")
    return None


def _build_local_item_body(it: AlertItem) -> str:
    """Build substantive 100% French paragraph from extracted article text or clean RSS summary."""
    base = ""
    if it.article_text:
        paras = [p.strip() for p in it.article_text.split("\n") if len(p.strip()) >= 45]
        if paras:
            base = trim_to_sentence(" ".join(paras[:3]), 420)
    if not base:
        base = trim_to_sentence(it.summary, 360)

    parts = [p for p in [base] if p]
    if it.recommendation and it.recommendation.lower() not in base.lower():
        parts.append(it.recommendation)
    return " ".join(parts).strip()


def format_telegram_messages(items: list[AlertItem], mode: str, now: datetime) -> list[str]:
    """Clean, spaced, 100% French local briefing when AI rewriting is unavailable."""
    fr_items = [x for x in items if x.lang == "fr"]
    skipped_en = len(items) - len(fr_items)
    active = fr_items if fr_items else items

    header = (
        f"<b>JOURNAL CYBER &amp; CLOUD · {now.strftime('%d/%m/%Y')}</b>\n"
        f"<i>Les {len(active)} faits majeurs à connaître aujourd'hui</i>"
    )

    rendered_items: list[str] = []
    for idx, it in enumerate(active, start=1):
        title_esc = html.escape(strip_emojis(it.title))
        src_esc = html.escape(it.source_name)
        body_esc = html.escape(_build_local_item_body(it))
        link_part = (
            f' (<a href="{html.escape(it.link, quote=True)}">Article complet</a>)'
            if it.link
            else ""
        )
        prefix = f"[{html.escape(it.severity)}] " if it.kind != "news" else ""
        rendered_items.append(
            f"<b>{idx}. {prefix}{title_esc}</b> ({src_esc})\n"
            f"{body_esc}{link_part}"
        )

    full_text = header + "\n\n\n" + "\n\n\n".join(rendered_items)
    if skipped_en > 0 and fr_items:
        full_text += (
            f"\n\n\n<i>Note : {skipped_en} article(s) anglophone(s) écarté(s) faute de synthèse IA disponible "
            f"(briefing maintenu 100 % en français).</i>"
        )
    return split_telegram_text(full_text)


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
    detail = _build_local_item_body(item)
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
        f"# Journal Cyber & Cloud ({now.strftime('%Y-%m-%d %H:%M UTC')})",
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


def run(
    mode: str,
    dry_run: bool,
    lookback_days: int | None,
    max_items: int | None,
    ignore_seen: bool = False,
) -> int:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    stack_kw: list[str] = config.get("stack_keywords", [])
    news_kw: list[str] = config.get("news_keywords", [])
    exclude_patterns: list[str] = config.get("exclude_patterns", [])
    days = lookback_days if lookback_days is not None else config.get("lookback_days_default", 4)
    cap = max_items if max_items is not None else config.get("max_items_per_run", 15)
    tg_cap = config.get("telegram_max_items", 5)
    tg_news = config.get("telegram_max_news", 3)
    tg_vulns = config.get("telegram_max_vulns", 2)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    state = load_state(STATE_PATH)
    seen_set = set() if ignore_seen else set(state.get("seen_ids", []))
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
                parsed = parse_rss_items(raw, source, stack_kw, cutoff, news_kw, exclude_patterns)
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

    print(
        f"[INFO] Grouped items: {len(grouped)} | Telegram Top briefing: {len(briefing_items)} "
        f"(dry_run={dry_run}, ignore_seen={ignore_seen})"
    )
    for it in briefing_items:
        print(f"  - [{it.severity} / {it.kind} / {it.lang}] {it.source_name}: {it.title} ({it.published})")

    if briefing_items:
        enrich_items_with_article_text(briefing_items)
        enriched_count = sum(1 for x in briefing_items if x.article_text)
        print(f"[OK] Full article text extracted for {enriched_count}/{len(briefing_items)} briefing item(s).")

    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    msgs: list[str] | None = None
    if briefing_items:
        if gemini_key:
            msgs = generate_gemini_briefing(briefing_items, mode, now, gemini_key)
        if not msgs:
            msgs = format_telegram_messages(briefing_items, mode, now)

    if dry_run:
        if msgs:
            print("[PREVIEW] Formatted Telegram output:")
            for i, m in enumerate(msgs, start=1):
                print(f"=== MESSAGE {i} ({len(m)} chars) ===")
                print(m)
                print("=== END MESSAGE ===")
        return 0

    write_digest(archive_items, mode, now, errors)

    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

    if msgs and tg_token and tg_chat:
        send_telegram(msgs, tg_token, tg_chat)
        print(f"[OK] Telegram: sent {len(msgs)} message(s).")
    elif briefing_items:
        print("[INFO] Telegram secrets not configured yet -> skipped Telegram notification.")

    notion_token = os.environ.get("NOTION_TOKEN", "").strip()
    notion_db = os.environ.get("NOTION_DATABASE_ID", "").strip()
    if archive_items and notion_token and notion_db:
        created = send_notion(archive_items, notion_token, notion_db)
        print(f"[OK] Notion: created {created}/{len(archive_items)} page(s).")

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
    parser.add_argument("--dry-run", action="store_true", help="Preview full briefing without sending or saving state")
    parser.add_argument("--ignore-seen", action="store_true", help="Ignore state/seen.json for this run")
    parser.add_argument("--lookback-days", type=int, default=None)
    parser.add_argument("--max-items", type=int, default=None)
    args = parser.parse_args()
    return run(args.mode, args.dry_run, args.lookback_days, args.max_items, args.ignore_seen)


if __name__ == "__main__":
    sys.exit(main())
