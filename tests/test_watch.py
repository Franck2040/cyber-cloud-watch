from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import watch


class TestWatchEngineV2(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)
        self.cutoff = self.now - timedelta(days=7)
        self.keywords = ["openssh", "windows", "azure", "fortinet", "linux"]
        self.news_keywords = ["ransomware", "ddos", "banque", "bank", "france"]

    def test_parse_rss_certfr_and_clean_risk(self) -> None:
        rss = b"""<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0"><channel>
          <item>
            <title>Multiples vulnerabilites dans OpenSSH</title>
            <link>https://cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-001/</link>
            <description>De multiples vulnerabilites ont ete decouvertes dans OpenSSH. Elles permettent une execution de code arbitraire a distance et une elevation de privileges.</description>
            <pubDate>Tue, 17 Nov 2026 08:00:00 +0000</pubDate>
          </item>
          <item>
            <title>Faille mineure dans un outil inconnu</title>
            <link>https://cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-002/</link>
            <description>Produit hors stack.</description>
            <pubDate>Tue, 17 Nov 2026 08:00:00 +0000</pubDate>
          </item>
        </channel></rss>"""
        source = {
            "id": "certfr-avis",
            "name": "CERT-FR Avis",
            "mode": "cyber",
            "kind": "vuln",
            "default_severity": "HAUTE",
            "always_include": False,
        }
        items = watch.parse_rss_items(rss, source, self.keywords, self.cutoff)
        self.assertEqual(len(items), 1)
        self.assertIn("prise de contrôle", items[0].summary)

    def test_group_linux_kernel_advisories(self) -> None:
        items = [
            watch.AlertItem(
                uid=f"linux-{i}",
                source_id="certfr-avis",
                source_name="CERT-FR Avis (ANSSI)",
                mode="cyber",
                kind="vuln",
                severity="CRITIQUE",
                title=f"Multiples vulnérabilités dans le noyau Linux de {distro} (13 novembre 2026)",
                summary="Risque : élévation de privilèges.",
                link=f"https://cert.cyber.gouv.fr/avis/{i}",
                published="2026-11-13 00:00 UTC",
            )
            for i, distro in enumerate(["Red Hat", "Ubuntu", "Debian", "SUSE"])
        ]
        grouped = watch.group_related_items(items)
        self.assertEqual(len(grouped), 1)
        self.assertIn("Red Hat, Ubuntu, Debian, SUSE", grouped[0].title)
        self.assertEqual(len(grouped[0].grouped_uids), 4)

    def test_parse_cisa_kev_strips_bod_boilerplate(self) -> None:
        payload = json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-9999",
                        "vendorProject": "Fortinet",
                        "product": "FortiOS",
                        "vulnerabilityName": "Auth Bypass",
                        "dateAdded": "2026-11-16",
                        "shortDescription": "FortiOS allows remote auth bypass.",
                        "requiredAction": "Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA's BOD 26-04 guidance.",
                        "knownRansomwareCampaignUse": "Known",
                    }
                ]
            }
        ).encode("utf-8")
        source = {"id": "cisa-kev", "name": "CISA KEV", "mode": "cyber", "kind": "vuln"}
        items = watch.parse_cisa_kev(payload, source, self.keywords, self.cutoff)
        self.assertEqual(len(items), 1)
        self.assertNotIn("BOD 26-04", items[0].recommendation)
        self.assertIn("ransomware", items[0].recommendation.lower())

    def test_balanced_top6_briefing(self) -> None:
        news = [
            watch.AlertItem(
                uid=f"news-{i}",
                source_id="it-connect-secu",
                source_name="IT-Connect Sécurité",
                mode="cyber",
                kind="news",
                severity="ACTU CLÉ",
                title=f"Cyberattaque DDoS banque #{i}",
                summary="Attaque DDoS ciblant des services en ligne.",
                link=f"https://example.com/news/{i}",
                published="2026-11-18 08:00 UTC",
                recommendation="Surveiller les filtres anti-DDoS.",
            )
            for i in range(5)
        ]
        vulns = [
            watch.AlertItem(
                uid=f"vuln-{i}",
                source_id="certfr-avis",
                source_name="CERT-FR",
                mode="cyber",
                kind="vuln",
                severity="CRITIQUE",
                title=f"Faille critique #{i}",
                summary="Risque : RCE.",
                link=f"https://example.com/vuln/{i}",
                published="2026-11-18 07:00 UTC",
                recommendation="Patcher.",
            )
            for i in range(5)
        ]
        selected = watch.select_balanced_briefing(news + vulns, max_total=6, max_news=3, max_vulns=3)
        self.assertEqual(len(selected), 6)
        self.assertEqual(sum(1 for x in selected if x.kind == "news"), 3)
        self.assertEqual(sum(1 for x in selected if x.kind == "vuln"), 3)

        msgs = watch.format_telegram_messages(selected, "all", self.now)
        self.assertEqual(len(msgs), 1)
        self.assertIn("ACTUS &amp; ATTAQUES", msgs[0])
        self.assertIn("FAILLES &amp; PANNES CRITIQUES", msgs[0])

    def test_parse_statuspage_and_state(self) -> None:
        payload = json.dumps(
            {
                "incidents": [
                    {
                        "id": "inc-123",
                        "name": "Degraded GitHub Actions",
                        "status": "investigating",
                        "impact": "major",
                        "shortlink": "https://stspg.io/abc",
                        "updated_at": "2026-11-18T09:30:00Z",
                        "incident_updates": [{"body": "Investigating delayed workflow runs."}],
                    }
                ]
            }
        ).encode("utf-8")
        source = {"id": "github-status", "name": "GitHub Status", "mode": "cloud", "url": "https://www.githubstatus.com"}
        items = watch.parse_statuspage(payload, source, self.keywords, self.cutoff)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].kind, "cloud")

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "seen.json"
            watch.save_state(p, ["a", "b"], self.now)
            loaded = watch.load_state(p)
            self.assertEqual(loaded["seen_ids"], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
