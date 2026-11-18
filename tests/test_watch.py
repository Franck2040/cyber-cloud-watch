from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import watch


class TestWatchEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)
        self.cutoff = self.now - timedelta(days=7)
        self.keywords = ["openssh", "windows", "azure", "fortinet"]

    def test_parse_rss_certfr_filtering(self) -> None:
        rss = b"""<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0"><channel>
          <item>
            <title>Multiples vulnerabilites dans OpenSSH</title>
            <link>https://cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-001/</link>
            <description>Execution de code arbitraire critique sur OpenSSH.</description>
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
            "default_severity": "HAUTE",
            "always_include": False,
        }
        items = watch.parse_rss_items(rss, source, self.keywords, self.cutoff)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].severity, "CRITIQUE")
        self.assertIn("openssh", items[0].matched_keywords)

    def test_parse_cisa_kev_date_cutoff(self) -> None:
        payload = json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-9999",
                        "vendorProject": "Fortinet",
                        "product": "FortiOS",
                        "vulnerabilityName": "Auth Bypass",
                        "dateAdded": "2026-11-16",
                        "shortDescription": "Critical bypass",
                        "requiredAction": "Patch immediately",
                        "knownRansomwareCampaignUse": "Known",
                    },
                    {
                        "cveID": "CVE-2022-0001",
                        "vendorProject": "OldVendor",
                        "product": "OldApp",
                        "vulnerabilityName": "Old Bug",
                        "dateAdded": "2022-01-01",
                        "shortDescription": "Old",
                        "requiredAction": "Patch",
                        "knownRansomwareCampaignUse": "Unknown",
                    },
                ]
            }
        ).encode("utf-8")
        source = {"id": "cisa-kev", "name": "CISA KEV", "mode": "cyber"}
        items = watch.parse_cisa_kev(payload, source, self.keywords, self.cutoff)
        self.assertEqual(len(items), 1)
        self.assertIn("CVE-2026-9999", items[0].title)
        self.assertEqual(items[0].severity, "CRITIQUE")

    def test_parse_statuspage_incidents(self) -> None:
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
        self.assertEqual(items[0].severity, "CRITIQUE")
        self.assertIn("MAJOR", items[0].title)

    def test_telegram_chunking_and_notion_payload(self) -> None:
        items = [
            watch.AlertItem(
                uid=f"id-{i}",
                source_id="certfr-alertes",
                source_name="CERT-FR Alertes",
                mode="cyber",
                severity="CRITIQUE",
                title=f"Alerte critique numero {i} <script>",
                summary="Details " + ("x" * 240),
                link=f"https://cert.cyber.gouv.fr/alerte/{i}",
                published="2026-11-18 09:00 UTC",
                matched_keywords=["windows"],
            )
            for i in range(20)
        ]
        msgs = watch.format_telegram_messages(items, "cyber", self.now)
        self.assertGreaterEqual(len(msgs), 2)
        for m in msgs:
            self.assertLessEqual(len(m), 4096)
            self.assertNotIn("<script>", m)

        notion_body = watch.build_notion_payload(items[0], "db-123")
        self.assertEqual(notion_body["parent"]["database_id"], "db-123")
        self.assertEqual(notion_body["properties"]["Priorité"]["select"]["name"], "CRITIQUE")

    def test_state_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "seen.json"
            watch.save_state(p, ["a", "b"], self.now)
            loaded = watch.load_state(p)
            self.assertEqual(loaded["seen_ids"], ["a", "b"])
            self.assertEqual(loaded["count"], 2)


if __name__ == "__main__":
    unittest.main()
