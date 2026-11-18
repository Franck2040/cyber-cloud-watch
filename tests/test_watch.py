from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import watch


class TestWatchEngineV3(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)
        self.cutoff = self.now - timedelta(days=7)
        self.keywords = ["openssh", "windows", "azure", "fortinet", "linux", "java"]
        self.news_keywords = ["ransomware", "ddos", "banque", "bank", "cyberattaque", "fuite"]
        self.excludes = ["weekly recap", "gta 6", "ps5", "xbox"]

    def test_strip_emojis_and_wordpress_footer_and_clean_sentence_trim(self) -> None:
        raw = "⚡ Weekly test: Une faille critique touche Java. Le correctif est disponible. Le post Test est apparu en premier sur IT-Connect. [...]"
        cleaned = watch.strip_html(raw)
        self.assertNotIn("⚡", cleaned)
        self.assertNotIn("est apparu en premier sur", cleaned)
        self.assertNotIn("[...]", cleaned)

        trimmed = watch.trim_to_sentence(
            "Première phrase complète sur une cyberattaque bancaire. Deuxième phrase expliquant la faille exploitée. Troisième phrase très longue qui dépasse largement la limite autorisée.",
            max_chars=125,
        )
        self.assertTrue(trimmed.endswith("."))
        self.assertNotIn("largement", trimmed)

    def test_excludes_weekly_recap_and_gta6_fluff(self) -> None:
        rss = b"""<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0"><channel>
          <item>
            <title>&#9889; Weekly Recap: Windows 0-Days and More Bad Days</title>
            <link>https://example.com/recap</link>
            <description>A default password opened doors.</description>
            <pubDate>Wed, 18 Nov 2026 08:00:00 +0000</pubDate>
          </item>
          <item>
            <title>GTA 6 : la Nouvelle-Zelande jouera 12 heures avant la France, attention aux arnaques</title>
            <link>https://example.com/gta6</link>
            <description>Astuce sur Xbox et PS5.</description>
            <pubDate>Wed, 18 Nov 2026 08:00:00 +0000</pubDate>
          </item>
          <item>
            <title>Cyberattaque : Air France et IKEA touches par un script malveillant</title>
            <link>https://example.com/airfrance</link>
            <description>Plusieurs grands sites ont diffuse un script malveillant suite a la compromission d'un prestataire.</description>
            <pubDate>Wed, 18 Nov 2026 09:00:00 +0000</pubDate>
          </item>
        </channel></rss>"""
        source = {
            "id": "it-connect-secu",
            "name": "IT-Connect",
            "lang": "fr",
            "mode": "cyber",
            "kind": "news",
            "default_severity": "ACTU",
            "always_include": True,
        }
        items = watch.parse_rss_items(rss, source, self.keywords, self.cutoff, self.news_keywords, self.excludes)
        self.assertEqual(len(items), 1)
        self.assertIn("Air France", items[0].title)
        self.assertEqual(items[0].severity, "ACTU CLÉ")

    def test_extract_article_text_from_html(self) -> None:
        html_doc = """
        <html><body>
          <nav><p>Menu Accueil Contact Cookies Accepter</p></nav>
          <article>
            <h2>Ce qui s'est passe</h2>
            <p>Une faille critique baptisee Java4Shell (CVE-2026-114938) affecte OpenJDK et Oracle Java SE dans plusieurs entreprises.</p>
            <p>Les attaquants peuvent executer du code a distance sans authentification. Les equipes doivent deployer la mise a jour de novembre 2026.</p>
          </article>
          <footer><p>Tous droits reserves - Politique de confidentialite et cookies.</p></footer>
        </body></html>
        """
        extracted = watch.extract_article_text_from_html(html_doc)
        self.assertIn("Java4Shell", extracted)
        self.assertIn("CVE-2026-114938", extracted)
        self.assertNotIn("Menu Accueil", extracted)
        self.assertNotIn("Politique de confidentialite", extracted)

    def test_newest_first_sorting_and_cross_source_dedup(self) -> None:
        older = watch.AlertItem(
            uid="old-1",
            source_id="it-connect-secu",
            source_name="IT-Connect",
            mode="cyber",
            kind="news",
            severity="ACTU CLÉ",
            title="Ancienne cyberattaque du 15 novembre",
            summary="Details anciens.",
            link="https://example.com/old",
            published="2026-11-15 08:00 UTC",
            lang="fr",
            published_ts=datetime(2026, 11, 15, 8, 0, tzinfo=timezone.utc).timestamp(),
        )
        newer_fr = watch.AlertItem(
            uid="new-fr",
            source_id="it-connect-secu",
            source_name="IT-Connect",
            mode="cyber",
            kind="news",
            severity="ACTU CLÉ",
            title="Faille critique Java4Shell (CVE-2026-114938) sur OpenJDK",
            summary="Execution de code a distance.",
            link="https://example.com/fr-java",
            published="2026-11-18 09:00 UTC",
            lang="fr",
            published_ts=datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc).timestamp(),
        )
        newer_en_dup = watch.AlertItem(
            uid="new-en",
            source_id="bleepingcomputer",
            source_name="BleepingComputer",
            mode="cyber",
            kind="news",
            severity="ACTU CLÉ",
            title="Critical Java4Shell flaw (CVE-2026-114938) hits Java apps",
            summary="Remote code execution.",
            link="https://example.com/en-java",
            published="2026-11-18 09:00 UTC",
            lang="en",
            published_ts=datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc).timestamp(),
        )
        selected = watch.select_balanced_briefing([older, newer_en_dup, newer_fr], max_total=5, max_news=3, max_vulns=2)
        self.assertEqual(len(selected), 2)
        self.assertEqual(selected[0].uid, "new-fr")
        self.assertEqual(selected[1].uid, "old-1")

    def test_local_fallback_is_100_percent_french_and_double_spaced(self) -> None:
        fr1 = watch.AlertItem(
            uid="fr-1",
            source_id="it-connect-secu",
            source_name="IT-Connect",
            mode="cyber",
            kind="news",
            severity="ACTU CLÉ",
            title="Fuite de donnees chez Maileva (La Poste)",
            summary="Les noms et adresses de 22 millions de personnes ont ete derobes.",
            link="https://example.com/maileva",
            published="2026-11-17 19:00 UTC",
            lang="fr",
        )
        fr2 = watch.AlertItem(
            uid="fr-2",
            source_id="certfr-alertes",
            source_name="CERT-FR Alertes",
            mode="cyber",
            kind="vuln",
            severity="CRITIQUE",
            title="Vulnerabilite critique dans Oracle Java SE",
            summary="Permet une prise de controle a distance.",
            link="https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-01/",
            published="2026-11-18 08:00 UTC",
            lang="fr",
            recommendation="Appliquer le correctif Oracle de novembre 2026.",
        )
        en_only = watch.AlertItem(
            uid="en-1",
            source_id="bleepingcomputer",
            source_name="BleepingComputer",
            mode="cyber",
            kind="news",
            severity="ACTU CLÉ",
            title="English story that should not leak in local French fallback",
            summary="Some English text.",
            link="https://example.com/en",
            published="2026-11-18 09:00 UTC",
            lang="en",
        )
        msgs = watch.format_telegram_messages([fr1, fr2, en_only], "all", self.now)
        self.assertEqual(len(msgs), 1)
        body = msgs[0]
        self.assertIn("Maileva", body)
        self.assertIn("Oracle Java SE", body)
        self.assertNotIn("English story", body)
        self.assertNotIn("À retenir pour ta veille", body)
        self.assertIn("\n\n\n<b>2.", body)
        self.assertIn('(<a href="https://example.com/maileva">Article complet</a>)', body)

    def test_clean_gemini_output_enforces_spacing_and_strips_fences_and_emojis(self) -> None:
        raw = (
            "```html\n"
            "<b>JOURNAL CYBER &amp; CLOUD · 18/11/2026</b>\n"
            "<i>Les 2 faits majeurs</i>\n"
            "<b>1. ⚡ Premier sujet</b> (IT-Connect)\n"
            "Texte clair — sans détour. (<a href=\"https://example.com/1\">Article complet</a>)\n"
            "<b>2. Deuxième sujet</b> (CERT-FR)\n"
            "Second texte clair. (<a href=\"https://example.com/2\">Article complet</a>)\n"
            "```"
        )
        cleaned = watch.clean_gemini_telegram_output(raw)
        self.assertNotIn("```", cleaned)
        self.assertNotIn("⚡", cleaned)
        self.assertNotIn("—", cleaned)
        self.assertIn("\n\n\n<b>2.", cleaned)

    def test_group_linux_kernel_and_cisa_kev_and_state(self) -> None:
        items = [
            watch.AlertItem(
                uid=f"linux-{i}",
                source_id="certfr-avis",
                source_name="CERT-FR Avis",
                mode="cyber",
                kind="vuln",
                severity="CRITIQUE",
                title=f"Multiples vulnérabilités dans le noyau Linux de {distro} (13 novembre 2026)",
                summary="Élévation de privilèges.",
                link=f"https://cert.cyber.gouv.fr/avis/{i}",
                published="2026-11-13 00:00 UTC",
                lang="fr",
                published_ts=1763000000 + i,
            )
            for i, distro in enumerate(["Red Hat", "Ubuntu", "Debian", "SUSE"])
        ]
        grouped = watch.group_related_items(items)
        self.assertEqual(len(grouped), 1)
        self.assertIn("Red Hat, Ubuntu, Debian, SUSE", grouped[0].title)

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
        kev = watch.parse_cisa_kev(payload, {"id": "cisa-kev", "name": "CISA KEV", "mode": "cyber", "kind": "vuln", "lang": "en"}, self.keywords, self.cutoff)
        self.assertEqual(len(kev), 1)
        self.assertNotIn("BOD 26-04", kev[0].recommendation)
        self.assertIn("rançongiciel", kev[0].recommendation.lower())

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "seen.json"
            watch.save_state(p, ["a", "b"], self.now)
            self.assertEqual(watch.load_state(p)["seen_ids"], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
