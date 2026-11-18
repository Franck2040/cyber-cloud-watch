# Cyber & Cloud Watch (v2 · Briefing Oral)

Veille automatisée **Cybersécurité & Pannes Cloud** à **0 €** (sans serveur), propulsée par **GitHub Actions**, livrée en **briefing digeste de 45 secondes sur Telegram** (prêt à raconter à l'oral), avec archivage optionnel **Notion** et digests Markdown dans `digests/`.

Conçu et maintenu par **Kenmeugne Calixte** (`Franck2040`).

## Nouveautés v2 (format digeste prêt à raconter)
- **Actus & attaques réelles** ajoutées : **IT-Connect Sécurité (FR)**, **CERT-FR Menaces & Incidents (CTI)**, **BleepingComputer** et **The Hacker News** (ransomwares, DDoS, fuites de données, cyberattaques).
- **Regroupement anti-spam** : plusieurs avis `noyau Linux` (Red Hat, Ubuntu, Debian, SUSE) sont fusionnés en **1 seule ligne claire**.
- **Nettoyage du jargon** : suppression du texte répétitif CISA (`BOD 26-04`) et reformulation directe `Fait / Risque / Réflexe`.
- **Top 6 équilibré max sur Telegram** (3 Actus/Attaques + 3 Failles/Pannes critiques = 1 seul message court, le reste est archivé dans `digests/latest.md` et Notion).
- **Mode Journaliste IA (optionnel, 0 €)** : ajoutez une clé gratuite `GEMINI_API_KEY` (Google AI Studio) dans GitHub Secrets pour que chaque briefing soit réécrit en français oral fluide prêt à raconter (avec repli automatique sur le formateur local sans clé).

## Limite honnête connue : Microsoft 365
Microsoft ne fournit plus de flux RSS public non authentifié pour Outlook/Teams/Copilot (`status.cloud.microsoft/m365/` est une application JS). En entreprise, brancher l'API **Microsoft Graph Service Health** (`ServiceHealth.Read.All`).

## Guide pas à pas (où cliquer exactement)

### 1. Secrets Telegram (obligatoire)
1. Dans **Telegram**, cliquez sur la **barre de recherche en haut**, tapez `@BotFather`, sélectionnez le compte officiel avec la coche bleue, puis cliquez **Démarrer** en bas.
2. Tapez `/newbot`, envoyez le nom d'affichage puis un identifiant finissant par `bot`, et copiez le token (`TELEGRAM_BOT_TOKEN`).
3. Cliquez sur le lien `t.me/<votre_bot>` dans le message de confirmation puis cliquez **Démarrer** en bas.
4. Retournez dans la **barre de recherche en haut de Telegram**, tapez `@userinfobot`, ouvrez le bot portant exactement `@UserInfoBot`, cliquez **Démarrer** et copiez le nombre en face de `Id:` (`TELEGRAM_CHAT_ID`).
5. Sur GitHub (`Franck2040/cyber-cloud-watch`), cliquez sur l'onglet **Settings** (en haut à droite), puis dans le menu de gauche **Security -> Secrets and variables -> Actions -> bouton vert New repository secret** et créez `TELEGRAM_BOT_TOKEN` et `TELEGRAM_CHAT_ID`.

### 2. Activer le mode « Journaliste IA » en français oral (optionnel, gratuit)
1. Ouvrez `https://aistudio.google.com/apikey` dans votre navigateur et connectez-vous avec votre compte Google.
2. Cliquez sur le bouton **Create API key** puis copiez la clé générée.
3. Dans GitHub -> **Settings -> Security -> Secrets and variables -> Actions -> New repository secret** :
   - Name : `GEMINI_API_KEY`
   - Secret : collez votre clé -> cliquez **Add secret**.

### 3. Tester immédiatement
Dans GitHub -> onglet **Actions** (en haut) -> menu gauche **Cyber & Cloud Daily Watch** -> menu déroulant **Run workflow** à droite -> bouton vert **Run workflow**.

## Tests locaux

```bash
python3 -m unittest discover -s tests -v
python3 src/watch.py --mode all --dry-run
```
