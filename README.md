# Cyber & Cloud Watch

Veille automatisée **Cybersécurité & Pannes Cloud** à **0 €** (sans serveur à maintenir), propulsée par **GitHub Actions**, avec alertes **Telegram**, archivage optionnel **Notion** et digests Markdown versionnés dans `digests/`.

Conçu et maintenu par **Kenmeugne Calixte** (`Franck2040`).

## Architecture

```
Sources officielles (RSS / JSON)
  ├── CERT-FR Alertes & Avis (ANSSI · cert.cyber.gouv.fr)
  ├── CISA KEV (vulnérabilités activement exploitées)
  ├── Microsoft Azure Status (RSS officiel)
  ├── GitHub Status (API incidents non résolus)
  └── Cloudflare Status (API incidents non résolus)
           │
           ▼
   src/watch.py (Python 3.12 stdlib, zéro dépendance)
   ├── Filtrage par stack technique (config/sources.json)
   ├── Priorisation automatique (CRITIQUE / HAUTE / INFO)
   └── Dédoublonnage persistant (state/seen.json)
           │
           ├──▶ Telegram Bot (alertes mobiles instantanées)
           ├──▶ Notion Database (archivage optionnel)
           └──▶ digests/latest.md (journal versionné GitHub)
```

## Fréquence d'exécution (GitHub Actions)

| Workflow | Fréquence | Rôle |
| :--- | :--- | :--- |
| `cyber-watch.yml` | 2x / jour (05:30 UTC et 17:00 UTC) + manuel | Veille CERT-FR + CISA KEV + Cloud, tests unitaires inclus |
| `cloud-outage-watch.yml` | Toutes les 30 min (lun–ven, 07:00–18:30 UTC) + manuel | Détection rapide des pannes Cloud (Azure, GitHub, Cloudflare) |

## Limite honnête connue : Microsoft 365 (Outlook / Teams / Copilot)
Microsoft ne publie plus de flux RSS public non authentifié pour l'état de santé Microsoft 365 :
- Page publique officielle (application JS) : `https://status.cloud.microsoft/m365/`
- Pour des alertes M365 automatiques par tenant en entreprise (stage / alternance), l'extension prévue consiste à brancher l'API **Microsoft Graph Service Health** (`ServiceHealth.Read.All`) via un enregistrement d'application Entra ID.

## Comment je mets cela en place ? (3 minutes)

### 1. Activer les alertes Telegram (gratuit)
1. Dans Telegram, ouvrir `@BotFather` et envoyer `/newbot`.
2. Choisir un nom (ex. `Cyber Cloud Watch`) et un username finissant par `bot` -> copier le **token** (`TELEGRAM_BOT_TOKEN`).
3. Ouvrir le nouveau bot et lui envoyer `/start` (obligatoire pour qu'il puisse vous écrire).
4. Récupérer votre identifiant numérique (`TELEGRAM_CHAT_ID`) via `@userinfobot` (ou en ouvrant `https://api.telegram.org/bot<VOTRE_TOKEN>/getUpdates` dans un navigateur).
5. Dans ce dépôt GitHub : **Settings -> Secrets and variables -> Actions -> New repository secret** :
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_CHAT_ID`

### 2. Activer l'archivage Notion (optionnel)
Si ces secrets ne sont pas renseignés, la veille fonctionne normalement sur Telegram + Markdown sans erreur.
1. Créer une intégration interne sur `https://www.notion.so/profile/integrations` -> copier le secret (`NOTION_TOKEN`).
2. Créer une base Notion avec les propriétés suivantes :
   - `Titre` (Title)
   - `Source` (Select)
   - `Catégorie` (Select)
   - `Priorité` (Select)
   - `Lien` (URL)
   - `Date` (Date)
3. Partager cette base avec votre intégration (`... -> Connections`) et copier son ID (`NOTION_DATABASE_ID`).
4. Ajouter `NOTION_TOKEN` et `NOTION_DATABASE_ID` dans **GitHub Repository Secrets**.

### 3. Lancer et tester immédiatement
Dans l'onglet **Actions** de GitHub :
1. Cliquer sur **Cyber & Cloud Daily Watch**.
2. Cliquer sur **Run workflow** (laisser `dry_run: false` pour recevoir la première alerte Telegram et générer `digests/latest.md`).

## Tests locaux

```bash
python3 -m unittest discover -s tests -v
python3 src/watch.py --mode all --dry-run
```
