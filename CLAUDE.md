# CLAUDE.md — Graph'in Simple Security SSL

## Contexte
Plugin WordPress de sécurité pour les sites clients de l'agence Graph'in (Nantes). Contretype simplifié de Really Simple Security, sans options payantes. Un plugin autonome par site, mises à jour via GitHub.
**La spécification complète est dans `SPEC.md` : la lire avant toute tâche et la respecter.** En cas de doute ou de contradiction, poser la question plutôt que d'improviser.

## Langue
- Échanges, commentaires de code et interface : français.
- Noms de fonctions, variables, classes : anglais.

## Méthode de travail
1. Avant de coder un module : proposer un plan court (fichiers créés/modifiés, hooks utilisés) et attendre validation.
2. Développer un module à la fois, dans l'ordre du plan de développement ci-dessous.
3. Après chaque module : lancer PHPCS, lister les tests manuels à faire dans l'environnement local, mettre à jour `CHANGELOG.md`.
4. Commits atomiques, messages en français, format `type(module): description` (ex. `feat(ssl): redirection 301 via .htaccess`).

## Architecture
```
graphin-simple-security-ssl/
├── graphin-simple-security-ssl.php   # en-tête plugin, constantes, bootstrap, GSSS_AGENCY_EMAIL
├── uninstall.php
├── includes/
│   ├── class-plugin.php               # chargement des modules, activation/désactivation
│   ├── class-settings.php             # lecture/écriture options (une seule option `gsss_settings`, tableau)
│   ├── class-htaccess.php             # écriture sécurisée : sauvegarde, marqueurs, test HTTP, rollback
│   ├── class-mailer.php               # alertes email (agence + client optionnel)
│   ├── class-logger.php               # table gsss_log
│   ├── class-crypto.php               # AES-256-GCM, clé dérivée des salts WP
│   └── modules/
│       ├── class-module.php           # classe abstraite : is_enabled(), register_hooks(), htaccess_rules(), nginx_rules()
│       ├── class-ssl.php
│       ├── class-headers.php
│       ├── class-vulnerabilities.php
│       ├── class-hardening.php
│       └── class-login.php            # limitation tentatives, URL perso, 2FA
├── admin/
│   ├── class-admin.php                # menus, pages, AJAX
│   └── views/                         # une vue PHP par page
├── assets/
│   ├── admin.css                      # variables CSS charte Graph'in
│   ├── admin.js                       # vanilla JS
│   └── qrcode.min.js                  # QR code local pour la 2FA
├── vendor/plugin-update-checker/      # YahnisElsts PUC v5
├── languages/
├── .github/workflows/release.yml      # build du zip + asset de release sur tag vX.Y.Z
├── .distignore                        # fichiers exclus du zip
├── CHANGELOG.md
└── SPEC.md
```

## Règles de code
- Préfixe `gsss_` partout (options, hooks, transients, crons, tables, meta). Namespace `Graphin\SimpleSecurity`.
- Toute action admin : `check_admin_referer()` / `check_ajax_referer()` + `current_user_can( 'manage_options' )`.
- Sortie : `esc_html()`, `esc_attr()`, `esc_url()`, `wp_kses_post()`. Entrée : `sanitize_*()`, `absint()`.
- SQL : `$wpdb->prepare()` uniquement.
- Aucune option n'agit tant qu'elle n'est pas cochée. Rien n'est appliqué à l'activation du plugin.
- Toute écriture `.htaccess` passe par `class-htaccess.php` (sauvegarde → écriture entre marqueurs → test HTTP accueil → rollback si échec).
- `GSSS_SAFE_MODE` vérifié en tout premier dans le bootstrap : si `true`, aucun module ne s'enregistre et un bandeau admin s'affiche.
- Chaque module fournit ses règles en deux versions : Apache (`htaccess_rules()`) et PHP/Nginx (`register_hooks()` + `nginx_rules()` pour le snippet à copier).
- Pas de dépendance Composer en production hors PUC ; pas de framework JS ; pas d'appel à des CDN.
- Requêtes sortantes autorisées uniquement : `www.wpvulnerability.net`, `www.wordfence.com` (si clé), `api.github.com` / `github.com` (mises à jour).
- Compatibilité PHP 7.4 : pas de `match`, pas de types union, pas de propriétés `readonly`.

## Environnement de développement
- Poste : macOS.
- Environnement WordPress local : `@wordpress/env` (wp-env, nécessite Docker). Si Docker est absent, le signaler et proposer LocalWP à la place.
- Qualité : `composer require --dev wp-coding-standards/wpcs` puis `vendor/bin/phpcs --standard=WordPress`.
- Tester aussi avec le thème Enfold quand un zip est fourni dans `/dev/themes/` (ne jamais committer ce dossier).

## Plan de développement
1. Squelette : bootstrap, constantes, settings, classe module abstraite, safe mode, menu admin vide, PUC branché.
2. `class-htaccess.php` + journal + mailer (socle commun).
3. Module SSL.
4. Module En-têtes (dont CSP report-only et endpoint REST).
5. Module Durcissement.
6. Module Connexion : limitation de tentatives → URL personnalisée → 2FA.
7. Module Vulnérabilités (WPVulnerability puis Wordfence v3 optionnel).
8. Tableau de bord, score, « Appliquer les réglages recommandés », export/import.
9. `uninstall.php`, GitHub Action de release, `.distignore`, recette complète (SPEC §9).

## Publication
- Dépôt GitHub public. URL du dépôt à demander à Guillaume à l'étape 1 et à renseigner dans l'initialisation de PUC.
- Version incrémentée dans l'en-tête du plugin ET dans `GSSS_VERSION`, entrée `CHANGELOG.md`, puis tag `vX.Y.Z`.
