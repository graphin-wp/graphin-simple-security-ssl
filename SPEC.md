# Cahier des charges — Graph'in Simple Security SSL

Plugin WordPress de sécurité, marque Graph'in, installé de façon autonome sur chaque site client.
Objectif : couvrir l'essentiel de Really Simple Security (version gratuite + options devenues payantes utiles), sans upsell, sans compte externe obligatoire, avec mises à jour automatiques depuis GitHub.

---

## 1. Identité technique

| Élément | Valeur |
|---|---|
| Nom affiché | Graph'in Simple Security SSL |
| Slug / dossier | `graphin-simple-security-ssl` |
| Fichier principal | `graphin-simple-security-ssl.php` |
| Text domain | `graphin-simple-security-ssl` |
| Préfixe fonctions / options / hooks | `gsss_` |
| Namespace PHP | `Graphin\SimpleSecurity` |
| Constantes | `GSSS_VERSION`, `GSSS_PATH`, `GSSS_URL`, `GSSS_FILE` |
| Compatibilité | WordPress 6.2+, PHP 7.4+ (testé jusqu'à PHP 8.3) |
| Licence | GPL-2.0-or-later |
| Auteur | Graph'in — Guillaume Néel |
| Langue de l'interface | Français (chaînes traduisibles via `__()`) |

---

## 2. Principes non négociables

1. **Tout est désactivable** : chaque option est une case à cocher, désactivée par défaut sauf mention contraire. Aucune action n'est appliquée à l'activation du plugin.
2. **Jamais de site cassé ni d'admin enfermé dehors** :
   - constante de secours `define( 'GSSS_SAFE_MODE', true );` dans `wp-config.php` → le plugin n'applique plus aucune règle (ni PHP, ni .htaccess) et affiche un bandeau dans l'admin ;
   - toute écriture dans `.htaccess` est précédée d'une sauvegarde (`.htaccess.gsss-backup`) et suivie d'un test HTTP de la page d'accueil ; si le test échoue (code ≥ 500 ou erreur), restauration automatique ;
   - la désactivation du plugin retire toutes ses règles `.htaccess` (bloc entre marqueurs) et restaure l'URL de connexion standard.
3. **Aucune dépendance payante, aucun service tiers obligatoire.** Les seules requêtes sortantes : WPVulnerability.net (vulnérabilités), Wordfence Intelligence v3 (optionnel, si clé renseignée), GitHub (mises à jour).
4. **Sécurité du code** : nonces + `current_user_can( 'manage_options' )` sur toutes les actions, échappement systématique en sortie, sanitation en entrée, requêtes SQL préparées, pas d'`eval`, pas de code distant exécuté.
5. **Léger** : aucun chargement d'assets côté front ; assets admin chargés uniquement sur les pages du plugin.

---

## 3. Mode serveur (réglage Général)

Choix unique (bouton radio) :
- **Apache (.htaccess)** — par défaut. Les règles serveur sont écrites dans `.htaccess` entre les marqueurs `# BEGIN Graphin Simple Security` / `# END Graphin Simple Security` via `insert_with_markers()`.
- **Autre serveur (Nginx, etc.)** — aucune écriture `.htaccess`. Les en-têtes et redirections passent par PHP (`send_headers`, `template_redirect`). Les règles impossibles en PHP (blocage PHP dans uploads, listing de répertoires) sont affichées sous forme de snippet Nginx à copier, avec un bouton « Copier ».

Si le mode Apache est choisi mais `.htaccess` n'est pas inscriptible : avertissement + bascule automatique des règles possibles en PHP.

---

## 4. Modules

### 4.1 Général
- Choix du mode serveur (§3).
- **Tableau de bord** : score de sécurité (pourcentage d'options recommandées actives), liste « À faire » avec lien direct vers l'option concernée, état du certificat SSL, date du dernier scan de vulnérabilités, version du plugin et disponibilité d'une mise à jour.
- **Alertes email** :
  - adresse agence : constante `GSSS_AGENCY_EMAIL` définie dans le fichier principal du plugin (valeur fixée par Graph'in au build), modifiable dans les réglages par un administrateur ;
  - case « Envoyer aussi les alertes au client » + champ email client (pré-rempli avec `admin_email`) ;
  - envoi via `wp_mail()` (compatible avec le SMTP déjà configuré sur le site) ;
  - bouton « Envoyer un email de test ».
- **Export / import** des réglages en JSON (pour dupliquer une configuration type d'un site client à l'autre).
- **Journal** : 200 derniers événements (option activée/désactivée, blocage IP, connexion 2FA, alerte envoyée), table personnalisée `{prefix}gsss_log`, purge automatique au-delà de 200 lignes.

### 4.2 SSL
- **Détection** : vérifie qu'un certificat valide répond sur `https://` + domaine (requête `wp_remote_get` avec vérification SSL). Bouton « Activer le SSL » grisé tant que la détection échoue, avec message explicatif.
- **Activer le SSL** :
  - passe `home` et `siteurl` en `https://` ;
  - redirection 301 HTTP → HTTPS (`.htaccess` en mode Apache, sinon PHP) ;
  - option : redirection `www` ↔ sans `www` (choix : aucune / forcer www / forcer sans www).
- **Correcteur de contenu mixte** (case) : tampon de sortie sur le front qui remplace `http://` + domaine du site par `https://` (src, href, srcset, url() CSS inline), sans toucher aux liens externes.
- **Correcteur de contenu mixte dans l'admin** (case séparée, désactivée par défaut).
- **HSTS** (case) : `Strict-Transport-Security: max-age=31536000` ; sous-options `includeSubDomains` et `preload`, chacune avec un avertissement clair (preload = engagement long terme).
- **Désactivation propre** : bouton « Revenir en HTTP » qui retire redirections et HSTS (avec avertissement : le HSTS déjà reçu par les navigateurs reste actif jusqu'à expiration).

### 4.3 En-têtes de sécurité
Chaque en-tête = une case, avec description courte en français :
- `X-Content-Type-Options: nosniff` (recommandé)
- `X-Frame-Options: SAMEORIGIN` (recommandé)
- `Referrer-Policy: strict-origin-when-cross-origin` (recommandé ; liste déroulante des autres valeurs)
- `Permissions-Policy` : cases par fonctionnalité (caméra, micro, géolocalisation, paiement, USB…), valeur par défaut `camera=(), microphone=(), geolocation=(), payment=(), usb=()`
- `Cross-Origin-Opener-Policy: same-origin` (désactivé par défaut, avertissement compatibilité)
- `X-XSS-Protection: 0` (bonne pratique moderne : désactive l'ancien filtre)
- **Content-Security-Policy** :
  - mode « Rapport seulement » (`Content-Security-Policy-Report-Only`) par défaut à l'activation ;
  - endpoint REST interne `gsss/v1/csp-report` qui stocke les 100 derniers rapports (dédoublonnés par directive + domaine) ;
  - tableau des domaines bloqués avec bouton « Autoriser » qui les ajoute à la politique ;
  - bouton « Passer en mode appliqué » une fois les rapports vides ;
  - politique de départ compatible WordPress/Enfold (`'self'`, `'unsafe-inline'` pour scripts et styles, `data:` pour images et polices).
- Bouton **« Tester les en-têtes »** : requête sur la page d'accueil et affichage des en-têtes réellement renvoyés (vert = présent, rouge = absent).
- En mode Apache, les en-têtes sont écrits dans `.htaccess` via `mod_headers` (avec `<IfModule mod_headers.c>`), sinon via PHP.

### 4.4 Vulnérabilités
- **Source par défaut : WPVulnerability.net** (gratuit, sans clé). Une requête par plugin, par thème et pour le cœur WordPress ; envoi uniquement des slugs et numéros de version.
- **Source optionnelle : Wordfence Intelligence v3** (champ « Clé API Wordfence », stockée chiffrée AES-256-GCM avec une clé dérivée des salts WordPress). Si renseignée, les deux sources sont croisées.
- **Scan quotidien** via WP-Cron (`gsss_daily_vuln_scan`), + bouton « Scanner maintenant ». Mise en cache des réponses 12 h (transients). Délai entre requêtes pour ne pas surcharger le service gratuit ; en cas d'échec, nouvel essai progressif (15 min → 1 h → 24 h).
- **Résultats** : tableau composant / version installée / gravité (critique, élevée, moyenne, faible) / description courte / version corrigée / lien vers l'avis.
- **Alerte email** uniquement pour les **nouvelles** vulnérabilités (pas de répétition quotidienne de la même alerte) ; seuil de gravité minimal réglable (par défaut : moyenne).
- **Notice admin** rouge sur le tableau de bord WordPress si une vulnérabilité critique ou élevée est présente.
- **Option** (case, désactivée par défaut) : mise à jour automatique d'un plugin vulnérable si une version corrigée est disponible sur wordpress.org.
- **Option** : signaler les plugins installés fermés sur wordpress.org (abandonnés ou retirés).

### 4.5 Durcissement
Chaque mesure = une case :
- Désactiver XML-RPC (recommandé)
- Désactiver l'éditeur de fichiers dans l'admin (`DISALLOW_FILE_EDIT`, défini via filtre, sans modifier `wp-config.php`) (recommandé)
- Bloquer l'énumération des utilisateurs : `?author=N` → 404, endpoint REST `/wp/v2/users` réservé aux utilisateurs connectés (recommandé)
- Masquer la version de WordPress (meta generator, flux RSS, `?ver=` des scripts et styles du cœur)
- Messages d'erreur de connexion génériques (« Identifiants incorrects ») (recommandé)
- Bloquer l'exécution de fichiers PHP dans `/wp-content/uploads/` (`.htaccess` dédié dans uploads en mode Apache ; snippet sinon) (recommandé)
- Désactiver le listing des répertoires (`Options -Indexes`)
- Protéger `wp-config.php`, `.htaccess`, `readme.html`, `license.txt`, `debug.log` contre l'accès direct
- Désactiver les mots de passe d'application
- Interdire les noms d'utilisateur `admin`, `administrator`, `administrateur` à la création, avec signalement si un compte existant porte ce nom
- Désactiver l'ajout du lien « Inscription » si les inscriptions sont ouvertes avec un rôle par défaut autre qu'« Abonné » (alerte)
- Désactiver les pingbacks entrants

### 4.6 Connexion
- **Limitation des tentatives** (case, recommandé) :
  - réglages : nombre d'essais (défaut 5), fenêtre (défaut 15 min), durée de blocage (défaut 30 min, doublée à chaque récidive, plafonnée à 24 h) ;
  - comptage par IP (en tenant compte de `X-Forwarded-For` uniquement si l'option « Site derrière un proxy / CDN » est cochée) ;
  - liste blanche d'IP (pré-remplie avec l'IP de l'admin qui active l'option) ;
  - liste des IP bloquées avec bouton « Débloquer » ;
  - table `{prefix}gsss_login_attempts`, purge automatique quotidienne.
- **URL de connexion personnalisée** (case) :
  - champ slug (ex. `acces-graphin`) ; `wp-login.php` et `/wp-admin` pour un visiteur non connecté → 404 ;
  - email automatique de la nouvelle URL à l'adresse agence et à l'admin au moment de l'activation ;
  - récupération : constante `GSSS_SAFE_MODE` ou renommage du dossier du plugin.
- **Double authentification (2FA)** :
  - méthode principale : application TOTP (RFC 6238, 6 chiffres, 30 s), implémentée localement, QR code généré localement en JS (aucun secret envoyé à un service tiers) ;
  - méthode de secours : code à 6 chiffres envoyé par email (valable 10 min) ;
  - 10 codes de récupération à usage unique, affichés une seule fois, stockés hachés ;
  - activation par l'utilisateur dans son profil ;
  - option « Imposer la 2FA aux administrateurs » avec délai de grâce (défaut 7 jours, rappel à chaque connexion) ;
  - un administrateur peut réinitialiser la 2FA d'un autre utilisateur ;
  - option « Se souvenir de cet appareil 30 jours » (cookie signé).

---

## 5. Interface d'administration

- Menu de premier niveau **« Graph'in Security »** (icône bouclier), sous-pages : Tableau de bord, SSL, En-têtes de sécurité, Vulnérabilités, Durcissement, Connexion, Réglages généraux.
- Mise en page inspirée de Really Simple Security : colonne de navigation à gauche, cartes à droite, interrupteurs (toggle) pour les cases, badge « Recommandé » sur les options conseillées.
- Bouton global **« Appliquer les réglages recommandés »** (active toutes les options marquées « Recommandé » après confirmation).
- Charte Graph'in sobre : logo Graph'in en en-tête, couleurs définies en variables CSS dans `assets/admin.css` (à remplacer par la charte exacte), pas de framework CSS externe, pas de React : PHP + JS vanilla.
- Enregistrement des réglages via l'API Settings de WordPress ou AJAX avec nonce, retour visuel immédiat.
- Lien « Réglages » dans la liste des extensions.

---

## 6. Mises à jour automatiques

- Librairie **Plugin Update Checker v5** (YahnisElsts) embarquée dans `vendor/`, branchée sur le dépôt **GitHub public** du plugin.
- Publication d'une version = création d'un tag `vX.Y.Z` ; une GitHub Action construit le zip propre (sans fichiers de dev) et l'attache à la release ; le plugin télécharge cet asset.
- Les mises à jour apparaissent dans WordPress comme pour un plugin wordpress.org et sont compatibles avec les mises à jour automatiques natives.
- Compte GitHub protégé par 2FA ; seules les releases taguées sont distribuées.

---

## 7. Désinstallation

- **Désactivation** : retire les règles `.htaccess`, restaure l'URL de connexion, stoppe les crons ; conserve les réglages.
- **Suppression** (`uninstall.php`) : supprime options, tables, transients, métadonnées utilisateur 2FA, crons.

---

## 8. Hors périmètre V1
Pare-feu applicatif (WAF), scan de fichiers malveillants, tableau de bord multi-sites centralisé, migration des réglages de Really Simple Security.

---

## 9. Critères de recette
- Activation du plugin sans aucune modification visible du site.
- Chaque option activée puis désactivée laisse le site dans son état initial (`.htaccess` identique).
- `GSSS_SAFE_MODE` neutralise tout, y compris URL de connexion et 2FA.
- Test sur WordPress avec thème Enfold : aucune régression front avec tous les réglages recommandés actifs.
- PHPCS (standard WordPress) sans erreur.
- Score A sur securityheaders.com avec les en-têtes recommandés.
- Une release taguée sur GitHub est proposée en mise à jour dans l'admin WordPress d'un site de test en moins de 12 h (ou immédiatement via « Vérifier les mises à jour »).
