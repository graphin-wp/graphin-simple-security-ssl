# Journal des modifications

## 0.10.0 (non publiée)

- Tableau de bord : score de sécurité (part des points recommandés en place, SSL compris), liste « À faire » avec un lien qui mène à l'option concernée, état du certificat et de son expiration, dernier scan de vulnérabilités, version du plugin et mise à jour disponible.
- Bouton « Appliquer les réglages recommandés » : en-têtes, durcissement, limitation des connexions (IP de l'administrateur mise en liste blanche) et scan des vulnérabilités, en une seule écriture de .htaccess. Si le site casse, tout revient comme avant. Le SSL et la double authentification ne sont pas concernés.
- Reprise de Graph'in Hardening : les réglages équivalents sont cochés, Graph'in Hardening est désactivé, puis le plugin vérifie ce que sert Apache. Si le site est déjà en https, le SSL est activé pour garder HSTS. X-XSS-Protection passe de « 1; mode=block » à 0.
- Liste des extensions en doublon (Login Lockdown, Limit Login Attempts, Loginizer, Wordfence, Really Simple Security, Graph'in Hardening).
- Rappel « Corriger le contenu mixte » quand le SSL est actif sans correcteur ni Upgrade Insecure Requests.
- Export et import des réglages en JSON. L'adresse de connexion, la liste blanche, l'email du client et l'activation du SSL restent propres à chaque site. Les valeurs importées sont contrôlées, la CSP repart en rapport seulement.
- Socle : bornes des réglages numériques dans Settings, écriture groupée (`set_many`), `Htaccess::is_rollback()`, détection commune des extensions actives.

## 0.9.0 (non publiée)

- Module SSL : détection d'un certificat valide sur l'adresse https, avec un message lisible en cas d'échec. La date d'expiration est lue en local, sans service tiers, avec une alerte à moins de 14 jours. Bouton « Revérifier ».
- « Activer le SSL » est refusé côté serveur si la détection échoue, si WP_HOME ou WP_SITEURL imposent http dans wp-config.php, ou en multisite. Les adresses du site passent en https si elles ne le sont pas déjà. Un cookie de connexion sécurisé est posé pour que l'administrateur reste connecté.
- Redirection 301 vers https en un seul saut, variante www comprise, pour GET et HEAD seulement (un formulaire envoyé en http n'est pas redirigé). En Apache, elle est écrite dans .htaccess avec des conditions sur `HTTPS` et `X-Forwarded-Proto`. Sinon, PHP s'en charge.
- Variante www : seul le choix qui correspond à l'adresse du site est accepté, car l'autre ferait boucler la redirection avec celle de WordPress.
- Après l'enregistrement, le plugin vérifie que la redirection et HSTS sont réellement servis par Apache. Si mod_rewrite ou mod_headers manquent, PHP prend le relais. Si les règles cassent le site (boucle de redirection), .htaccess est restauré, ainsi que les adresses et les options.
- HSTS (max-age d'un an), avec les options includeSubDomains et preload accompagnées d'avertissements. preload ajoute includeSubDomains, que les navigateurs exigent. L'en-tête n'est envoyé qu'en https.
- Derrière un proxy qui termine le https (`X-Forwarded-Proto: https`), WordPress est informé qu'il est en https. Cela évite une boucle de redirection.
- Correcteur de contenu mixte pour le site public, avec une case séparée pour l'administration. Les adresses `http://` du domaine (www compris, JSON échappé compris) passent en https dans les pages HTML. Les autres domaines et les sous-domaines ne sont pas modifiés.
- « Revenir en HTTP » : confirmation, retrait de la redirection et de HSTS. Seules les adresses que le plugin avait changées repassent en http. Un avertissement rappelle que HSTS reste actif dans les navigateurs jusqu'à son expiration.
- Avis quand Graph'in Hardening est actif (HSTS en double). Snippet Nginx affiché hors mode Apache. Journal pour chaque action.

## 0.8.0 (non publiée)

- Module En-têtes de sécurité : X-Content-Type-Options, X-Frame-Options, Referrer-Policy (valeur au choix), Permissions-Policy (une case par fonctionnalité), Cross-Origin-Opener-Policy, X-XSS-Protection à 0. Tout est décoché par défaut.
- En mode Apache, écriture dans .htaccess via mod_headers (sauvegarde, test, rollback). Après l'enregistrement, le plugin vérifie que les en-têtes arrivent vraiment : sinon (mod_headers absent, .htaccess ignoré), PHP les envoie.
- Content-Security-Policy en rapport seulement par défaut, envoyée par PHP sur le site public seulement. Endpoint REST `gsss/v1/csp-report` (formats csp-report et reports+json, 16 Ko, 30 rapports par minute et par IP, 100 lignes, dédoublonnage), tableau des violations avec « Autoriser », « Vider », passage en mode appliqué refusé tant que des rapports restent.
- `report-uri` seul (sans `report-to`) : avec `report-to`, Chrome n'utilisait plus `report-uri` et aucun rapport n'arrivait lors des tests.
- Case « Upgrade Insecure Requests » indépendante de la CSP (comme dans Graph'in Hardening) : en-tête appliqué à part quand la CSP est absente ou en rapport seulement, intégré à la CSP quand elle est appliquée. Site en https seulement.
- Bouton « Tester les en-têtes » : la page d'accueil est demandée et les en-têtes reçus s'affichent, présents ou absents.
- Socle : `Htaccess::sync()` mémorise si les règles sont en place (`gsss_htaccess_active`).

## 0.7.0 (non publiée)

- Module Connexion, bloc adresse de connexion personnalisée : le slug sert la page de connexion, wp-login.php et /wp-admin répondent 404 aux visiteurs non connectés (admin-ajax.php, admin-post.php, upgrade.php, install.php, repair.php, load-styles.php, load-scripts.php et l'action postpass restent accessibles).
- Les liens de connexion, de déconnexion, de mot de passe perdu, les emails de réinitialisation, le formulaire de la double authentification et les redirections passent par le slug.
- Les alias /login, /admin et /dashboard de WordPress sont neutralisés tant que le bloc est actif.
- Slug validé (3 à 40 caractères, mots réservés et contenus existants refusés), email de la nouvelle adresse à l'agence et à l'administrateur du site, rappel de la procédure de récupération.
- Aucune règle serveur : la désactivation du plugin, le mode secours ou le renommage du dossier rétablissent wp-login.php.
- La page 404 est un message neutre (pas le gabarit du thème), pour ne pas dépendre du thème à ce stade.

## 0.6.0 (non publiée)

- Module Connexion, bloc limitation des tentatives : compteur par IP, blocage progressif (30 min par défaut, doublé à chaque récidive, plafonné à 24 h), liste blanche préremplie avec l'IP de l'administrateur à l'activation, liste des IP bloquées avec « Débloquer », purge quotidienne.
- Le contrôle passe après la vérification du mot de passe et avant le second facteur : une IP bloquée est refusée même avec le bon mot de passe, y compris par XML-RPC. Les mauvais codes de double authentification comptent comme des échecs.
- Derrière un proxy (case à cocher), l'IP est la dernière adresse de X-Forwarded-For, filtre `gsss_client_ip` pour les cas particuliers.
- Avis quand une autre extension de limitation est active (Login Lockdown, Limit Login Attempts, Loginizer, Wordfence).
- Les mots de passe d'application en REST ne passent pas par ce contrôle.

## 0.5.0 (non publiée)

- Module Connexion, bloc double authentification : application TOTP (RFC 6238, vérifié avec les vecteurs de test officiels), code par email de secours, 10 codes de récupération à usage unique, appareil de confiance 30 jours en option.
- Le cookie de connexion n'est posé qu'après le second facteur. Un compte protégé ne s'ouvre que depuis la page de connexion WordPress : wp_signon et XML-RPC refusent le mot de passe seul.
- Secrets chiffrés en AES-256-GCM avec une clé dérivée des salts WordPress.
- Activation dans une page dédiée avec QR code généré en local (qrcode-generator 1.4.4, MIT), section dans le profil, réinitialisation par un administrateur avec email à l'utilisateur.
- Option « Imposer la 2FA aux administrateurs » avec délai de grâce, rappel dans l'administration, puis renvoi vers la configuration.
- Limitation des tentatives et URL personnalisée : blocs suivants du module, pas encore codés.

## 0.4.0 (non publiée)

- Module Durcissement : 13 cases, toutes décochées par défaut. XML-RPC, éditeur de fichiers, énumération des utilisateurs, version de WordPress, erreurs de connexion génériques, PHP interdit dans uploads, listing des répertoires, fichiers sensibles, mots de passe d'application, identifiants interdits, pingbacks entrants, test OPcache de Santé du site, alerte d'inscription.
- Le socle `.htaccess` écrit aussi dans le dossier uploads, et supprime un fichier devenu vide : tout cocher puis tout décocher rend l'état d'origine.
- La vérification d'écriture de `.htaccess` ne se fait plus que s'il y a quelque chose à changer.
- Page Durcissement : interrupteurs, badge « Recommandé », snippet Nginx avec bouton « Copier », avis quand Graph'in Hardening est encore actif.
- Les modules déclarent leurs réglages recommandés (`recommended()`) pour le futur bouton « Appliquer les réglages recommandés ».

## 0.3.0 (non publiée)

- Module Vulnérabilités : scan des plugins, thèmes et du cœur via WPVulnerability.net, par lots, avec cache de 12 h. Désactivé tant que la case n'est pas cochée.
- Scan quotidien par WP-Cron, bouton « Scanner maintenant » avec progression, relance après échec à 15 min, 1 h puis 24 h.
- Alerte email groupée pour les failles nouvelles au-dessus du seuil choisi, notice rouge sur le tableau de bord WordPress pour les failles critiques ou élevées.
- Option de mise à jour automatique d'un plugin vulnérable, et signalement des extensions fermées sur wordpress.org.
- Seul l'identifiant du composant part sur le réseau (pour le cœur, son numéro de version), avec un agent HTTP qui ne contient pas l'adresse du site.

## 0.2.0 (non publiée)

- Socle commun : écriture sécurisée de `.htaccess` (sauvegarde, bloc en tête de fichier entre marqueurs, test HTTP de l'accueil avant et après, restauration automatique si échec), journal en base (table `gsss_log`, 200 lignes maximum), alertes email (agence, client optionnel, anti-doublon).
- Réglages généraux : mode serveur, adresses d'alerte, email de test, journal en lecture seule.
- Le mode secours et la désactivation retirent le bloc `.htaccess`.

## 0.1.0 (non publiée)

- Squelette : fichier principal, constantes, mode secours `GSSS_SAFE_MODE`, réglages (option `gsss_settings`), classe abstraite de module, menu « Graph'in Security » avec 7 pages vides, Plugin Update Checker 5.6 branché sur le dépôt GitHub.
- Rien n'est appliqué à l'activation.
