# Journal des modifications

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
