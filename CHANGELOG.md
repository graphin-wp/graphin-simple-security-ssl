# Journal des modifications

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
