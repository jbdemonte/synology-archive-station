# 001 — Retirer le mot de passe Internet Archive mémorisé

## Contexte

Depuis 1.1.0, Archive Station peut mémoriser le mot de passe Internet Archive pour renouveler automatiquement une session expirée. Le mot de passe est chiffré avec Fernet (`src/archive_station/credentials.py`). La clé est stockée dans `archive-account.key`, à côté du fichier chiffré `archive-account.json`. C'est le seul usage de `cryptography`, et donc de `cffi` et `pycparser`.

Ces dépendances compilées empêchent de publier un paquet SynoCommunity `noarch`. La recette actuelle n'installe que des bibliothèques en Python pur (aujourd'hui seulement Waitress).

La session Internet Archive se compose des cookies `logged-in-user` et `logged-in-sig`. Elle dure environ un an : une session ouverte le 1er novembre 2026 expire le 1er novembre 2027. Se reconnecter à la main une fois par an est acceptable.

## Objectif

Supprimer partout le stockage du mot de passe et le renouvellement automatique, en gardant la connexion par session. Le comportement devient celui de 1.1.0-8 avec « Mémoriser » décoché. Ensuite, plus aucun code ni paquet ne dépend de `cryptography`, `cffi` ou `pycparser`.

## Comportement attendu

### Connexion et session

1. **Connexion.** L'e-mail et le mot de passe sont envoyés à Internet Archive comme aujourd'hui (`_login`). Seuls l'e-mail, les cookies et l'expiration sont enregistrés dans `archive-account.json`, avec les droits `0600`. Le mot de passe n'est jamais écrit sur disque. Il n'est gardé ni dans l'état du compte, ni dans un cache, ni dans les journaux, et l'interface vide le champ après chaque tentative, comme aujourd'hui. On ne promet pas d'effacer toute trace en mémoire : le corps HTTP ou une trace d'exception peuvent encore y faire référence brièvement.
2. **Session expirée.**
   - L'état est `expired` et l'interface affiche « Session expirée. Reconnecter le compte. ».
   - Aucune tentative de connexion automatique n'a lieu, ni au démarrage, ni sur une requête, ni sur un 401 ou un 403.
   - Les fichiers publics continuent d'être demandés anonymement, comme aujourd'hui (`request_snapshot`).
   - Un fichier restreint échoue avec le message d'erreur déjà utilisé quand l'accès est refusé.
3. **Réponse 401 ou 403.** La requête est rejouée une fois seulement si une connexion manuelle a créé une session plus récente que celle qu'elle a utilisée. C'est ce que fait déjà `refresh()` quand il renvoie `True`, et `archive.py` peut continuer de l'appeler. Sinon, l'erreur d'origine est remontée, sans aucune requête vers `LOGIN_URL`.
4. **Déconnexion.** Le comportement ne change pas : `archive-account.json` est supprimé, ainsi que `archive-account.key` s'il en reste un. Les transferts déjà ouverts peuvent se terminer, et les requêtes suivantes passent en accès public.
5. **Ce qui ne change pas.** La validation des cookies, l'invalidation des sélections quand le compte change (`account_generation`), le refus des redirections hors d'Archive.org et le délai entre deux connexions manuelles restent inchangés.

### API

6. **Connexion.** `POST /api/archive-account/login` accepte `{email, password}`. Un champ `remember` éventuel, envoyé par une ancienne interface en cache, est ignoré quelle que soit sa valeur, sans erreur.
7. **Oubli du mot de passe.** La route `POST /api/archive-account/forget` est supprimée. Elle obtient la même réponse que les autres routes inconnues.
8. **Statut du compte.** L'objet `archive_account` renvoyé par les paramètres ne contient plus `remember_credentials`, `remember_choice` ni `reconnect_error`. Il garde `connected`, `state` et `email`. Retire aussi les autres usages de ces champs dans le code (rapports, notifications, interface, tests).

### Migration au démarrage

Cette migration concerne les fichiers `archive-account.json` aux versions 1 à 3.

9. **Session conservée.** L'e-mail, les cookies et l'expiration restent valides s'ils passent les contrôles actuels. Un fichier à la structure invalide est ignoré, comme aujourd'hui.
10. **Champs abandonnés.** Les champs `credentials`, `remember_choice`, `blocked` et `blocked_reason` sont ignorés. Un ancien état `blocked`, posé après un mot de passe refusé, ne bloque plus rien.
11. **Purge du disque.** Si le fichier contient un de ces champs, il est réécrit tout de suite dans le nouveau format, pour retirer le mot de passe chiffré du disque.
12. **Suppression de la clé.** `archive-account.key` est supprimé s'il existe, avec `unlink` (qui ne suit pas les liens). La suppression de la clé ou la réécriture du fichier peut échouer : le service démarre quand même, garde la session en mémoire et ne journalise aucune donnée sensible.
13. **Nouveau format.** Le fichier contient `{"version": 4, "email": …, "cookies": …, "expires": …}`, écrit de façon atomique comme aujourd'hui. 1.1.0-8 ne lit pas la version 4 : après un retour à 1.1.0, il faut se reconnecter. Les notes de version le diront.

### Interface : Paramètres → Compte Internet Archive

14. **Éléments retirés.**
    - La case « Mémoriser les identifiants pour se reconnecter automatiquement. » et l'aide « Le mot de passe est chiffré sur ce NAS. Décocher pour conserver uniquement la session. ».
    - Le bouton « Oublier le mot de passe », la ligne « Reconnexion automatique activée. / désactivée. » et l'élément d'erreur de reconnexion.
    - Le message « La session sera renouvelée au prochain téléchargement. ».
15. **Aide ajoutée.** Dans la fenêtre de connexion, sous les champs, ajouter cette aide, dont voici le texte source exact : « Le mot de passe n’est pas enregistré. Seule la session est conservée ; reconnecter le compte quand elle expire. »
16. **Statuts possibles.** Seuls trois statuts restent : connecté (« Compte connecté : {account} »), expiré (« Session expirée. Reconnecter le compte. ») et public (« Accès public uniquement. »).
17. **Éléments conservés.** L'indicateur de connexion en cours, les erreurs, la déconnexion et l'aide « Après connexion, utiliser « Actualiser la liste » sur la tâche existante. » restent en place. Le corps de la requête de connexion ne contient plus `remember`.

### Traductions

18. Traduire la nouvelle chaîne dans les 27 catalogues de `static/locales/`. Retirer des 27 catalogues les textes d'interface qui ne sont plus utilisés nulle part. Garder en revanche les messages serveur qui ont pu être enregistrés comme erreur de fichier ou d'incident, par exemple `STORAGE_ERROR` de `credentials.py`. `engine.py` stocke ces erreurs dans SQLite et `app.js` les traduit à l'affichage avec `t(error)` : sans leur clé, elles réapparaîtraient en français dans toutes les langues. Suivre `docs/TRANSLATIONS.md`.

### Dépendances et paquet

19. Supprimer `src/archive_station/credentials.py`.
20. Retirer `cryptography`, `cffi` et `pycparser` de ces fichiers :
    - `pyproject.toml` ;
    - `requirements.txt` ;
    - `packaging/synology/runtime-lock.json` ;
    - `packaging/synology/THIRD_PARTY_NOTICES.txt`.

    Vérifier que `scripts/build_spk.py` et `scripts/fetch_runtime.py` fonctionnent sans eux. `build_spk.py` lit déjà les entrées du fichier de verrouillage une à une.
21. Le `.spk` construit ne contient plus rien de `cryptography`, `cffi`, `_cffi_backend` ni `pycparser` sous `vendor/`.

### Documentation

AGENTS.md demande de documenter toute modification d'une limite de sécurité.

22. **README.md.** Dans la liste des fonctions et la section sur le compte, indiquer que seule la session est conservée et qu'il faut se reconnecter quand elle expire.
23. **docs/USAGE.md.** Réécrire la section sur le compte. Le mot de passe n'est jamais enregistré. `archive-account.json`, en `0600`, contient l'e-mail et les cookies de session en clair. Il faut le protéger dans les sauvegardes comme un identifiant. Expliquer aussi la reconnexion à l'expiration et la déconnexion.
24. **docs/ARCHITECTURE.md.** Le fichier ne décrit aujourd'hui aucune session Internet Archive. Ajouter un court paragraphe, près de la description de l'authentification : seuls l'e-mail et les cookies de session sont enregistrés, en clair, dans `archive-account.json` avec les droits `0600`. Le mot de passe n'est jamais mémorisé et la session n'est jamais renouvelée automatiquement.
25. **Capture d'écran.** Regénérer `docs/images/archive-account.png` avec `scripts/screenshots.mjs` si elle montre la case ou le bouton retirés.

## Tests

Tests backend (`unittest`, réseau simulé) :

- **Connexion.** Le fichier enregistré ne contient que `version`, `email`, `cookies` et `expires`. Le mot de passe n'apparaît ni dans le fichier, ni dans le statut, ni dans les réponses de l'API. Aucun `archive-account.key` n'est créé.
- **Champ `remember`.** Avec `remember` absent, `true`, `false` ou une valeur non booléenne comme `"oui"` ou `1`, la connexion réussit et le résultat est identique. Convertir en ce sens le test actuel qui exige le refus des valeurs non booléennes (`tests/test_archive_account.py`, vers la ligne 465) au lieu de le supprimer.
- **Migration.** Partir d'un fichier en version 3 avec `credentials` non vide, `remember_choice` et `blocked: true` (`blocked_reason: "credentials"`), et d'un `archive-account.key`. Après `ArchiveAccount(data_dir)` :
  - la session est conservée et `snapshot()` renvoie le cookie ;
  - le fichier est réécrit en version 4, sans les anciens champs ;
  - la clé est supprimée ;
  - l'état n'est pas bloqué.
- **Migration en échec.** Si la suppression de la clé ou la réécriture échoue, le service démarre quand même avec la session.
- **Session expirée.** Une requête restreinte n'envoie aucune requête à `LOGIN_URL`, et une requête publique part en accès anonyme.
- **Réponse 401 ou 403.** Si une session manuelle plus récente existe, la requête est rejouée une fois avec le nouveau cookie. Sinon, l'erreur d'origine remonte, sans tentative de connexion.
- **Route supprimée.** `POST /api/archive-account/forget` obtient la réponse des routes inconnues.
- **Plus de dépendance.** L'application s'importe et démarre quand `cryptography` est indisponible, par exemple avec `sys.modules["cryptography"] = None` dans un sous-processus.
- **Anciens tests.** Retirer ou adapter ceux du mot de passe mémorisé : `tests/test_remember_account.py`, `tests/test_account_regressions.py` et `tests/test_archive_account.py` pour la partie concernée.

Tests de l'interface (`scripts/archive_account_smoke.mjs`) :

- La case et le bouton « Oublier » n'existent plus, et la nouvelle aide s'affiche.
- Le corps de la requête de connexion ne contient pas `remember`.
- Le statut expiré affiche « Session expirée. Reconnecter le compte. ».
- La fenêtre reste correcte en petite taille.

À lancer :

- `make check` et `make test-ui` doivent passer.
- `make build` doit produire un paquet dont `vendor/` ne contient plus rien de `cryptography`, `cffi` ni `pycparser`.

## Hors périmètre

- Changement de version, notes de version et publication, préparés à part.
- Mise à jour de la recette SynoCommunity (PR SynoCommunity/spksrc#7563).
- Test sur le NAS : session conservée après la mise à jour, fichier réécrit, clé supprimée. Il sera fait après la relecture.
