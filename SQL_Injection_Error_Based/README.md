Description : Identification d'une vulnérabilité d'injection SQL sur la page MEMBERS.

Analyse technique : > Le champ de recherche est vulnérable car il ne filtre pas correctement les entrées numériques. Bien que le serveur tente d'échapper les apostrophes (ex: ' devient \'), la requête SQL reste vulnérable car le paramètre attendu est un entier (ID). Nous pouvons donc injecter des commandes SQL sans utiliser d'apostrophes, contournant ainsi la protection en place.

Étapes d'exploitation :

Provoquer une erreur de syntaxe pour confirmer la vulnérabilité (Capture 01).

Utiliser la fonction EXTRACTVALUE pour forcer l'affichage de données dans le message d'erreur XPATH.

Extraire le nom de la base de données, des tables et enfin le contenu de la colonne countersign (Captures 02 à 05).

Payload final : 1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT substring(countersign,1,64) FROM users LIMIT 1), 0x7e))
