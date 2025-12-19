# Rapport de Pentest : XSS Stored (Feedback)

## 1. Description de la vulnérabilité
* **Indice du challenge :** `xss_stored_feedback`
* **Cible :** Page `Guestbook` / `Feedback`.
* **Vecteur d'attaque :** Champ "Message" du formulaire.
* **Type de faille :** Cross-Site Scripting (Stored) & HTML Injection.

### Analyse
Le formulaire permet aux utilisateurs de laisser des commentaires. Les données saisies sont stockées en base de données et réaffichées aux visiteurs. L'analyse du code source montre que les commentaires sont insérés dans une structure de tableau HTML (`<table><tr><td>...`).
Bien que le serveur applique des filtres sur certaines balises (comme `<script>`), il ne valide pas correctement la structure HTML, permettant à un attaquant de "casser" le tableau pour injecter du code arbitraire.

---

## 2. Étapes d'exploitation et Preuves

### Étape 1 : Identification des filtres (Fuzzing)
Nous avons d'abord tenté une injection basique pour tester la sécurité.
* **Payload :** `<script>alert('XSS')</script>`
* **Résultat :** Le serveur échappe les caractères spéciaux ou supprime les balises. le script ne s'exécute pas et le code apparait en texte clair.
* **Preuve visuelle :** `screenshots/capture1.png`
![Fuzzing](screenshots/capture1.png)

### Étape 2 : Rupture de la structure ("Table Break")
En inspectant le code, nous avons vu que notre texte était enfermé dans une balise `<td>`. Nous avons contourné la limitation de taille du champ (`maxlength`) via l'inspecteur web, puis injecté un payload fermant brutalement les balises du tableau (`</td></tr></table>`).
* **Payload :** `</td></tr></table><h1>HACKED</h1>`
* **Résultat :** Le texte "HACKED" s'affiche en dehors de l'alignement normal, prouvant que nous contrôlons la structure de la page.
* **Preuve visuelle :** `screenshots/capture2.png`
![Fuzzing](screenshots/capture2.png)

### Étape 3 : Injection Finale et Obtention du Flag
En utilisant la faille de structure découverte précédemment, nous avons injecté un script permettant d'interagir avec le challenge. L'exécution de notre injection a déclenché l'affichage du Flag caché de la section.
* **Vecteur utilisé :** Injection HTML brisant le tableau (`Table Break`) combinée à un script d'exécution.
* **Résultat :** Le flag s'affiche explicitement sur la page accompagné du logo de validation.
* **Preuve visuelle :** `screenshots/capture3.png`
![Fuzzing](screenshots/capture3.png)
---
