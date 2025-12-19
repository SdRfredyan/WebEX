# Vulnérabilité : Security Misconfiguration (User-Agent & Referer)

## 1. Découverte (Reconnaissance)
En examinant le code HTML de la page d'accueil, nous avons repéré un lien suspect dans le pied de page (footer), sur le texte du copyright "&copy; BornToSec".

**Lien découvert :**
`http://192.168.222.135/index.php?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f`

En cliquant dessus via un navigateur standard, l'accès est refusé. Le message d'erreur (ou le contexte du challenge) suggère que le site attend un navigateur spécifique et une provenance spécifique.

## 2. Exploitation (Spoofing)
Les en-têtes HTTP `User-Agent` et `Referer` peuvent être modifiés librement par l'utilisateur. Nous avons utilisé l'outil en ligne de commande `curl` pour simuler les critères attendus par le serveur.

**Critères identifiés :**
* **User-Agent** (Navigateur) : `ft_bornToSec`
* **Referer** (Provenance) : `https://www.nsa.gov/`

### Commande exécutée
```bash
curl -A "ft_bornToSec" -e "[https://www.nsa.gov/](https://www.nsa.gov/)" "[http://192.168.222.135/index.php?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f](http://192.168.222.135/index.php?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f)"
