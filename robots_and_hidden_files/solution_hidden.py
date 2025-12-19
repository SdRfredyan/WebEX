import urllib.request
import re

ROOT_URL = "http://192.168.222.135/.hidden/"
# On garde en mémoire les liens visités pour ne pas tourner en rond
VISITED = set()

def get_content(url):
    try:
        with urllib.request.urlopen(url) as response:
            return response.read().decode('utf-8')
    except:
        return None

def crawl(url):
    # Si on a déjà vu ce dossier, on passe
    if url in VISITED: return False
    VISITED.add(url)

    # Récupère le contenu HTML du dossier
    html = get_content(url)
    if not html: return False

    # --- 1. On regarde si le README contient le graal ---
    readme_content = get_content(url + "README")
    if readme_content:
        clean = readme_content.strip()
        # Si le message N'EST PAS un troll connu, c'est le flag !
        if "voisin" not in clean and "aide" not in clean and "craquer" not in clean and "Non" not in clean:
            print(f"\n\n{'='*50}")
            print(f"[+] VICTOIRE ! FLAG TROUVÉ !")
            print(f"[+] Chemin : {url}")
            print(f"[+] FLAG   : {clean}")
            print(f"{'='*50}\n")
            return True # On arrête tout, on a trouvé

    # --- 2. On cherche les sous-dossiers et on plonge dedans ---
    folders = re.findall(r'href="(.*?/)"', html)
    for folder in folders:
        # On ignore le dossier parent "../"
        if folder == "../": continue
        
        # Petit effet visuel pour dire qu'on travaille
        print(".", end="", flush=True)
        
        # APPEL RÉCURSIF : On lance la fonction sur le sous-dossier
        if crawl(url + folder):
            return True # Si le sous-dossier a trouvé, on remonte l'info pour tout arrêter
            
    return False

print("[-] Lancement du scan en profondeur... (patience)")
crawl(ROOT_URL)
input("Appuie sur Entrée pour quitter...")