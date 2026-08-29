"""
Wraps CloakQuest3r (https://github.com/spyboy-productions/CloakQuest3r) as a library:
loads cloakquest3r.py as a module (its __main__ block never runs) and re-implements the
subdomain scan without interactive input(), returning structured data instead of
just printing to stdout.
"""

import importlib.util
import os
import sys
import threading
from contextlib import contextmanager
from urllib.parse import urlparse


def _default_cloakquest3r_dir():
    env = os.environ.get("CLOAKQUEST3R_DIR")
    if env:
        return os.path.abspath(env)
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "..", "CloakQuest3r"))


@contextmanager
def _pushd(path):
    prev = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(prev)


def clean_domain(target):
    parsed = urlparse(target)
    return parsed.netloc if parsed.scheme else target


_cq3r_module = None
_cq3r_dir = None


def load_cloakquest3r(cloakquest3r_dir=None):
    """Import cloakquest3r.py as a module named 'cloakquest3r_lib' (not '__main__'),
    so its `if __name__ == "__main__":` block never executes."""
    global _cq3r_module, _cq3r_dir

    directory = os.path.abspath(cloakquest3r_dir) if cloakquest3r_dir else _default_cloakquest3r_dir()
    if _cq3r_module is not None and _cq3r_dir == directory:
        return _cq3r_module

    script = os.path.join(directory, "cloakquest3r.py")
    if not os.path.isfile(script):
        raise FileNotFoundError(
            f"cloakquest3r.py introuvable dans {directory}. "
            f"Precise --cloakquest3r-dir ou la variable d'environnement CLOAKQUEST3R_DIR."
        )

    spec = importlib.util.spec_from_file_location("cloakquest3r_lib", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    _cq3r_module = module
    _cq3r_dir = directory
    return module


def _safe_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        print(f"[!] {fn.__name__} a echoue: {exc}")
        return None


def _scan_subdomains(cq3r, domain, wordlist_path, timeout):
    found = []
    lock = threading.Lock()

    def check(sub):
        url = f"https://{sub}.{domain}"
        try:
            resp = cq3r.requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                with lock:
                    found.append(url)
                print(f"{cq3r.Fore.GREEN}Subdomain Found └➤ {url}{cq3r.Fore.RESET}")
        except cq3r.requests.exceptions.RequestException:
            pass

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        subs = [line.strip() for line in f if line.strip()]

    print(f"\n[*] Scan de {len(subs)} sous-domaines potentiels sur {domain}...")
    threads = [threading.Thread(target=check, args=(s,)) for s in subs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"[*] {len(found)} sous-domaine(s) actif(s) trouve(s), resolution des IP reelles...")

    results = []
    for url in found:
        host = url.split("//", 1)[1]
        ip = cq3r.get_real_ip(host)
        if not ip:
            continue
        cert = _safe_call(cq3r.get_ssl_certificate_info, host)
        results.append({"host": host, "ip": ip, "cert": cert})
        cn = cert["Common Name"] if cert else "?"
        print(f"    └➤ {host}: {ip}  (cert CN: {cn})")

    return results


def recon(domain, wordlist_path=None, include_history=True, cloakquest3r_dir=None, timeout=20):
    """Run the CloakQuest3r recon workflow non-interactively and return structured results."""
    cq3r = load_cloakquest3r(cloakquest3r_dir)
    directory = os.path.abspath(cloakquest3r_dir) if cloakquest3r_dir else _default_cloakquest3r_dir()
    domain = clean_domain(domain)

    # cloakquest3r.py reads/writes config.ini and wordlist.txt using relative paths,
    # so we run it with CloakQuest3r's own directory as cwd.
    with _pushd(directory):
        visible_ip = _safe_call(cq3r.get_real_ip, domain)
        uses_cloudflare = bool(_safe_call(cq3r.is_using_cloudflare, domain))
        web_server = _safe_call(cq3r.detect_web_server, domain) or "UNKNOWN"

        if include_history:
            _safe_call(cq3r.get_domain_historical_ip_address, domain)
            _safe_call(cq3r.securitytrails_historical_ip_address, domain)

        wl_path = wordlist_path or cq3r.default_wordlist
        if not os.path.isfile(wl_path):
            _safe_call(cq3r.download_wordlist, wl_path)

        subdomains = _scan_subdomains(cq3r, domain, wl_path, timeout) if os.path.isfile(wl_path) else []

    return {
        "domain": domain,
        "visible_ip": visible_ip,
        "uses_cloudflare": uses_cloudflare,
        "web_server": web_server,
        "subdomains": subdomains,
    }


def build_nmap_targets(result, only_main_ip=False):
    """Turn a recon() result into a sorted list of unique IPs to scan, plus an
    IP -> hostnames map used later for labelling the nmap report."""
    ip_to_hosts = {}

    def add(ip, host):
        if ip:
            ip_to_hosts.setdefault(ip, set()).add(host)

    # If the domain itself isn't behind Cloudflare, its visible IP already IS the
    # real origin IP. If it is behind Cloudflare, the visible IP is just the edge
    # and isn't useful to nmap, so skip it and rely on subdomain-derived real IPs.
    if not result["uses_cloudflare"]:
        add(result["visible_ip"], result["domain"])

    if not only_main_ip:
        for sub in result["subdomains"]:
            add(sub["ip"], sub["host"])

    targets = sorted(ip_to_hosts.keys())
    ip_to_hostnames = {ip: sorted(hosts) for ip, hosts in ip_to_hosts.items()}
    return targets, ip_to_hostnames
