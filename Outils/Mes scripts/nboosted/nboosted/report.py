"""Builds and prints the port-sorted report combining CloakQuest3r hostnames
with nmap -sV -sC results."""

from colorama import init, Fore, Style

init()


def group_by_port(nmap_hosts, ip_to_hostnames):
    """port/proto -> {"service": str, "entries": [ {ip, hostnames, product, version, scripts} ]}"""
    grouped = {}
    for host in nmap_hosts:
        ip = host["ip"]
        hostnames = ip_to_hostnames.get(ip, [])
        for p in host["ports"]:
            key = (p["port"], p["protocol"])
            bucket = grouped.setdefault(key, {"service": p["service"], "entries": []})
            bucket["entries"].append({
                "ip": ip,
                "hostnames": hostnames,
                "product": p["product"],
                "version": p["version"],
                "scripts": p["scripts"],
            })
    return grouped


def print_recon_summary(result, targets, ip_to_hostnames):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Recon CloakQuest3r: {result['domain']} ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Visible IP:{Fore.RESET} {result['visible_ip']}")
    print(f"{Fore.YELLOW}Derriere Cloudflare:{Fore.RESET} {'oui' if result['uses_cloudflare'] else 'non'}")
    print(f"{Fore.YELLOW}Serveur web:{Fore.RESET} {result['web_server']}")
    print(f"{Fore.YELLOW}Sous-domaines actifs trouves:{Fore.RESET} {len(result['subdomains'])}")
    print(f"{Fore.YELLOW}IP uniques a scanner:{Fore.RESET} {len(targets)}")
    for ip in targets:
        hosts = ip_to_hostnames.get(ip, [])
        label = f"{ip}  ({', '.join(hosts)})" if hosts else ip
        print(f"    - {label}")


def print_host_result(index, total, target, parsed_hosts, ip_to_hostnames, error=None, verbose=False):
    """Called as soon as a single nmap process finishes, so the terminal fills up
    live instead of staying silent until every target is done."""
    hostnames = ip_to_hostnames.get(target, [])
    label = f"{target} ({', '.join(hostnames)})" if hostnames else target
    prefix = f"    [{index}/{total}] {label}"

    if error:
        print(f"{Fore.RED}{prefix}: echec ({error}){Fore.RESET}")
        return

    if not parsed_hosts:
        print(f"{Fore.YELLOW}{prefix}: hote down / injoignable{Fore.RESET}")
        return

    all_ports = sorted(
        (p for h in parsed_hosts for p in h["ports"]),
        key=lambda p: p["port"],
    )
    if not all_ports:
        print(f"{prefix}: aucun port ouvert")
        return

    bits = []
    for p in all_ports:
        version = f"{p['product']} {p['version']}".strip()
        bit = f"{p['port']}/{p['protocol']} {p['service']}"
        if version:
            bit += f" ({version})"
        bits.append(bit)

    print(f"{Fore.GREEN}{prefix}{Fore.RESET}: {', '.join(bits)}")
    if verbose:
        for p in all_ports:
            for script in p["scripts"]:
                output = (script["output"] or "").strip().replace("\n", "\n            ")
                print(f"        [{p['port']}/{p['protocol']} {script['id']}] {output}")


def print_port_report(grouped, verbose=False):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Recap: ports ouverts, tries par port ==={Style.RESET_ALL}")
    if not grouped:
        print(f"{Fore.RED}Aucun port ouvert trouve.{Fore.RESET}")
        return

    for (port, proto), data in sorted(grouped.items()):
        entries = data["entries"]
        print(
            f"\n{Fore.GREEN}{port}/{proto}{Fore.RESET} "
            f"{Fore.YELLOW}{data['service']}{Fore.RESET} "
            f"({len(entries)} hote{'s' if len(entries) > 1 else ''})"
        )
        for e in entries:
            hosts_label = f" ({', '.join(e['hostnames'])})" if e["hostnames"] else ""
            version = f"{e['product']} {e['version']}".strip()
            version_label = f" - {version}" if version else ""
            print(f"    └➤ {Fore.RED}{e['ip']}{Fore.RESET}{hosts_label}{version_label}")
            if verbose:
                for script in e["scripts"]:
                    output = (script["output"] or "").strip().replace("\n", "\n        ")
                    print(f"        [{script['id']}] {output}")

    total_open = sum(len(d["entries"]) for d in grouped.values())
    print(f"\n{Fore.CYAN}Total: {len(grouped)} port(s) distinct(s) ouvert(s), {total_open} instance(s) au total.{Fore.RESET}")
