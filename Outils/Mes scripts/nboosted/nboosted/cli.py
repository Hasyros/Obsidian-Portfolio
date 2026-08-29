import argparse
import os
import sys

from . import cloak, scanner, report

# Make sure unicode glyphs (used by CloakQuest3r's own output style) never crash
# on terminals stuck on a legacy codepage (e.g. plain Windows cmd.exe).
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def build_parser():
    parser = argparse.ArgumentParser(
        prog="nboosted",
        description=(
            "Workflow recon: cherche les IP reelles derriere Cloudflare avec CloakQuest3r, "
            "puis lance nmap -sV -sC dessus et trie les ports trouves."
        ),
    )
    parser.add_argument("target", help="Domaine cible, ex: cat.com")
    parser.add_argument(
        "--wordlist",
        help="Wordlist de sous-domaines a utiliser (evite le telechargement/prompt par defaut)",
    )
    parser.add_argument(
        "--cloakquest3r-dir",
        help="Chemin vers le checkout de CloakQuest3r (defaut: dossier ../CloakQuest3r ou $CLOAKQUEST3R_DIR)",
    )
    parser.add_argument(
        "--skip-history",
        action="store_true",
        help="Ne pas interroger ViewDNS/SecurityTrails pour l'historique d'IP",
    )
    parser.add_argument("--ports", help="Plage de ports pour nmap -p (ex: 1-1000,8080)")
    parser.add_argument("--top-ports", type=int, help="Scanner seulement les N ports les plus communs (nmap --top-ports)")
    parser.add_argument(
        "--no-pn",
        action="store_true",
        help="Ne pas passer -Pn a nmap (reactive la decouverte d'hote par ping)",
    )
    parser.add_argument(
        "--parallel", "-j",
        type=int,
        default=scanner.DEFAULT_PARALLEL,
        help=f"Nombre de processus nmap lances en simultane, un par IP (defaut: {scanner.DEFAULT_PARALLEL})",
    )
    parser.add_argument("--timeout", type=int, default=20, help="Timeout HTTP par sous-domaine teste (secondes)")
    parser.add_argument(
        "--only-main-ip",
        action="store_true",
        help="Ne scanner que l'IP reelle du domaine principal, ignorer les sous-domaines",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Afficher aussi la sortie des scripts NSE (-sC) pour chaque port",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    wordlist_path = os.path.abspath(args.wordlist) if args.wordlist else None
    cloakquest3r_dir = os.path.abspath(args.cloakquest3r_dir) if args.cloakquest3r_dir else None

    try:
        result = cloak.recon(
            args.target,
            wordlist_path=wordlist_path,
            include_history=not args.skip_history,
            cloakquest3r_dir=cloakquest3r_dir,
            timeout=args.timeout,
        )
    except FileNotFoundError as exc:
        print(f"[!] {exc}")
        return 1

    targets, ip_to_hostnames = cloak.build_nmap_targets(result, only_main_ip=args.only_main_ip)
    report.print_recon_summary(result, targets, ip_to_hostnames)

    if not targets:
        print("\n[!] Aucune IP a scanner. Arret.")
        return 1

    parallel = max(1, args.parallel)
    print(f"\n[*] Lancement de nmap -sV -sC sur {len(targets)} IP(s), {min(parallel, len(targets))} en simultane...")

    done_count = 0

    def _progress(target, parsed_hosts, error):
        nonlocal done_count
        done_count += 1
        report.print_host_result(
            done_count, len(targets), target, parsed_hosts, ip_to_hostnames,
            error=error, verbose=args.verbose,
        )

    try:
        nmap_hosts, nmap_errors = scanner.run_nmap(
            targets,
            use_pn=not args.no_pn,
            ports=args.ports,
            top_ports=args.top_ports,
            parallel=parallel,
            on_target_done=_progress,
        )
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return 1

    if nmap_errors:
        print(f"\n[!] {len(nmap_errors)} IP(s) en echec sur {len(targets)}.")

    grouped = report.group_by_port(nmap_hosts, ip_to_hostnames)
    report.print_port_report(grouped, verbose=args.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
