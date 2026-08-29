"""Runs nmap -sV -sC against a list of IPs, several nmap processes in parallel,
and parses the XML output of each."""

import concurrent.futures
import shutil
import subprocess
import xml.etree.ElementTree as ET

DEFAULT_PARALLEL = 10


def _build_cmd(target, use_pn, ports, top_ports, extra_args):
    cmd = ["nmap", "-sV", "-sC"]
    if use_pn:
        cmd.append("-Pn")
    if ports:
        cmd += ["-p", ports]
    elif top_ports:
        cmd += ["--top-ports", str(top_ports)]
    if extra_args:
        cmd += list(extra_args)
    cmd += ["-oX", "-", target]
    return cmd


def _scan_one(target, use_pn, ports, top_ports, extra_args):
    cmd = _build_cmd(target, use_pn, ports, top_ports, extra_args)
    return subprocess.run(cmd, capture_output=True, text=True)


def run_nmap(targets, use_pn=True, ports=None, top_ports=None, extra_args=None,
             parallel=DEFAULT_PARALLEL, on_target_done=None):
    """Scan `targets` with up to `parallel` nmap processes running at the same time
    (one target per process). Returns (hosts, errors):
      - hosts: merged list of parsed host dicts (see parse_nmap_xml)
      - errors: list of (target, message) for targets that failed
    """
    if not shutil.which("nmap"):
        raise RuntimeError(
            "nmap introuvable dans le PATH. Installe-le (ex: 'sudo apt install nmap' sous Kali/WSL)."
        )
    if not targets:
        return [], []

    max_workers = max(1, min(parallel, len(targets)))
    hosts = []
    errors = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_scan_one, target, use_pn, ports, top_ports, extra_args): target
            for target in targets
        }
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                proc = future.result()
            except Exception as exc:
                errors.append((target, str(exc)))
                if on_target_done:
                    on_target_done(target, None, str(exc))
                continue

            if not proc.stdout.strip():
                message = proc.stderr.strip() or f"nmap a quitte avec le code {proc.returncode}"
                errors.append((target, message))
                if on_target_done:
                    on_target_done(target, None, message)
                continue

            try:
                parsed = parse_nmap_xml(proc.stdout)
            except ET.ParseError as exc:
                message = f"XML invalide: {exc}"
                errors.append((target, message))
                if on_target_done:
                    on_target_done(target, None, message)
                continue

            hosts.extend(parsed)
            if on_target_done:
                on_target_done(target, parsed, None)

    return hosts, errors


def parse_nmap_xml(xml_text):
    root = ET.fromstring(xml_text)
    hosts = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        addr_el = host_el.find("address")
        ip = addr_el.get("addr") if addr_el is not None else None

        ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                scripts = [
                    {"id": s.get("id"), "output": s.get("output")}
                    for s in port_el.findall("script")
                ]

                ports.append({
                    "port": int(port_el.get("portid")),
                    "protocol": port_el.get("protocol"),
                    "service": service_el.get("name") if service_el is not None else "",
                    "product": service_el.get("product", "") if service_el is not None else "",
                    "version": service_el.get("version", "") if service_el is not None else "",
                    "scripts": scripts,
                })

        hosts.append({"ip": ip, "ports": ports})

    return hosts
