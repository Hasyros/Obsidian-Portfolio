import os
import subprocess
import shutil
import threading
from rich.console import Console

console = Console()

# SQLMap tamper scripts for WAF bypass
TAMPER_SCRIPTS = [
    "randomcase",           # Randomize keyword case: SeLeCt
    "space2comment",        # Replace spaces with /**/
    "between",              # Replace > with NOT BETWEEN 0 AND
    "equaltolike",          # Replace = with LIKE
    "charunicodeencode",    # Unicode-encode characters
    "percentage",           # Add % before each char (ASP)
]


class SQLMapRunner:
    def __init__(self, output_dir="output", sqlmap_path=None, extra_args=None, scheme="http"):
        self.output_dir = output_dir
        self.sqlmap_path = sqlmap_path or self._find_sqlmap()
        self.extra_args = extra_args or []
        # Scheme (http/https) de la cible : sert a reconstruire l'URL sqlmap depuis
        # les fichiers de requete (qui ne portent pas le schema). Un site HTTPS
        # sonde en http -> "unable to connect".
        self.scheme = scheme or "http"
        self.results = []

    def _find_sqlmap(self):
        # First check if sqlmap is on PATH
        path = shutil.which("sqlmap")
        if path:
            return path

        for cmd in ["python -m sqlmap", "python3 -m sqlmap"]:
            binary = cmd.split()[0]
            if shutil.which(binary):
                try:
                    result = subprocess.run(
                        cmd.split() + ["--version"],
                        capture_output=True, text=True, timeout=10,
                        input="\n",  # auto-press Enter for sqlmap prompt
                    )
                    if "sqlmap" in result.stdout.lower() or result.returncode == 0:
                        return cmd
                except (subprocess.SubprocessError, FileNotFoundError):
                    continue

        common_paths = [
            os.path.expanduser("~/sqlmap/sqlmap.py"),
            os.path.expanduser("~/tools/sqlmap/sqlmap.py"),
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            "/opt/sqlmap/sqlmap.py",
        ]
        for path in common_paths:
            if os.path.exists(path):
                return f"python {path}" if path.endswith(".py") else path

        return None

    def is_available(self):
        if not self.sqlmap_path:
            return False
        try:
            cmd = self.sqlmap_path.split() + ["--version"]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
                input="\n",
            )
            return result.returncode == 0 or "sqlmap" in result.stdout.lower()
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def _build_base_cmd(self, level, risk, batch):
        cmd = self.sqlmap_path.split()
        cmd.extend(["--level", str(level)])
        cmd.extend(["--risk", str(risk)])

        sqlmap_output = os.path.join(self.output_dir, "sqlmap_results")
        os.makedirs(sqlmap_output, exist_ok=True)
        cmd.extend(["--output-dir", sqlmap_output])
        cmd.extend(["--threads", "1"])
        cmd.extend(["--delay", "1"])

        if batch:
            cmd.append("--batch")

        return cmd

    def _run_process(self, cmd, label="", timeout=600):
        console.print(f"\n  [bold cyan]Commande:[/bold cyan] {' '.join(cmd)}")

        process = None
        timed_out = {"flag": False}
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",   # sortie sqlmap non-cp1252 -> pas de crash Windows
                bufsize=1,
            )

            # Watchdog: kills sqlmap after `timeout` seconds even if it hangs while
            # producing no output (a plain readline loop would block forever otherwise).
            def _kill_on_timeout():
                timed_out["flag"] = True
                try:
                    process.kill()
                except Exception:
                    pass

            watchdog = threading.Timer(timeout, _kill_on_timeout)
            watchdog.start()

            output_lines = []
            vulnerabilities = []

            try:
                for line in iter(process.stdout.readline, ""):
                    line = line.rstrip()
                    output_lines.append(line)

                    lower = line.lower()

                    # Negative indicators - skip these
                    not_vuln = ("not injectable" in lower or "does not seem to be injectable" in lower
                                or "do not appear to be injectable" in lower or "testing " in lower
                                or "tested parameters" in lower or "might not be" in lower)

                    # Positive indicators - real confirmed vulnerabilities
                    is_vuln = (("is vulnerable" in lower or "injectable" in lower or "Payload:" in line)
                               and "[INFO]" in line and not not_vuln)

                    # Confirmed injection type/title (sqlmap output when it FINDS something)
                    is_confirmed = (("Type:" in line or "Title:" in line) and "[INFO]" not in line
                                    and "---" not in line and "testing" not in lower)

                    if is_vuln or is_confirmed:
                        vulnerabilities.append(line)
                        console.print(f"  [bold red]{line}[/bold red]")
                    elif "[INFO]" in line:
                        console.print(f"  [dim]{line}[/dim]")
                    elif "[WARNING]" in line:
                        console.print(f"  [yellow]{line}[/yellow]")
                    elif "[CRITICAL]" in line or "[ERROR]" in line:
                        console.print(f"  [red]{line}[/red]")
            except KeyboardInterrupt:
                # Ctrl+C : tuer sqlmap tout de suite pour que le wait() ci-dessous
                # ne bloque pas, puis laisser remonter (main() sort proprement).
                process.kill()
                console.print("\n  [yellow]Interrompu (Ctrl+C) — sqlmap stoppe.[/yellow]")
                raise
            finally:
                watchdog.cancel()
                process.wait()

            if timed_out["flag"]:
                console.print(f"  [red]Timeout ({timeout // 60} min) - sqlmap interrompu.[/red]")
                return {
                    "label": label,
                    "error": f"Timeout ({timeout // 60} minutes)",
                    "vulnerabilities": vulnerabilities,
                    "output_lines": output_lines,
                    "vulnerable": len(vulnerabilities) > 0,
                }

            # Double-check: if output says "all tested parameters do not appear to be injectable"
            # then it's NOT vulnerable regardless of what was collected
            full_output = "\n".join(output_lines).lower()
            if "do not appear to be injectable" in full_output or "all tested parameters do not" in full_output:
                vulnerabilities = []

            return {
                "label": label,
                "returncode": process.returncode,
                "vulnerabilities": vulnerabilities,
                "output_lines": output_lines,
                "vulnerable": len(vulnerabilities) > 0,
            }

        except Exception as e:
            if process is not None:
                try:
                    process.kill()
                except Exception:
                    pass
            return {"label": label, "error": str(e), "vulnerable": False}

    def _request_file_to_url(self, request_file):
        """Parse a request file and build a full URL + data for sqlmap -u."""
        try:
            with open(request_file, "r") as f:
                lines = f.read().strip().split("\n")

            first_line = lines[0]  # e.g. "GET /path?params HTTP/1.1"
            parts = first_line.split(" ")
            method = parts[0]
            path_query = parts[1] if len(parts) >= 2 else "/"

            host = ""
            scheme = self.scheme          # schema reel de la cible (https en general)
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break

            # Force HTTPS si demande via extra_args
            if any("ssl" in a.lower() or "https" in a.lower() for a in self.extra_args):
                scheme = "https"

            if host:
                full_url = f"{scheme}://{host}{path_query}"
            else:
                full_url = None

            # Extract POST body (everything after blank line)
            body = ""
            blank_found = False
            for line in lines:
                if blank_found:
                    body += line
                elif line.strip() == "":
                    blank_found = True

            return full_url, method, body.strip() if body.strip() else None
        except Exception:
            return None, None, None

    def run_with_request_file(self, request_file, params=None, level=2, risk=2, batch=True, tamper=False):
        if not self.sqlmap_path:
            return {"error": "sqlmap non trouve", "file": request_file}

        # Try to build URL from request file for more reliable sqlmap execution
        full_url, method, body = self._request_file_to_url(request_file)

        cmd = self._build_base_cmd(level, risk, batch)

        if full_url:
            cmd.extend(["-u", full_url])
            if method == "POST" and body:
                cmd.extend(["--data", body])
            if "https://" in full_url:
                cmd.append("--force-ssl")
        else:
            cmd.extend(["-r", request_file])

        if params:
            cmd.extend(["-p", ",".join(params)])

        if tamper:
            cmd.extend(["--tamper", ",".join(TAMPER_SCRIPTS[:3])])

        cmd.extend(self.extra_args)

        result = self._run_process(cmd, label=request_file)
        result["file"] = request_file
        self.results.append(result)

        # If no vuln found and tamper not tried yet, retry with tamper
        if not result.get("vulnerable") and not tamper and not result.get("error"):
            console.print(f"  [yellow]Retry avec tamper scripts (bypass WAF)...[/yellow]")
            result2 = self.run_with_request_file(
                request_file, params, level, risk, batch, tamper=True,
            )
            return result2

        return result

    def run_url_direct(self, url, method="GET", data=None, params=None, level=2, risk=2, batch=True):
        if not self.sqlmap_path:
            return {"error": "sqlmap non trouve", "url": url}

        cmd = self._build_base_cmd(level, risk, batch)
        cmd.extend(["-u", url])

        if method == "POST" and data:
            cmd.extend(["--data", data])

        if params:
            cmd.extend(["-p", ",".join(params)])

        cmd.extend(self.extra_args)

        result = self._run_process(cmd, label=url)
        result["url"] = url
        self.results.append(result)
        return result

    def run_headers_test(self, url, level=3, risk=2, batch=True):
        """Test injectable headers (requires level 3+)."""
        if not self.sqlmap_path:
            return {"error": "sqlmap non trouve"}

        cmd = self._build_base_cmd(max(level, 3), risk, batch)
        cmd.extend(["-u", url])
        # Level 3 tests User-Agent and Referer, level 5 tests Host
        cmd.extend(self.extra_args)

        console.print("  [cyan]Test des headers HTTP (level 3+)...[/cyan]")
        result = self._run_process(cmd, label=f"headers:{url}")
        result["url"] = url
        result["mode"] = "headers"
        self.results.append(result)
        return result

    def run_forms_crawl(self, url, crawl_depth=3, level=2, risk=2, batch=True):
        if not self.sqlmap_path:
            return {"error": "sqlmap non trouve"}

        cmd = self._build_base_cmd(level, risk, batch)
        cmd.extend(["-u", url])
        cmd.extend(["--forms"])
        cmd.extend(["--crawl", str(crawl_depth)])
        cmd.extend(self.extra_args)

        result = self._run_process(cmd, label=f"forms+crawl:{url}")
        result["url"] = url
        result["mode"] = "forms+crawl"
        self.results.append(result)
        return result

    def get_summary(self):
        total = len(self.results)
        vulnerable = sum(1 for r in self.results if r.get("vulnerable"))
        errors = sum(1 for r in self.results if r.get("error"))
        return {
            "total_tests": total,
            "vulnerable": vulnerable,
            "clean": total - vulnerable - errors,
            "errors": errors,
            "details": self.results,
        }
