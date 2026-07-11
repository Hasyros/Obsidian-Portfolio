"""PhoneInfoga — phone number OSINT."""

import re
import os

import requests

from .base import Engine, has_binary, run_cmd, console
from ..models import InputType


class PhoneInfogaEngine(Engine):
    name = "PhoneInfoga"
    desc = "OSINT sur numero de telephone"
    modes = ["phone"]

    def is_available(self) -> bool:
        return has_binary("phoneinfoga")

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        results = []

        # Clean phone number
        phone = re.sub(r"[\s\-().]+", "", query.strip())
        if not phone.startswith("+"):
            phone = "+" + phone

        # PhoneInfoga CLI
        if has_binary("phoneinfoga"):
            out, err, rc = run_cmd(["phoneinfoga", "scan", "-n", phone])
            combined = out + "\n" + err

            for line in combined.splitlines():
                line = line.strip()
                if not line or line.startswith("--"):
                    continue
                # Extract carrier, country, line type info
                for pattern, label in [
                    (r"Country:\s*(.+)", "Pays"),
                    (r"Carrier:\s*(.+)", "Operateur"),
                    (r"Line Type:\s*(.+)", "Type"),
                    (r"International:\s*(.+)", "International"),
                ]:
                    m = re.search(pattern, line, re.I)
                    if m:
                        results.append({
                            "site": f"[Phone] {label}: {m.group(1).strip()}",
                            "url": f"https://phoneinfoga.crvx.fr/",
                        })

            # Google dorks for phone
            for dork_template in [
                'intext:"{phone}" site:facebook.com',
                'intext:"{phone}" site:linkedin.com',
                '"{phone}"',
            ]:
                dork = dork_template.replace("{phone}", phone)
                results.append({
                    "site": f"[Phone] Dork: {dork[:50]}",
                    "url": f"https://www.google.com/search?q={requests.utils.quote(dork)}",
                })

        # Numverify API (if key available)
        cfg = kwargs.get("config")
        nv_key = ""
        if cfg:
            nv_key = cfg.api_keys.numverify
        if not nv_key:
            nv_key = os.environ.get("OSINT_NUMVERIFY_KEY", "")

        if nv_key:
            try:
                r = requests.get(
                    "http://apilayer.net/api/validate",
                    params={"access_key": nv_key, "number": phone, "format": 1},
                    timeout=10,
                )
                if r.status_code == 200:
                    data = r.json()
                    if data.get("valid"):
                        parts = []
                        if data.get("country_name"):
                            parts.append(f"Pays: {data['country_name']}")
                        if data.get("carrier"):
                            parts.append(f"Operateur: {data['carrier']}")
                        if data.get("line_type"):
                            parts.append(f"Type: {data['line_type']}")
                        if parts:
                            results.append({
                                "site": f"[Numverify] {' | '.join(parts)}",
                                "url": "https://numverify.com",
                            })
            except Exception:
                pass

        return results
