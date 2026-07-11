"""
Loot Manager - Stockage et affichage des donnees extraites par cible.
Chaque cible a un fichier JSON + une page HTML generee automatiquement.
Les nouveaux scans completent les donnees existantes.
"""

import os
import json
from datetime import datetime
from urllib.parse import urlparse


class LootStore:
    def __init__(self, output_dir="output"):
        self.output_dir = output_dir
        self.loot_dir = os.path.join(output_dir, "loot")
        os.makedirs(self.loot_dir, exist_ok=True)
        self.target = None
        self.target_key = None
        self.data = {}

    def set_target(self, url):
        """Set the current target and load existing loot."""
        parsed = urlparse(url)
        self.target = parsed.netloc or url
        self.target_key = self.target.replace(":", "_").replace("/", "_")
        self._load()

    def _json_path(self):
        return os.path.join(self.loot_dir, f"{self.target_key}.json")

    def _html_path(self):
        return os.path.join(self.loot_dir, f"{self.target_key}.html")

    def _load(self):
        path = self._json_path()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        else:
            self.data = {
                "target": self.target,
                "first_seen": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "server_info": {},
                "entries": [],
            }

    def _save(self):
        self.data["last_updated"] = datetime.now().isoformat()
        with open(self._json_path(), "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        self._generate_html()

    def set_server_info(self, info):
        """Update server info (OS, DBMS, tech, etc). Merges with existing."""
        if "server_info" not in self.data:
            self.data["server_info"] = {}
        self.data["server_info"].update(info)
        self._save()

    def add_entry(self, category, title, data, columns=None, query=None):
        """
        Add a loot entry. Deduplicates by (category, title).
        If same (category, title) exists, it updates the data.

        category: credentials, databases, tables, nas, config, query, file, dump, info
        title: description of the entry
        data: list of dicts or list of lists
        columns: column headers if data is list of lists
        query: SQL query used (optional)
        """
        timestamp = datetime.now().isoformat()

        # Find existing entry with same category+title
        existing = None
        for entry in self.data.get("entries", []):
            if entry["category"] == category and entry["title"] == title:
                existing = entry
                break

        if existing:
            existing["data"] = data
            existing["columns"] = columns
            existing["updated"] = timestamp
            if query:
                existing["query"] = query
        else:
            self.data.setdefault("entries", []).append({
                "category": category,
                "title": title,
                "data": data,
                "columns": columns,
                "query": query,
                "created": timestamp,
                "updated": timestamp,
            })

        self._save()

    def add_raw(self, category, title, text):
        """Add raw text content (file reads, etc)."""
        self.add_entry(category, title, [{"content": text}])

    def get_entries(self, category=None):
        """Get entries, optionally filtered by category."""
        entries = self.data.get("entries", [])
        if category:
            return [e for e in entries if e["category"] == category]
        return entries

    def get_html_path(self):
        return self._html_path()

    def _generate_html(self):
        """Generate a beautiful HTML loot page."""
        entries = self.data.get("entries", [])
        server = self.data.get("server_info", {})
        target = self.data.get("target", "?")
        first_seen = self.data.get("first_seen", "")[:19].replace("T", " ")
        last_updated = self.data.get("last_updated", "")[:19].replace("T", " ")

        # Group entries by category
        categories_order = [
            ("info", "Informations Serveur", "#3498db"),
            ("credentials", "Identifiants", "#e74c3c"),
            ("databases", "Bases de Donnees", "#9b59b6"),
            ("tables", "Tables", "#8e44ad"),
            ("nas", "Equipements Reseau (NAS)", "#e67e22"),
            ("config", "Configurations", "#f39c12"),
            ("dump", "Donnees Extraites (Dump)", "#2ecc71"),
            ("query", "Resultats de Requetes SQL", "#1abc9c"),
            ("file", "Fichiers Lus sur le Serveur", "#e74c3c"),
            ("nosqli", "Injections NoSQL", "#ff6348"),
            ("xss", "Cross-Site Scripting (XSS)", "#ff4757"),
            ("recon", "Reconnaissance", "#0984e3"),
            ("osint", "OSINT", "#6c5ce7"),
            ("elk", "Elasticsearch / Kibana", "#00b894"),
            ("ai", "Analyse IA", "#fdcb6e"),
        ]

        grouped = {}
        for entry in entries:
            cat = entry["category"]
            grouped.setdefault(cat, []).append(entry)

        # Server info section
        server_html = ""
        if server:
            rows = ""
            for key, val in server.items():
                rows += f"<tr><td class='key'>{_esc(key)}</td><td>{_esc(str(val))}</td></tr>\n"
            server_html = f"""
            <div class="card info-card">
                <h2>Serveur</h2>
                <table class="info-table">{rows}</table>
            </div>"""

        # Category sections
        sections_html = ""
        for cat_id, cat_name, cat_color in categories_order:
            cat_entries = grouped.pop(cat_id, [])
            if not cat_entries:
                continue

            entries_html = ""
            for entry in cat_entries:
                entries_html += _render_entry(entry, cat_color)

            sections_html += f"""
            <div class="section">
                <h2 style="border-left: 4px solid {cat_color}; padding-left: 12px;">{cat_name}
                    <span class="badge" style="background:{cat_color}">{len(cat_entries)}</span>
                </h2>
                {entries_html}
            </div>"""

        # Remaining categories
        for cat_id, cat_entries in grouped.items():
            entries_html = ""
            for entry in cat_entries:
                entries_html += _render_entry(entry, "#95a5a6")
            sections_html += f"""
            <div class="section">
                <h2 style="border-left: 4px solid #95a5a6; padding-left: 12px;">{_esc(cat_id)}
                    <span class="badge">{len(cat_entries)}</span>
                </h2>
                {entries_html}
            </div>"""

        total_entries = len(entries)

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Loot - {_esc(target)}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #0a0e17;
    color: #e0e0e0;
    line-height: 1.6;
}}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
header {{
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    padding: 30px;
    border-radius: 12px;
    margin-bottom: 24px;
    border: 1px solid #1a3a5c;
}}
header h1 {{ color: #00d4ff; font-size: 28px; margin-bottom: 8px; }}
header .target {{ color: #ff6b6b; font-size: 20px; font-family: monospace; }}
header .meta {{ color: #888; font-size: 13px; margin-top: 12px; }}
header .meta span {{ margin-right: 20px; }}
.stats {{
    display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap;
}}
.stat-card {{
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 10px;
    padding: 16px 24px;
    flex: 1;
    min-width: 150px;
    text-align: center;
}}
.stat-card .num {{ font-size: 32px; font-weight: bold; color: #00d4ff; }}
.stat-card .label {{ font-size: 12px; color: #888; text-transform: uppercase; }}
.section {{ margin-bottom: 24px; }}
.section h2 {{
    font-size: 18px;
    margin-bottom: 12px;
    color: #fff;
    display: flex;
    align-items: center;
    gap: 10px;
}}
.badge {{
    font-size: 12px;
    padding: 2px 8px;
    border-radius: 12px;
    background: #374151;
    color: #fff;
}}
.card {{
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 12px;
}}
.card h3 {{
    font-size: 15px;
    color: #00d4ff;
    margin-bottom: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}}
.card h3 .time {{ font-size: 11px; color: #555; font-weight: normal; }}
.card .query {{
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 8px 12px;
    font-family: monospace;
    font-size: 12px;
    color: #7ee787;
    margin-bottom: 10px;
    overflow-x: auto;
}}
table.data {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}
table.data th {{
    background: #1f2937;
    color: #9ca3af;
    text-align: left;
    padding: 8px 12px;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 2px solid #374151;
}}
table.data td {{
    padding: 6px 12px;
    border-bottom: 1px solid #1f2937;
    max-width: 400px;
    overflow: hidden;
    text-overflow: ellipsis;
    word-break: break-all;
}}
table.data tr:hover td {{ background: #1a2332; }}
table.data tr:nth-child(even) td {{ background: #0f1520; }}
table.data tr:nth-child(even):hover td {{ background: #1a2332; }}
.info-table {{ width: auto; }}
.info-table td {{ padding: 4px 16px 4px 0; }}
.info-table .key {{ color: #9ca3af; font-weight: 600; }}
.raw-content {{
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 12px;
    font-family: monospace;
    font-size: 12px;
    white-space: pre-wrap;
    max-height: 400px;
    overflow-y: auto;
    color: #c9d1d9;
}}
.highlight {{ color: #ff6b6b; font-weight: bold; }}
.info-card {{ border-left: 3px solid #3498db; }}
footer {{
    text-align: center;
    padding: 20px;
    color: #555;
    font-size: 12px;
    border-top: 1px solid #1f2937;
    margin-top: 30px;
}}
</style>
</head>
<body>
<div class="container">

<header>
    <h1>Loot Report</h1>
    <div class="target">{_esc(target)}</div>
    <div class="meta">
        <span>Premier scan: {first_seen}</span>
        <span>Derniere MAJ: {last_updated}</span>
    </div>
</header>

<div class="stats">
    <div class="stat-card">
        <div class="num">{total_entries}</div>
        <div class="label">Donnees collectees</div>
    </div>
    <div class="stat-card">
        <div class="num">{len(grouped.get('credentials', grouped.get('dump', [])))+len([e for e in entries if e['category']=='credentials'])}</div>
        <div class="label">Identifiants</div>
    </div>
    <div class="stat-card">
        <div class="num">{len([e for e in entries if e['category']=='file'])}</div>
        <div class="label">Fichiers lus</div>
    </div>
    <div class="stat-card">
        <div class="num">{_esc(server.get('DBMS', '?'))}</div>
        <div class="label">DBMS</div>
    </div>
</div>

{server_html}
{sections_html}

<footer>
    SQLi Auto-Auditor - Loot Report | Genere le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</footer>

</div>
</body>
</html>"""

        with open(self._html_path(), "w", encoding="utf-8") as f:
            f.write(html)


def _esc(text):
    """Escape HTML."""
    if not text:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _render_entry(entry, color):
    """Render a single loot entry as HTML."""
    title = entry.get("title", "")
    data = entry.get("data", [])
    columns = entry.get("columns")
    query = entry.get("query")
    created = entry.get("created", "")[:16].replace("T", " ")
    updated = entry.get("updated", "")[:16].replace("T", " ")
    time_str = updated if updated != created else created

    html = f"""<div class="card">
        <h3>{_esc(title)} <span class="time">{time_str}</span></h3>"""

    if query:
        html += f'<div class="query">{_esc(query)}</div>'

    if not data:
        html += '<p style="color:#666">Aucune donnee</p>'
    elif isinstance(data, list) and len(data) > 0:
        # Check if it's raw content
        if isinstance(data[0], dict) and "content" in data[0] and len(data[0]) == 1:
            content = data[0]["content"]
            html += f'<div class="raw-content">{_esc(content)}</div>'
        elif isinstance(data[0], dict):
            # Table from dict list
            keys = list(data[0].keys())
            if columns:
                keys = columns
            html += '<table class="data"><thead><tr>'
            for k in keys:
                html += f"<th>{_esc(k)}</th>"
            html += "</tr></thead><tbody>"
            for row in data:
                html += "<tr>"
                for k in keys:
                    val = row.get(k, "") if isinstance(row, dict) else ""
                    cell = str(val) if val is not None else ""
                    # Highlight passwords/secrets
                    if any(kw in k.lower() for kw in ["password", "secret", "pass", "key", "hash"]):
                        html += f'<td class="highlight">{_esc(cell)}</td>'
                    else:
                        html += f"<td>{_esc(cell)}</td>"
                html += "</tr>"
            html += "</tbody></table>"
        elif isinstance(data[0], list):
            # Table from list of lists
            html += '<table class="data"><thead><tr>'
            if columns:
                for c in columns:
                    html += f"<th>{_esc(c)}</th>"
            html += "</tr></thead><tbody>"
            for row in data:
                html += "<tr>"
                for cell in row:
                    html += f"<td>{_esc(str(cell))}</td>"
                html += "</tr>"
            html += "</tbody></table>"

    html += "</div>"
    return html
