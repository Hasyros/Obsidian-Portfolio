"""GHDB — curated Google Hacking Database dork templates (fully offline).

Generates ready-to-click Google queries adapted to the target type. For domains
it focuses on public exposure-surface recon (indexes, exposed documents), which
is standard for authorized assessments. No network calls — just link generation.
"""

from __future__ import annotations

from urllib.parse import quote_plus

from .base import Engine
from ..models import Finding, FindingKind, Confidence, InputType

# category -> list of dork templates using {q}
_BY_TYPE: dict[str, list[tuple[str, str]]] = {
    "name": [
        ("Reseaux sociaux", '"{q}" (site:linkedin.com OR site:facebook.com OR site:instagram.com)'),
        ("Documents", '"{q}" (filetype:pdf OR filetype:doc OR filetype:docx)'),
        ("CV / resume", '"{q}" (CV OR resume OR "curriculum vitae")'),
        ("Presentations", '"{q}" (filetype:ppt OR filetype:pptx OR site:slideshare.net)'),
        ("Mentions presse", '"{q}" (interview OR biographie OR profil)'),
        ("Coordonnees", '"{q}" (email OR "@" OR telephone OR contact)'),
    ],
    "username": [
        ("Profils", '"{q}" (site:github.com OR site:reddit.com OR site:gitlab.com)'),
        ("Forums", '"{q}" (inurl:member OR inurl:user OR inurl:profile)'),
        ("Pastes", '"{q}" (site:pastebin.com OR site:paste.ee OR site:ghostbin.com)'),
        ("Mentions", '"{q}"'),
    ],
    "email": [
        ("Mentions email", '"{q}"'),
        ("Pastes", '"{q}" (site:pastebin.com OR site:throwbin.io OR site:paste.ee)'),
        ("Documents", '"{q}" (filetype:pdf OR filetype:xlsx OR filetype:csv)'),
        ("Fuites forums", '"{q}" (inurl:forum OR inurl:member)'),
    ],
    "domain": [
        ("Index listings", 'site:{q} intitle:"index of"'),
        ("Documents exposes", 'site:{q} (filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv)'),
        ("Pages de login", 'site:{q} (inurl:login OR inurl:admin OR inurl:signin)'),
        ("Config / logs", 'site:{q} (ext:log OR ext:env OR ext:conf OR ext:bak)'),
        ("Sous-domaines", 'site:*.{q} -site:www.{q}'),
        ("Fichiers backup", 'site:{q} (ext:sql OR ext:zip OR ext:tar OR ext:gz)'),
    ],
    "phone": [
        ("Mentions numero", '"{q}"'),
        ("Reseaux sociaux", '"{q}" (site:facebook.com OR site:linkedin.com)'),
        ("Annuaires", '"{q}" (annuaire OR whitepages OR "pages blanches")'),
    ],
}


class GHDBEngine(Engine):
    name = "GHDB"
    desc = "Google Hacking DB — dorks cliquables (offline)"
    modes = ["name", "username", "email", "domain", "phone"]

    def is_available(self) -> bool:
        return True

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        templates = _BY_TYPE.get(input_type.value, [])
        findings: list[Finding] = []
        for label, tpl in templates:
            dork = tpl.replace("{q}", query)
            findings.append(Finding(
                source=self.name, title=f"GHDB: {label}",
                url=f"https://www.google.com/search?q={quote_plus(dork)}",
                kind=FindingKind.DORK, confidence=Confidence.LOW, note=dork))
        return findings
