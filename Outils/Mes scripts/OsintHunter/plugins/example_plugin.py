"""
Example plugin engine for OSINT Hunter.

Place any .py file in this directory to add custom engines.
Each file must define at least one class that inherits from Engine.

Usage:
    1. Copy this file as a starting point
    2. Rename the class and fill in name/desc/modes
    3. Implement is_available() and scan()
    4. Restart OSINT Hunter — the engine auto-loads

Example:
    plugins/my_custom_engine.py
"""

from osint_hunter.engines.base import Engine
from osint_hunter.models import InputType


class ExamplePluginEngine(Engine):
    name = ""  # Set to "" to disable; set a name to enable (e.g., "MyEngine")
    desc = "Example plugin engine"
    modes = ["username"]

    def is_available(self) -> bool:
        return True

    def scan(self, query: str, input_type: InputType, **kwargs) -> list[dict]:
        # Your custom OSINT logic here
        # Must return a list of dicts with "site" and "url" keys
        # Example:
        # return [{"site": "MyService", "url": f"https://example.com/user/{query}"}]
        return []
