"""Engine registry — auto-discovers built-in + plugin engines."""

from .base import Engine, debug_log
from .maigret import MaigretEngine
from .sherlock import SherlockEngine
from .blackbird import BlackbirdEngine
from .nexfil import NexfilEngine
from .socialscan import SocialscanEngine
from .holehe import HoleheEngine
from .hibp import HIBPEngine
from .leakcheck import LeakCheckEngine
from .breachdir import BreachDirEngine
from .whatsmyname import WhatsMyNameEngine
from .directprobe import DirectProbeEngine
from .theharvester import TheHarvesterEngine
from .googledork import GoogleDorkEngine
from .peoplesearch import PeopleSearchEngine
from .emailfinder import EmailFinderEngine
from .wayback import WaybackEngine
from .github_api import GitHubApiEngine
from .dns_whois import DnsWhoisEngine
from .hunter_io import HunterIOEngine
from .dehashed import DehashedEngine
from .epieos import EpieosEngine
from .phoneinfoga import PhoneInfogaEngine

BUILTIN_ENGINES = [
    MaigretEngine(),
    SherlockEngine(),
    BlackbirdEngine(),
    NexfilEngine(),
    SocialscanEngine(),
    HoleheEngine(),
    HIBPEngine(),
    LeakCheckEngine(),
    BreachDirEngine(),
    WhatsMyNameEngine(),
    DirectProbeEngine(),
    TheHarvesterEngine(),
    GoogleDorkEngine(),
    PeopleSearchEngine(),
    EmailFinderEngine(),
    WaybackEngine(),
    GitHubApiEngine(),
    DnsWhoisEngine(),
    HunterIOEngine(),
    DehashedEngine(),
    EpieosEngine(),
    PhoneInfogaEngine(),
]


def load_plugin_engines(plugin_dir: str = "plugins") -> list[Engine]:
    """Load Engine subclasses from plugin_dir/*.py."""
    import importlib.util
    from pathlib import Path

    engines = []
    pdir = Path(plugin_dir)
    if not pdir.is_dir():
        return engines
    for py in sorted(pdir.glob("*.py")):
        if py.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(py.stem, str(py))
        if not spec or not spec.loader:
            continue
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            debug_log(f"plugin:{py.name}", e)
            continue
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if (isinstance(obj, type)
                    and issubclass(obj, Engine)
                    and obj is not Engine
                    and hasattr(obj, "name")
                    and obj.name):
                try:
                    engines.append(obj())
                except Exception as e:
                    debug_log(f"plugin:{py.name}", e)
    return engines


def get_all_engines(plugin_dir: str = "plugins") -> list[Engine]:
    return BUILTIN_ENGINES + load_plugin_engines(plugin_dir)
