"""Engine registry."""

from __future__ import annotations

from .base import Engine, LIVE, NEEDS_SETUP, ASSISTED

from .username_maigret import MaigretEngine
from .username_sherlock import SherlockEngine
from .username_whatsmyname import WhatsMyNameEngine
from .username_directprobe import DirectProbeEngine
from .socialscan import SocialscanEngine
from .email_holehe import HoleheEngine
from .email_hibp import HIBPEngine
from .email_ghunt import GHuntEngine
from .email_epieos import EpieosEngine
from .dork_google import GoogleDorkEngine
from .dork_ghdb import GHDBEngine
from .phone_phoneinfoga import PhoneInfogaEngine
from .web_wayback import WaybackEngine
from .framework_spiderfoot import SpiderFootEngine
from .framework_recon_ng import ReconNgEngine
from .image_metadata import ImageMetadataEngine
from .image_reverse import ReverseImageEngine
from .geo_overpass import OverpassEngine
from .domain_dns import DomainDnsEngine

# Order matters for display + scan order (fast/self-verifying first).
BUILTIN_ENGINES: list[Engine] = [
    MaigretEngine(),
    SherlockEngine(),
    WhatsMyNameEngine(),
    DirectProbeEngine(),
    SocialscanEngine(),
    HoleheEngine(),
    HIBPEngine(),
    GHuntEngine(),
    EpieosEngine(),
    GoogleDorkEngine(),
    GHDBEngine(),
    PhoneInfogaEngine(),
    WaybackEngine(),
    DomainDnsEngine(),
    SpiderFootEngine(),
    ReconNgEngine(),
    ImageMetadataEngine(),
    ReverseImageEngine(),
    OverpassEngine(),
]


def get_all_engines() -> list[Engine]:
    return list(BUILTIN_ENGINES)
