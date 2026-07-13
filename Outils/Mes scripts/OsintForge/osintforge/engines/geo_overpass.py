"""Overpass Turbo — build OpenStreetMap queries around coordinates.

If the target is a geotagged image, we read its GPS and build an Overpass QL
query for nearby amenities plus an overpass-turbo.eu link. The
``overpass_for_coords`` helper is reused by the TUI's Geo menu for arbitrary
coordinates or a place name.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from .base import Engine, ASSISTED, has_module
from ..models import Finding, FindingKind, Confidence, InputType


def _overpass_query(lat: float, lon: float, radius: int = 250) -> str:
    return (
        "[out:json][timeout:25];\n"
        f"( node(around:{radius},{lat:.6f},{lon:.6f})[amenity];\n"
        f"  node(around:{radius},{lat:.6f},{lon:.6f})[shop];\n"
        f"  way(around:{radius},{lat:.6f},{lon:.6f})[building]; );\n"
        "out center;"
    )


def overpass_for_coords(lat: float, lon: float, radius: int = 250) -> list[Finding]:
    q = _overpass_query(lat, lon, radius)
    turbo = f"https://overpass-turbo.eu/?Q={quote(q)}&C={lat:.6f};{lon:.6f};17"
    return [
        Finding(source="Overpass", title=f"POIs OSM autour de {lat:.5f},{lon:.5f}",
                url=turbo, kind=FindingKind.LINK, confidence=Confidence.MEDIUM,
                note=f"Rayon {radius} m — clic = execute dans Overpass Turbo",
                tags=["geo"], data={"query": q}),
        Finding(source="OpenStreetMap", title="Voir la zone sur OSM",
                url=f"https://www.openstreetmap.org/#map=18/{lat:.6f}/{lon:.6f}",
                kind=FindingKind.LINK, confidence=Confidence.MEDIUM, tags=["geo"]),
        Finding(source="Google Maps", title="Voir sur Google Maps",
                url=f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}",
                kind=FindingKind.LINK, confidence=Confidence.MEDIUM, tags=["geo"]),
    ]


def _read_gps(path: Path):
    try:
        from PIL import Image, ExifTags
        exif = Image.open(path).getexif()
        gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
        gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
        if not (gps.get("GPSLatitude") and gps.get("GPSLongitude")):
            return None
        d, m, s = gps["GPSLatitude"]
        lat = float(d) + float(m) / 60 + float(s) / 3600
        d, m, s = gps["GPSLongitude"]
        lon = float(d) + float(m) / 60 + float(s) / 3600
        if gps.get("GPSLatitudeRef", "N") == "S":
            lat = -lat
        if gps.get("GPSLongitudeRef", "E") == "W":
            lon = -lon
        return lat, lon
    except Exception:
        return None


class OverpassEngine(Engine):
    name = "Overpass"
    desc = "OSM/Overpass Turbo autour d'un point"
    modes = ["image"]

    def is_available(self) -> bool:
        return True

    def status(self) -> str:
        return ASSISTED

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        path = Path(query)
        if has_module("PIL") and path.is_file():
            coords = _read_gps(path)
            if coords:
                return overpass_for_coords(*coords)
        # No GPS -> generic guidance.
        return [Finding(
            source="Overpass", title="Overpass Turbo (requetes OSM)",
            url="https://overpass-turbo.eu/", kind=FindingKind.LINK,
            confidence=Confidence.LOW,
            note="Photo sans GPS — utiliser le menu Geo (G) avec des coordonnees")]
