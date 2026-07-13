"""Image metadata (Jimpl-style) — local EXIF + GPS extraction from a photo.

Runs fully offline with Pillow when the target is a local image file. Surfaces
camera, timestamp and — most usefully — GPS coordinates with a ready map link.
Also links Jimpl for a browser-based deep read.
"""

from __future__ import annotations

from pathlib import Path

from .base import Engine, NEEDS_SETUP, has_module
from ..models import Finding, FindingKind, Confidence, InputType


def _to_degrees(value) -> float:
    d, m, s = value
    return float(d) + float(m) / 60.0 + float(s) / 3600.0


class ImageMetadataEngine(Engine):
    name = "Jimpl/EXIF"
    desc = "Metadonnees & GPS d'une photo (local)"
    modes = ["image"]

    def is_available(self) -> bool:
        return has_module("PIL")

    def status(self) -> str:
        return "live" if has_module("PIL") else NEEDS_SETUP

    def run(self, query: str, input_type: InputType, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(query)
        # Always offer the online Jimpl reader.
        findings.append(Finding(
            source=self.name, title="Ouvrir dans Jimpl (upload navigateur)",
            url="https://jimpl.com/", kind=FindingKind.LINK, confidence=Confidence.LOW,
            note="Upload de la photo pour une lecture EXIF complete"))

        if not has_module("PIL"):
            findings.append(Finding(
                source=self.name, title="Pillow absent (pip install pillow)",
                url="", kind=FindingKind.INFO, confidence=Confidence.LOW))
            return findings
        if not path.is_file():
            return findings

        try:
            from PIL import Image, ExifTags
            img = Image.open(path)
            exif = img.getexif()
            if not exif:
                findings.append(Finding(
                    source=self.name, title="Aucune metadonnee EXIF", url="",
                    kind=FindingKind.INFO, confidence=Confidence.LOW,
                    note="Souvent retire par les reseaux sociaux"))
                return findings

            tagmap = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
            for tag, label in [("Make", "Appareil"), ("Model", "Modele"),
                               ("DateTime", "Date/heure"), ("Software", "Logiciel")]:
                if tagmap.get(tag):
                    findings.append(Finding(
                        source=self.name, title=f"{label}: {tagmap[tag]}", url="",
                        kind=FindingKind.INFO, confidence=Confidence.MEDIUM))

            # GPS
            gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo) if hasattr(ExifTags, "IFD") else {}
            gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_ifd.items()} if gps_ifd else {}
            if gps.get("GPSLatitude") and gps.get("GPSLongitude"):
                lat = _to_degrees(gps["GPSLatitude"])
                lon = _to_degrees(gps["GPSLongitude"])
                if gps.get("GPSLatitudeRef", "N") == "S":
                    lat = -lat
                if gps.get("GPSLongitudeRef", "E") == "W":
                    lon = -lon
                findings.append(Finding(
                    source=self.name, title=f"GPS: {lat:.6f}, {lon:.6f}",
                    url=f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}",
                    kind=FindingKind.INFO, confidence=Confidence.HIGH,
                    note="Coordonnees extraites de la photo", tags=["geo"],
                    data={"lat": lat, "lon": lon}))
        except Exception as e:
            findings.append(Finding(
                source=self.name, title=f"Lecture EXIF impossible: {type(e).__name__}",
                url="", kind=FindingKind.INFO, confidence=Confidence.LOW))
        return findings
