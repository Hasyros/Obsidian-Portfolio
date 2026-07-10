---
titre: "Jimpl"
tags: [Outils, OSINT, exif, metadonnees, geoloc]
source: https://jimpl.com/
---

# Jimpl

**Visualiseur de métadonnées d'image en ligne.** Service web
(**[jimpl.com](https://jimpl.com/)**) qui extrait les **métadonnées EXIF/IPTC/XMP**
d'une photo : appareil, date/heure de prise, réglages, et surtout les
**coordonnées GPS** si présentes — affichées directement sur une carte.

> ⚠️ N'analyser que des fichiers qu'on est autorisé à traiter. Cf. `README`.

## Utilisation
1. Aller sur [jimpl.com](https://jimpl.com/), glisser-déposer l'image (ou l'URL).
2. Lire les champs : `Make/Model`, `DateTimeOriginal`, `GPS Latitude/Longitude`.
3. Cliquer la position GPS pour l'ouvrir sur une carte.

Aucune installation ; pratique quand on n'a pas d'accès terminal. Pour un usage
hors-ligne / scriptable, préférer [[exiftool]] :
```bash
exiftool -gpslatitude -gpslongitude -datetimeoriginal photo.jpg
```

## Réflexe
Les réseaux sociaux **strippent** souvent l'EXIF : Jimpl est surtout utile sur
des fichiers bruts (envoyés en pièce jointe, trouvés sur un serveur). Coordonnées
trouvées → recouper avec [[Overpass Turbo]] et la géoloc visuelle.
