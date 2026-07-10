---
titre: "Overpass Turbo"
tags: [Outils, OSINT, geoint, openstreetmap]
source: https://github.com/tyrasd/overpass-turbo
---

# Overpass Turbo

**Data mining géospatial sur OpenStreetMap.** Interface web pour écrire et tester
des requêtes **Overpass API** et visualiser les résultats sur une carte. Très
utile en **géo-OSINT** (géolocalisation d'une photo, recherche de POI :
antennes, éoliennes, fast-foods, panneaux…).

## Accès
- Stable : **[overpass-turbo.eu](https://overpass-turbo.eu/)** (aucune installation)
- Dev : https://tyrasd.github.io/overpass-turbo/
- Auto-hébergement :
```bash
git clone https://github.com/tyrasd/overpass-turbo.git
cd overpass-turbo && pnpm install && pnpm run start   # http://localhost:5173
```

## Utilisation
1. Écrire une requête en **Overpass QL** (ou bouton **Assistant/Wizard** pour la
   générer en langage naturel : `amenity=fast_food in Paris`).
2. **Exécuter** (Run) → les objets s'affichent sur la carte.
3. **Exporter** (GeoJSON, GPX, KML…) ou partager via URL.

Exemple — toutes les boulangeries dans la zone visible :
```overpassql
[out:json][timeout:25];
nwr["shop"="bakery"]({{bbox}});
out center;
```

## Réflexe géo-OSINT
Partir d'indices visuels d'une photo (type de commerce, langue, forme de
route/pylône) → traduire en tags OSM → requêter la zone suspectée pour recouper.
Combiner avec [[Jimpl]] (EXIF/GPS) et la géoloc visuelle.
