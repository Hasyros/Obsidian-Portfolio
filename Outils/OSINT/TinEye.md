---
titre: "TinEye"
tags: [Outils, OSINT, reverse-image-search]
source: https://tineye.com/
---

# TinEye

**Recherche d'image inversée.** Service web (**[tineye.com](https://tineye.com/)**)
qui retrouve **où** une image apparaît sur le web à partir d'une empreinte visuelle
(pas d'une recherche par mots-clés). Utile pour dater une photo, retrouver la
source originale, détecter des réutilisations / faux profils.

## Utilisation
1. Sur [tineye.com](https://tineye.com/), uploader l'image ou coller son URL.
2. Trier les résultats par **Oldest** (retrouver la 1ʳᵉ apparition → source) ou
   **Most changed / Biggest image**.
3. Une extension navigateur permet le clic-droit → « Search on TinEye ».

TinEye excelle sur les **recadrages/retouches** (moteur par signature). Le croiser
avec **Google Lens** et **Yandex Images** (souvent meilleur sur les visages/lieux)
pour couvrir plus de bases.

## Réflexe OSINT
Sur un profil suspect : reverse-search la photo → si elle apparaît sur des banques
d'images ou d'autres identités = **faux compte** probable.
