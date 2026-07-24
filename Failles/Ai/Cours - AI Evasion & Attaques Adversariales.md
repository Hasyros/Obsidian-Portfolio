---
title: "Cours — AI Evasion & Attaques Adversariales"
type: cours
domaine: AI Red Teaming
niveau: fondamentaux → intermédiaire
date: 2026-07-23
tags:
  - ai-red-teaming
  - adversarial-ml
  - evasion
  - cours
  - portfolio
---

# AI Evasion & Attaques Adversariales

> [!abstract] Objet du cours
> L'**évasion** est l'attaque qui consiste à modifier une entrée à l'inférence pour provoquer une erreur de classification, sans jamais toucher au modèle ni à ses données d'entraînement.
> Ce cours couvre la taxonomie, la mécanique mathématique, les techniques par modalité, les défenses et leurs limites, et le cadrage opérationnel en red team.

---

## 1. Situer l'évasion dans le paysage des attaques ML

Quatre familles, distinguées par **ce qui est modifié** et **quand** :

| Famille | Cible | Moment | Objectif |
|---|---|---|---|
| **Évasion** | L'entrée | Inférence | Faire mal classer un échantillon précis |
| **Empoisonnement** | Les données | Entraînement | Dégrader ou biaiser le modèle |
| **Backdoor / Trojan** | Données + déclencheur | Entraînement | Comportement caché activé par un motif |
| **Extraction / Inversion** | Rien | Inférence | Voler le modèle ou reconstruire ses données |

L'évasion est la plus accessible en pratique : elle ne demande aucun accès privilégié, seulement la capacité d'interroger le système et de contrôler l'entrée. C'est exactement la posture d'un spammeur, d'un fraudeur, ou d'un attaquant face à un EDR piloté par ML.

### Niveaux d'accès

```
Boîte blanche  →  architecture + poids + gradients        (insider, modèle open-weight, fuite)
Boîte grise    →  architecture connue, poids inconnus     (modèle standard fine-tuné)
Boîte noire    →  requêtes uniquement                     (API commerciale)
   ├─ score-based : la sortie donne des probabilités      ← sondage possible
   └─ label-only  : la sortie donne une classe            ← attaque bien plus coûteuse
```

> [!important] Le vrai facteur discriminant n'est pas blanc/noir mais **score vs label**.
> Une API qui renvoie une probabilité fournit un **substitut de gradient** : chaque requête mesure une dérivée directionnelle. Une API qui ne renvoie que le label force une recherche par frontière, avec un coût en requêtes de plusieurs ordres de grandeur supérieur.

---

## 2. La mécanique de base : modèles linéaires

Tout modèle linéaire — Naive Bayes, régression logistique, SVM linéaire — s'écrit :

$$
f(x) = \langle \omega, x \rangle + b
$$

La décision suit le signe de $f$. **La distance à la frontière est calculable en forme close** :

$$
d(x) = \frac{|f(x)|}{\|\omega\|_2}
$$

Et la perturbation minimale qui fait basculer la décision est colinéaire à $\omega$. En clair : sur un modèle linéaire, l'attaque optimale se calcule, elle ne se cherche pas.

### Cas du Multinomial Naive Bayes

$$
\log \frac{P(y_1 \mid x)}{P(y_0 \mid x)} = \log\frac{P(y_1)}{P(y_0)} + \sum_w c_w \left[\log\theta_{w,y_1} - \log\theta_{w,y_0}\right]
$$

Trois propriétés exploitables :

1. **Linéarité en les comptes** — ajouter un token décale le score d'une constante.
2. **Additivité pure** — l'hypothèse d'indépendance interdit tout effet de contexte amortisseur.
3. **Comptes non bornés** — répéter un token $n$ fois multiplie son effet par $n$.

> [!tip] Formule du budget minimal
> $$n_{\min} = \left\lceil \frac{\text{log-odds initial}}{\max_w |\omega_w|} \right\rceil$$
> Toute la difficulté opérationnelle se réduit à estimer $\omega_w$.

---

## 3. L'attaque GoodWords

### Principe

Face à un filtre statistique, l'attaquant ne cherche pas à masquer le contenu malveillant : il **noie** sa signature sous des tokens fortement associés à la classe bénigne. Le message reste parfaitement lisible pour un humain, mais le vecteur de features a franchi la frontière.

### Origine

Formalisée par **Lowd & Meek (2005)**, *Good Word Attacks on Statistical Spam Filters*, dans le contexte des filtres bayésiens type SpamAssassin. Les auteurs distinguent :

- **Passive attack** — l'attaquant devine les bons mots sans interroger le filtre (dictionnaire, corpus public).
- **Active attack** — l'attaquant sonde le filtre et classe les mots par effet mesuré. Bien plus efficace, mais laisse des traces.

### Procédure active, en boîte noire

```
1. Mesurer le score initial du message
2. Pour chaque mot candidat : mesurer le score de (message + mot)
3. Trier par effet décroissant
4. Injecter jusqu'à basculement, sous contrainte de budget
```

> [!warning] Piège n°1 — la saturation des probabilités
> Sur une entrée à forte confiance, $p \approx 0.9999$ et les deltas de probabilité s'écrasent sous la précision flottante. **Il faut travailler en log-odds** :
> ```python
> logit = lambda p: math.log(p / (1 - p))
> ```
> Sans cette transformation, le classement obtenu est du bruit — et l'attaque peut réussir malgré tout, par robustesse structurelle, ce qui masque le défaut méthodologique.

> [!warning] Piège n°2 — le vocabulaire hors distribution
> Les mots « intuitivement bénins » ne sont pas les mots discriminants du corpus. Sur le dataset UCI SMS (SMS singapouriens), les tokens ham les plus forts sont des marqueurs oraux locaux (`lor`, `lar`, `dun`, `wat`), invisibles pour qui construit sa liste depuis un registre corporate.
> **Le vocabulaire d'attaque doit venir du corpus cible, pas de l'intuition.**

> [!warning] Piège n°3 — ignorer la granularité des features
> Si le vectorizer utilise des n-grammes, injecter une **expression** active simultanément le trigramme, ses bigrammes et ses unigrammes. Le rendement par token injecté est plusieurs fois supérieur à celui d'un mot isolé.

### Transposition

Le même schéma s'applique bien au-delà du spam :

| Domaine | Classe à éviter | Injection |
|---|---|---|
| Modération de contenu | toxique | vocabulaire neutre/institutionnel |
| Détection de phishing | malveillant | boilerplate légitime, mentions légales |
| Scoring de CV | rejeté | mots-clés de l'offre |
| Détection de malware (statique) | malveillant | sections/imports bénins, padding |
| Classification de logs SOC | suspect | motifs d'activité normale |

---

## 4. Le cas continu : attaques par gradient

Sur des entrées continues (images, audio, features numériques), la perturbation peut être infinitésimale, et le gradient est directement calculable.

### FGSM — Fast Gradient Sign Method

**Goodfellow et al., 2014.** Un seul pas dans la direction du signe du gradient de la perte :

$$
x_{adv} = x + \epsilon \cdot \text{sign}(\nabla_x \mathcal{L}(\theta, x, y))
$$

Rapide, faible taux de succès sur modèles durcis. Valeur pédagogique : il montre que la vulnérabilité vient de la **linéarité locale** des réseaux profonds, pas de leur complexité.

### PGD — Projected Gradient Descent

**Madry et al., 2017.** Itération de FGSM avec projection sur la boule $\epsilon$ à chaque pas :

$$
x^{t+1} = \Pi_{B_\epsilon(x)}\left(x^t + \alpha \cdot \text{sign}(\nabla_x \mathcal{L})\right)
$$

Considéré comme l'attaque de référence pour évaluer une défense. Une défense qui ne résiste pas à PGD ne résiste à rien.

### Carlini & Wagner

**2017.** Reformulation en problème d'optimisation cherchant la perturbation de norme **minimale** plutôt qu'une perturbation bornée. Plus lent, plus fort — a cassé une dizaine de défenses publiées comme robustes.

### Boîte noire

- **Transférabilité (Papernot et al., 2016)** — entraîner un modèle substitut local, y calculer l'attaque, la transférer. Fonctionne parce que des modèles différents entraînés sur des distributions proches partagent des frontières de décision proches.
- **Estimation de gradient (ZOO, NES)** — approximer $\nabla_x$ par différences finies. Coûteux en requêtes.
- **Boundary Attack** — partir d'un échantillon déjà classé dans la cible et marcher le long de la frontière. Fonctionne en **label-only**.

---

## 5. La spécificité du texte : l'espace discret

Le gradient ne s'applique pas directement au texte. On ne peut pas ajouter $\epsilon$ à un mot. D'où des familles de techniques distinctes :

| Niveau | Technique | Exemple | Détectabilité |
|---|---|---|---|
| Caractère | Typos, homoglyphes, zero-width | `v1agra`, `раypal` (cyrillique) | Faible pour un humain, forte par normalisation |
| Mot | Substitution par synonymes | `terrible` → `dreadful` | Moyenne |
| Mot | **Injection GoodWords** | ajout de tokens bénins | Faible — le sens original est préservé |
| Phrase | Paraphrase, reformulation LLM | réécriture complète | Très faible |
| Encodage | Base64, ROT13, leetspeak | contournement de filtre naïf | Forte |

> [!note] Pourquoi GoodWords reste la technique de référence pédagogique
> Elle préserve intégralement la lisibilité et l'intention du message original — la contrainte **append-only** garantit qu'aucun caractère du texte source n'est altéré. C'est la démonstration la plus pure du décalage entre *ce que le modèle mesure* et *ce que le texte signifie*.

### Cas particulier : les LLM

L'évasion contre un LLM aligné prend la forme du **jailbreak**, avec des mécaniques voisines :

- suffixes adversariaux optimisés (**GCG**, Zou et al. 2023) — l'équivalent direct de PGD en espace de tokens ;
- injection de prompt directe et indirecte ;
- exploitation du décalage entre distribution d'entraînement et distribution d'attaque (langues peu représentées, encodages inhabituels).

---

## 6. Défenses

### Ce qui fonctionne

| Défense | Mécanisme | Limite |
|---|---|---|
| **Adversarial training** | Entraîner sur des exemples adverses | Coût élevé ; robustesse spécifique à la menace vue |
| **Binarisation des features** | `binary=True` : présence, pas comptage | Casse net la répétition ; perte d'information |
| **Normalisation d'entrée** | Nettoyage HTML, unicode, casse | Contournable par variantes |
| **Ensembles hétérogènes** | Plusieurs modèles de familles différentes | Réduit la transférabilité, ne l'annule pas |
| **Limitation de la sortie** | Label seul, ou probabilité quantifiée | Coût en utilité pour les clients légitimes |
| **Rate limiting** | Quotas par compte/IP | Contournable par distribution |
| **Détection de sondage** | Alerte sur requêtes à préfixe commun | Nécessite une instrumentation dédiée |

### Ce qui ne fonctionne pas

> [!danger] Gradient masking / obfuscated gradients
> **Athalye et al., 2018** a montré que la majorité des défenses publiées entre 2017 et 2018 ne faisaient que **rendre le gradient inutilisable** sans déplacer la frontière de décision. Les attaques adaptées (BPDA, EOT) les cassent toutes.
>
> Signe d'alerte : une défense qui résiste à FGSM mais dont le taux de succès ne se dégrade pas quand on augmente le budget de l'attaque. Cela signale un artefact d'optimisation, pas de la robustesse.

### Le compromis fondamental

**Tsipras et al., 2019** : robustesse et précision sont en tension. Un modèle robuste apprend des features causales, plus rares et moins prédictives sur la distribution naturelle. Gagner en robustesse coûte en performance nominale — et ce coût doit être un choix explicite, pas une découverte en production.

---

## 7. Méthodologie de red team

### Étapes

```
1. Reconnaissance
   ├─ Le système utilise-t-il du ML ? Où, dans quelle décision ?
   ├─ Quelle modalité d'entrée est sous contrôle de l'attaquant ?
   └─ Quel est le format de sortie (label ? score ? explication ?)

2. Caractérisation de l'oracle
   ├─ Coût, latence, rate limit
   ├─ Granularité de la sortie
   └─ Le système journalise-t-il les requêtes ?

3. Estimation
   ├─ Boîte blanche : lire les poids
   ├─ Score-based : sondage en log-odds sur entrée NEUTRE
   └─ Label-only : recherche par frontière, ou substitut local

4. Construction
   ├─ Respecter les contraintes du domaine (le texte doit rester lisible,
   │  le malware doit rester exécutable, l'image doit rester plausible)
   └─ Minimiser la perturbation ET le nombre de requêtes

5. Validation
   ├─ Taux de succès sur un échantillon, pas sur un cas
   └─ Robustesse : l'attaque tient-elle après un ré-entraînement ?

6. Reporting
   ├─ Impact métier, pas score technique
   └─ Correctifs par rapport coût/efficacité
```

> [!important] L'erreur méthodologique la plus fréquente
> **Confondre « l'attaque a réussi » et « la méthode est bonne ».**
> Une approche robuste par construction (budget généreux, modèle linéaire, vocabulaire large) réussit même quand l'estimation sous-jacente est du bruit pur. Il faut vérifier que le **signal mesuré est réel** — sinon la technique s'effondre silencieusement dès que les conditions se durcissent.
>
> Test de contrôle : comparer le budget consommé par l'attaque guidée à celui d'une attaque à vocabulaire aléatoire. Sans écart, il n'y a pas de guidage.

### Contraintes de domaine

Une perturbation n'est valide que si elle préserve la fonction de l'objet :

| Domaine | Contrainte dure |
|---|---|
| Texte | Lisibilité, préservation du sens |
| Malware | Le binaire doit rester exécutable et fonctionnel |
| Réseau | Les paquets doivent rester valides et routables |
| Image physique | Robustesse à l'angle, la lumière, l'impression |
| Finance | Les features doivent rester mutuellement cohérentes |

C'est ce qui sépare une attaque de laboratoire d'une attaque réelle. Une perturbation en norme $L_\infty$ sur un vecteur de features de transaction bancaire n'a aucun sens si elle produit un âge négatif.

---

## 8. Cadres de référence

- **MITRE ATLAS** — matrice ATT&CK adaptée au ML. Chaîne type de l'évasion : *reconnaissance → accès au modèle ML → fabrication de données adverses → évasion du modèle*.
- **OWASP Machine Learning Security Top 10** — l'évasion (*adversarial attack*) y figure au premier rang.
- **OWASP Top 10 for LLM Applications** — prompt injection, jailbreak, et leurs variantes indirectes.
- **NIST AI 100-2** — taxonomie et terminologie de l'adversarial machine learning ; référence utile pour cadrer un rapport.

---

## 9. Points à retenir

1. **La vulnérabilité est structurelle, pas accidentelle.** Elle découle de la géométrie des frontières de décision apprises, pas d'un bug d'implémentation.
2. **Le format de sortie est la surface d'attaque principale.** Exposer une probabilité, c'est offrir un gradient.
3. **Travailler en log-odds, pas en probabilité.** La saturation détruit l'information exactement là où elle est utile.
4. **Le vocabulaire d'attaque vient du corpus, pas de l'intuition.**
5. **Une attaque réussie ne valide pas la méthode.** Vérifier que le signal existe avant d'attribuer le succès au guidage.
6. **Le sondage est bruyant.** 179 requêtes à préfixe commun sont détectables — la discrétion se conçoit dès la phase d'estimation.
7. **La défense la plus rentable est souvent la plus simple.** Binariser un vectorizer coûte une ligne et annule toute la classe d'attaques par répétition.

---

## Références

- Dalvi et al. (2004) — *Adversarial Classification*, KDD
- Lowd & Meek (2005) — *Good Word Attacks on Statistical Spam Filters*, CEAS
- Szegedy et al. (2013) — *Intriguing Properties of Neural Networks*
- Biggio et al. (2013) — *Evasion Attacks against ML at Test Time*
- Goodfellow et al. (2014) — *Explaining and Harnessing Adversarial Examples* (FGSM)
- Papernot et al. (2016) — *Practical Black-Box Attacks against ML*
- Carlini & Wagner (2017) — *Towards Evaluating the Robustness of Neural Networks*
- Madry et al. (2017) — *Towards Deep Learning Models Resistant to Adversarial Attacks* (PGD)
- Athalye et al. (2018) — *Obfuscated Gradients Give a False Sense of Security*
- Tsipras et al. (2019) — *Robustness May Be at Odds with Accuracy*
- Zou et al. (2023) — *Universal and Transferable Adversarial Attacks on Aligned Language Models* (GCG)

---

## Liens

- [[HTB - AI Evasion - GoodWords & Feature Obfuscation]] — application pratique
- [[HTB - Attacking AI - Application and System]] — attaques système contre les déploiements ML
