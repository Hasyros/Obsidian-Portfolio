---

titre: "Planning HTB Academy — Été 2026 (Red Team Track)"

plateforme: "Hack The Box Academy"

abonnement: "Student (Tier 0–II)"

periode: "2026-07-01 → 2026-08-31"

objectif: "Maximiser les modules complétés, trajectoire offensive/red team, départ API & IA"

tags: [HTB, Planning, RedTeam, Roadmap, Tracker, Notes]

---

  

# Planning HTB Academy — Été 2026 (Red Team Track)

  

> **Hypothèse de rythme** : ~20–25 h/semaine (≈ 3–4 h/jour sur 6 jours). Les durées HTB sont des estimations *généreuses* : en prenant des notes Obsidian comme d'habitude, compte le temps affiché ; en allant droit au but, souvent moins.

> **Règle d'or** : tout module fini = **cube** (ownership permanent côté Student) + **note Obsidian**. La note fait partie du livrable, pas un extra.

> Ajuste : si tu as plus/moins de temps, tu avances plus ou moins loin dans l'ordre — la **séquence** reste bonne.

  

---

  

## Logique du parcours (pourquoi cet ordre)

  

```

Phase 1 — API & IA        ← ton point de départ choisi (et marché très porteur)

   │

Phase 2 — Web offensive   ← consolider TA force (SSRF/CRLF/LFI/upload), tu vas vite

   │

Phase 3 — Post-exploit    ← shells, creds, privesc, pivoting : le pont vers le red team

   │

Phase 4 — Active Directory ← le cœur du red teaming (l'objectif stage)

```

  

Cette trajectoire **web → AD** est exactement celle d'un pentester offensif qui monte vers le red team. **Bonus CV** : ~80 % de ces modules composent le job-role path **Penetration Tester → CPTS** (très bien vu chez DGA / Orange Cyberdefense / Sopra). On ne le vise pas frontalement, mais on l'avance « gratuitement ».

  

### État de départ (déjà acquis)

- ✅ Nmap · SQLi Fundamentals · Web Requests · Intro Web Applications · **XSS**

- 🔄 En cours à finir vite : **API Attacks** (7 %), **SQLMap Essentials** (45 %), **Login Brute Forcing**

  

---

  

## Phase 1 — API & IA (Semaines 1–2)

  

Ton départ. On enchaîne API puis le bloc IA offensive (le plus différenciant aujourd'hui).

  

### Semaine 1 — API

- [ ] **API Attacks** *(finir — déjà à 7 %)* — ~1 j

- [ ] **Web Service & API Attacks** *(Medium, 7h)* — SOAP/REST, attaques API classiques

- [ ] **Attacking GraphQL** *(mini, Medium, 1j)* — introspection, injection GraphQL

  

### Semaine 2 — IA offensive (Red Teaming AI)

- [ ] **Introduction to Red Teaming AI** *(Medium, 4h)* — le bon point d'entrée

- [ ] **Prompt Injection Attacks** *(Medium, 1j)* — direct/indirect, jailbreaks

- [ ] **LLM Output Attacks** *(Medium, 1j)* — exploitation des sorties (XSS via LLM, etc. → résonne avec ton module XSS)

- [ ] **Attacking AI - Application and System** *(Medium, 1j)*

- *(prérequis légers si besoin de contexte ML : **Fundamentals of AI**, **Applications of AI in InfoSec** — General, 1j chacun)*

  

> 🎯 Stretch (si IA te passionne, sinon plus tard) : **AI Data Attacks** *(Hard, 3j)*, **AI Evasion - Foundations** *(Medium, 1j)*. Le reste de la série AI Evasion (First-Order, Sparsity) est *Hard* et demande des bases ML solides → à garder pour après l'été.

  

---

  

## Phase 2 — Web offensive (Semaines 3–4)

  

Ta zone de confort : tu vas vite, donc on en met beaucoup. C'est aussi le cœur du quotidien d'un pentester web et ça muscle ton bug bounty (Yogosha).

  

### Outils & dette technique d'abord

- [ ] **Using Web Proxies** *(Easy, 1j)* — Burp/Caido à fond *(tu avais setup Caido/Burp : la note te resservira)*

- [ ] **SQLMap Essentials** *(finir — 45 %)*

- [ ] **Login Brute Forcing** *(finir)*

  

### Le gros bloc web

- [ ] **File Inclusion** *(Medium, 1j)* — LFI/RFI, log poisoning

- [ ] **Command Injections** *(Medium, 6h)*

- [ ] **File Upload Attacks** *(Medium, 1j)*

- [ ] **Web Attacks** *(Medium, 2j)* — ⭐ **SSRF, CRLF, IDOR** → pile tes sujets de prédilection

- [ ] **Server-side Attacks** *(Medium, 1j)* — SSRF avancé, SSTI

  

> 🎯 Stretch web : **Broken Authentication** *(2j)*, **Session Security** *(7h — complète parfaitement ta note Session Hijacking)*, **Hacking WordPress** *(6h — tu viens d'en faire en XSS)*, **Information Gathering - Web Edition** *(1j)*.

  

---

  

## Phase 3 — Post-exploitation / socle Red Team (Semaines 5–6)

  

Le pont entre le web et le red teaming. Indispensable pour passer de « j'ai un point d'entrée » à « je tiens le réseau ».

  

- [ ] **Shells & Payloads** *(Medium, 2j)* — reverse/bind shells, génération de payloads

- [ ] **Using the Metasploit Framework** *(Easy, 5h)*

- [ ] **Password Attacks** *(Medium, 1j)*

- [ ] **Cracking Passwords with Hashcat** *(Medium, 1j)* — synergie directe avec Password Attacks

- [ ] **Linux Privilege Escalation** *(Easy, 1j)*

- [ ] **Pivoting, Tunneling, and Port Forwarding** *(Medium, 2j)* — ⭐ compétence red team clé

  

> Prérequis utile si Windows te manque : **Windows Fundamentals** *(6h)* avant la Phase 4.

  

---

  

## Phase 4 — Active Directory, le cœur du Red Team (Semaines 7–9)

  

L'aboutissement de la trajectoire et **le** sujet attendu en entretien red team.

  

### Semaine 7 — Bases AD

- [ ] **Introduction to Active Directory** *(Fundamental, 7h)*

- [ ] **Windows Privilege Escalation** *(Medium, 4j)* — gros, mais central *(peut déborder S8)*

  

### Semaines 8–9 — Le morceau de roi

- [ ] **Active Directory Enumeration & Attacks** *(Medium, 7j)* — ⭐⭐ LE module red team par excellence (Kerberos, BloodHound, lateral movement). À étaler sur ~2 semaines.

- [ ] **Attacking Common Services** *(Medium, 1j)* — SMB/RDP/etc., si temps restant

  

> 🎯 Stretch / suite naturelle après l'été : **Attacking Common Applications** *(4j)*, **Attacking Enterprise Networks** *(2j — la synthèse type assessment réel)*.

  

---

  

## Tableau de bord (vue rapide)

  

| Phase | Thème | Modules cœur | Charge estimée |

|---|---|---|---|

| 1 | API & IA | 7 | ~2 sem |

| 2 | Web offensive | 8 | ~2 sem |

| 3 | Post-exploit | 6 | ~2 sem |

| 4 | Active Directory | 4 | ~2,5 sem |

| — | **Total cœur** | **~25 modules** | **~9 sem** |

  

---

  

## Méthode de travail (ce qui fait la différence)

  

- **1 module = 1 note Obsidian** + le(s) flag(s) en frontmatter. Ton système de notes est déjà ton meilleur atout — il transforme chaque module en ressource réutilisable *et* en preuve concrète pour les entretiens.

- **MOC par domaine** : crée un index `Web Offensive MOC`, `Red Team AD MOC`… qui lie les notes. Le graphe devient ton « cours » personnel.

- **Pratique active** : après chaque bloc, enchaîne 1–2 **box HTB** sur le thème (ou un challenge) pour ancrer. Les modules donnent la théorie, les box donnent les réflexes.

- **Cubes** : finis les modules à 100 % (questions comprises) pour l'ownership permanent Student.

- **Anti-enlisement** : si un module *Hard* te bloque > 1,5× son temps estimé, parke-le (note « à reprendre ») et avance. Le momentum > la complétion linéaire.

  

## Garde-fous réalistes

- Le total « cœur » est **ambitieux mais atteignable** à 20–25 h/sem. À 12–15 h/sem, vise Phases 1–3 + bases AD (et garde la Phase 4 lourde pour septembre).

- **Windows Privilege Escalation (4j)** et **AD Enum & Attacks (7j)** sont les deux gros poids : si le temps manque, ce sont eux qu'on étale ou décale, pas les phases 1–2.

- Bloque **1 créneau/semaine** pour réviser tes notes de la semaine (consolidation > accumulation).

  

---

  

## Suivi hebdo (à remplir)

  

| Sem. | Dates | Objectif | Fait ? | Note |

|---|---|---|---|---|

| 1 | 30/06–06/07 | API | ⬜ | |

| 2 | 07/07–13/07 | IA offensive | ⬜ | |

| 3 | 14/07–20/07 | Web (outils + LFI/CMDi) | ⬜ | |

| 4 | 21/07–27/07 | Web (upload/SSRF/SSTI) | ⬜ | |

| 5 | 28/07–03/08 | Shells + creds | ⬜ | |

| 6 | 04/08–10/08 | PrivEsc + pivoting | ⬜ | |

| 7 | 11/08–17/08 | Bases AD + Win privesc | ⬜ | |

| 8 | 18/08–24/08 | AD Enum & Attacks (1/2) | ⬜ | |

| 9 | 25/08–31/08 | AD Enum & Attacks (2/2) | ⬜ | |

  

---

  

## Liens

- [[Cross-Site Scripting (XSS) — Fondamentaux, Stored & Reflected]]

- [[Outillage — WSL2, Exegol, VPN HTB & serveur d'exfiltration]]