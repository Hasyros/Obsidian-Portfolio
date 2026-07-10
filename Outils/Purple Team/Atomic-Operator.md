---
titre: "Atomic-Operator"
tags: [Outils, purple-team, MITRE, ATT&CK, detection]
source: https://github.com/swimlane/atomic-operator
---

# Atomic-Operator

**Exécution des tests Atomic Red Team** (mappés à **MITRE ATT&CK**) sur Windows,
Linux et macOS. Sert au **purple teaming** : rejouer des techniques d'attaque pour
**valider la détection** (SIEM/EDR) et repérer les angles morts défensifs.

> ⚠️ Exécute de vraies techniques offensives : **uniquement sur des machines de
> test qu'on contrôle**. Cf. `README`.

## Téléchargement / installation
```bash
pip install atomic-operator
# ou depuis les sources
git clone https://github.com/swimlane/atomic-operator.git
cd atomic-operator && pip install -r requirements.txt && python setup.py install
```

## Utilisation
```bash
# 1) récupérer la base Atomic Red Team
atomic-operator get_atomics --destination /opt/atomics

# 2) lancer une technique précise (avec sélection du test)
atomic-operator run --techniques T1564.001 --select_tests --atomics-path /opt/atomics

# arguments custom / exécution distante
atomic-operator run --techniques T1564.001 --input_arguments '{"key":"value"}'
atomic-operator run --atomics-path /opt/atomics --hosts 10.32.1.10 --username user --password pass
```
API Python :
```python
from atomic_operator import AtomicOperator
op = AtomicOperator()
op.get_atomics('/opt/atomics')
op.run(technique='T1564.001', atomics_path='/opt/atomics', check_prereqs=True, cleanup=True)
```

## Réflexe
Toujours activer le **cleanup** après un test. Corréler chaque technique jouée
avec ce que voit la défense (alerte levée ou non) → mesurer la couverture ATT&CK.
Ressources : https://attack.mitre.org/ · https://github.com/redcanaryco/atomic-red-team
