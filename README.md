<p align="center">
  <img src="./app/resource/images/logo.png">
</p>

# PenToolBox

PenToolBox est un un outil développé dans le cadre du projet de ma première année de master en ingénierie en cybersécurité.

## Introduction

Cet outil a été conçu dans le but d'aider les professionnels de la cybersécurité à évaluer la sécurité des systèmes informatiques en identifiant les vulnérabilités.

## Fonctionnalités

- **Reconnaissance**: Exploration des systèmes cibles pour collecter des informations initiales sur les cibles potentielles.
- **Scanning**: Analyse des systèmes pour identifier les ports ouverts, les services en cours d'exécution et les vulnérabilités connues.
- **Exploitation**: Utilisation des vulnérabilités détectées pour accéder aux systèmes cibles et obtenir un accès non autorisé.
- **Post-Exploitation**: Phase de maintien de l'accès et d'exploration plus approfondie des systèmes compromis.
- **Reporting**: Génération de rapports détaillés pour documenter les résultats des tests de pénétration.

## Commentaires

Veuillez noter que l'outil est encore en phase de développement initial.  
Par conséquent, il n'est pas compilé et nécessite d'être lancé via Python en utilisant main.py.

## Installation

Pour installer l'outil, suivez ces étapes :

1. Clonez ce dépôt sur votre machine locale.
2. Assurez-vous d'avoir les dépendances requises installées.

```console
git clone https://github.com/KarimGhazlaoui/ASI-M1CB-PenToolBox.git
cd ASI-M1CB-PenToolBox
pip install -r requirements.txt
```

3. Lancez l'application en exécutant le script principal.
```console
python main.py
```

Ces commandes vont récupérer votre dépôt depuis GitHub et installer les dépendances requises pour exécuter votre application PenToolBox.

## Contribution
Les contributions sont les bienvenues ! Si vous souhaitez contribuer à ce projet, n'hésitez pas à ouvrir une issue pour discuter des changements que vous souhaitez apporter.

## Licence
Ce projet est sous licence <span style="font-size:1.5em; font-weight:bold;">GPL-2.0</span>.
