<p align="center">
  <img src="./app/resource/images/logo.png">
</p>

# PenToolBox

PenToolBox est un un outil développé dans le cadre du projet de ma première année de master en ingénierie en cybersécurité.

## Introduction

Cet outil a été conçu dans le but d'aider les professionnels de la cybersécurité à évaluer la sécurité des systèmes informatiques en identifiant les vulnérabilités.

Exclusivement fonctionnel sur Windows actuellement, il incorpore des fonctionnalités inédites tel que l'intégration complète de Kali.
Permettant ainsi d'utiliser les derniers outils de pentesting disponible sans aucunte limite, tout en permettant en cas de besoin d'avoir la main directement sur celle-ci.


## Fonctionnalités Clé

<p align="center">
  <img src="./images/demo.gif">
</p>

- **Reconnaissance**: Exploration des systèmes cibles pour collecter des informations initiales sur les cibles potentielles.
- **Scanning**: Analyse des systèmes pour identifier les ports ouverts, les services en cours d'exécution et les vulnérabilités connues.
- **Exploitation**: Utilisation des vulnérabilités détectées pour accéder aux systèmes cibles et obtenir un accès non autorisé.
- **Post-Exploitation**: Phase de maintien de l'accès et d'exploration plus approfondie des systèmes compromis.
- **Reporting**: Génération de rapports détaillés pour documenter les résultats des tests de pénétration.

<p align="center">
  <img src="./images/rapport.gif">
</p>

## Commentaires

Veuillez noter que l'outil est encore en phase de développement. 
Des bugs critique peuvent encore exister.

## Utilisation

✨ Une version compilé pour windows est disponible ✨

Plus simple et plus rapide à mettre en oeuvre, à télécharger ci-dessous :

[Page des releases](https://github.com/KarimGhazlaoui/ASI-M1CB-PenToolBox/releases/tag/executable)<br>

## Installation manuelle

Pour installer les dépendances nécessaires à ce projet, vous pouvez utiliser le fichier `requirements.txt` fourni. Exécutez la commande suivante :

1. Clonez ce dépôt sur votre machine locale.
  ```console
  git clone https://github.com/KarimGhazlaoui/ASI-M1CB-PenToolBox.git
  cd ASI-M1CB-PenToolBox
  ```

2. Installer Microsoft C++ Build Tools - Développement Desktop en C++ (Obligatoire pour netifaces) 

    [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools)<br>


3. Assurez-vous d'avoir les dépendances requises installées.
  ```console
  pip install -r requirements.txt
  ```
  3.1. Installation manuel des packages

  Si vous préférez installer les packages individuellement, vous pouvez utiliser les commandes suivantes :
  ```console
  pip install paramiko
  pip install "PyQt-Fluent-Widgets[full]" -i https://pypi.org/simple/
  pip install netifaces
  pip install qvncwidget
  pip install reportlab
  pip install bs4
  ```

5. Télécharger kali.qcow2 et déplacer le dans le répertoire \app\qemu\kali
   
     [Cliquer ici pour télécharger kali.qcow2](https://drive.google.com/file/d/19TkXSNwm6RxxnFsOpfuVuTnsTJIXfvee/view?usp=sharing)<br>
     
6. Lancez l'application en exécutant le script principal.
  ```console
  python main.py
  ```



## Contribution
Les contributions sont les bienvenues ! Si vous souhaitez contribuer à ce projet, n'hésitez pas à ouvrir une issue pour discuter des changements que vous souhaitez apporter.

## Licence
Ce projet est sous licence <span style="font-size:1.5em; font-weight:bold;">GPL-3.0</span>.

### Licences des Composants Utilisés

- PyQt5 : Licence GPL v3
- Qemu : Licence GPL v2
- Kali : Licence GPL v3
- attrs : Licence MIT
- bcrypt : Licence Apache 2.0
- cffi : Licence MIT
- chardet : Licence LGPL v2.1
- colorthief : Licence MIT
- cryptography : Licence Apache 2.0
- darkdetect : Licence MIT
- freetype-py : Licence GPL v3
- Jinja2 : Licence BSD
- MarkupSafe : Licence BSD
- netifaces : Licence MIT
- numpy : Licence BSD
- paramiko : Licence LGPL v2.1
- pillow : Licence HPND
- pyasn1 : Licence BSD
- pyasn1_modules : Licence BSD
- pycairo : Licence LGPL v2.1
- pycparser : Licence BSD
- pyDes : Licence MIT
- PyNaCl : Licence Apache 2.0
- PyPDF2 : Licence BSD
- PyQt-Fluent-Widgets : Licence LGPL v3
- PyQt5-Frameless-Window : Licence MIT
- PyQt5-Qt5 : Licence GPL v3
- PyQt5-sip : Licence GPL v3
- pywin32 : Licence PSF
- qvncwidget : Licence GPL v3
- reportlab : Licence BSD
- rlPyCairo : Licence MIT
- scipy : Licence BSD
- service-identity : Licence MIT
- six : Licence MIT
