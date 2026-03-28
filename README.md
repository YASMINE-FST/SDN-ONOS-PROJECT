# Projet PFE SDN avec ONOS et RYU

## 📦 Données nécessaires
Les fichiers volumineux (captures réseau, datasets complets) sont disponibles sur demande :
- Captures PCAP (6.8 Go) : [À télécharger séparément]
- Datasets CSV : inclus dans le dossier `dataset/` (fichiers locaux)
- Modèles ML : générables via `train_and_visualize.py`

## 🚀 Installation
1. Clonez ce dépôt
2. Installez les dépendances : `pip install -r requirements.txt`
3. Placez les fichiers PCAP dans `ONOS-IDS-main/dataset/captures/`
4. Exécutez les scripts

## 📂 Structure
- `ONOS-IDS-main/` : Code pour ONOS et l'IDS
- `SDN-ML-CONTROLLER-main-RYU/` : Contrôleurs RYU et ML
- `Projet-dhcp-option43/` : Tests DHCP
- `NOTES/` : Documentation

## ⚠️ Note
Les fichiers > 100 Mo (PCAP, modèles) ne sont pas versionnés sur GitHub. Contactez l'auteur pour les obtenir.
