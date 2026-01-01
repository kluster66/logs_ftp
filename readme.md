# 🚀 Analyseur de Logs FTP via Amazon Bedrock (IA)

Ce projet est un outil en ligne de commande (CLI) écrit en Python qui utilise l'intelligence artificielle générative (**Amazon Bedrock** avec **Claude 3**) pour analyser automatiquement les fichiers de logs FTP.

Il est spécialement conçu pour traiter des fichiers volumineux (ex: 100 Mo+) grâce à un système de pré-filtrage intelligent qui ne transmet à l'IA que les données pertinentes (erreurs, tentatives d'intrusion, connexions).

---

## ✨ Fonctionnalités

- **🧠 Analyse IA** : Détecte les attaques par force brute, les accès non autorisés et les comportements suspects.
- **📁 Support Gros Fichiers** : Lit les fichiers en mode "streaming" et filtre localement. Le nouveau système parcourt l'intégralité du fichier pour ne rien rater, même sur des logs de plusieurs Go.
- **🔍 Contexte étendu** : Capture automatiquement les lignes précédant une erreur pour une meilleure analyse par l'IA.
- **📄 Rapports Automatiques** : Génère un rapport de sécurité détaillé au format Markdown (`.md`).
- **⚙️ Flexible** : Entièrement paramétrable via la ligne de commande (mots-clés, taille, contexte, modèles).

---

## 📋 Prérequis

- **Python 3.8+** installé sur votre machine.
- Un **compte AWS** actif.
- L'accès au modèle **Claude 3 Sonnet** activé dans la console Amazon Bedrock (région `us-west-2` par défaut).

---

## 🛠️ Installation

1. Clonez ce dépôt ou téléchargez le script `ftp_log_analyzer.py`.
2. Installez les dépendances via le fichier `requirements.txt` :

```bash
pip install -r requirements.txt
```

---

## 🔐 Configuration AWS

Le script utilise les identifiants AWS configurés sur votre machine. Vous pouvez les configurer de deux manières :

### Option A : Via AWS CLI (Recommandé)

```bash
aws configure
# Entrez votre Access Key ID
# Entrez votre Secret Access Key
# Entrez la région par défaut (ex: us-west-2)
```

### Option B : Via variables d'environnement

```bash
export AWS_ACCESS_KEY_ID=votre_cle_acces
export AWS_SECRET_ACCESS_KEY=votre_cle_secrete
export AWS_DEFAULT_REGION=us-west-2
```

---

## 🚀 Utilisation

La commande de base nécessite simplement le chemin vers votre fichier de log :

```bash
python ftp_log_analyzer.py /chemin/vers/vsftpd.log
```

### Options avancées

| Argument | Description | Défaut |
| :--- | :--- | :--- |
| `logfile` | Le fichier de logs à analyser (**obligatoire**). | N/A |
| `--output`, `-o` | Nom du fichier de rapport généré. | `rapport_securite.md` |
| `--max-size` | Limite de caractères envoyés à l'IA. | `150000` |
| `--context` | Nombre de lignes de contexte avant chaque alerte. | `3` |
| `--keywords` | Mots-clés personnalisés (ex: `--keywords error critical`). | Mots-clés par défaut |
| `--region`, `-r` | Région AWS pour Bedrock. | `us-west-2` |
| `--model`, `-m` | ID du modèle Bedrock à utiliser. | `anthropic.claude-3-sonnet-20240229-v1:0` |
| `--verbose`, `-v` | Active le mode DEBUG pour voir le détail du filtrage. | `False` |

### Exemples

**Analyse avec contexte étendu et mots-clés spécifiques :**
```bash
python ftp_log_analyzer.py vsftpd.log --context 5 --keywords critical panic
```

**Mode verbeux pour débugger le filtrage :**
```bash
python ftp_log_analyzer.py server.log -v
```

---

## ⚙️ Comment ça marche ? (Logique de filtrage)

Pour gérer des fichiers massifs de manière optimale :

1. **Lecture en flux** : Le script parcourt le fichier ligne par ligne sans le charger en mémoire.
2. **Buffer de Contexte** : Il conserve un historique glissant des dernières lignes. Lorsqu'une erreur est détectée, le script inclut ces lignes pour aider l'IA.
3. **Scan Intégral** : Contrairement à l'ancienne version, il scanne tout le fichier pour identifier les erreurs partout, pas seulement au début.
4. **Purge Intelligente** : Si le volume d'erreurs dépasse la limite, il conserve les segments les plus récents et les plus anciens (échantillonnage de tête et de queue).
5. **Analyse Claude 3** : L'IA reçoit un condensé hyper-pertinent pour rédiger le rapport final.

---

## 📊 Structure du Rapport

Le rapport généré contiendra :

1. **Synthèse** : Vue d'ensemble de la sécurité.
2. **Analyse des Menaces** : IPs attaquantes, comptes visés, types d'erreurs.
3. **Recommandations** : Actions concrètes (Fail2Ban, règles pare-feu, etc.).
