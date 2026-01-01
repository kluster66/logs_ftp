import boto3
import argparse
import json
import os
import sys
import random
import logging
from datetime import datetime
from typing import List, Optional, Set
from botocore.exceptions import ClientError

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def lire_et_filtrer_logs(
    chemin_fichier: str, 
    max_chars: int = 150000, 
    keywords: Optional[List[str]] = None,
    context_lines: int = 3
) -> str:
    """
    Lit le fichier de logs et filtre les entrées intéressantes.
    Optimisé pour les gros fichiers : parcourt tout le fichier et garde le contexte.
    """
    if not os.path.exists(chemin_fichier):
        logger.error(f"Le fichier '{chemin_fichier}' n'existe pas.")
        sys.exit(1)

    suspicious_keywords = keywords or [
        'FAIL', 'error', 'denied', 'refused', 'incorrect', 
        '530', '550', '421', 'root', 'admin'
    ]
    
    important_lines = []
    buffer = [] # Pour garder le contexte précédent
    total_lines = 0
    selected_count = 0
    
    logger.info(f"Analyse du fichier : {chemin_fichier}...")
    
    try:
        with open(chemin_fichier, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                total_lines += 1
                line_lower = line.lower()
                
                # On garde un buffer circulaire pour le contexte
                buffer.append(line)
                if len(buffer) > context_lines + 1:
                    buffer.pop(0)
                
                is_suspicious = any(k.lower() in line_lower for k in suspicious_keywords)
                is_connection = 'connect' in line_lower or 'ok login' in line_lower
                
                if is_suspicious or is_connection:
                    # Ajouter le contexte si ce n'est pas déjà fait
                    if is_suspicious and len(buffer) > 1:
                        important_lines.append(f"--- CONTEXTE ---\n" + "".join(buffer[:-1]))
                        # On vide le buffer pour ne pas le rajouter plusieurs fois
                        buffer = [line]
                    
                    important_lines.append(line)
                    selected_count += 1
                elif random.random() < 0.005: # 0.5% d'échantillon pour le volume global
                    important_lines.append(f"[ECHANTILLON] {line}")
                    selected_count += 1

                # Vérification de la taille périodiquement
                if len("".join(important_lines)) > max_chars * 1.2:
                    # Si on dépasse vraiment trop, on fait une purge intelligente
                    # (On garde les 1000 premières et les 1000 dernières lignes par exemple)
                    logger.warning("Limite de taille approchée, échantillonnage plus agressif activé.")
                    if len(important_lines) > 2000:
                        important_lines = important_lines[:1000] + ["\n... [TRONQUÉ AU MILIEU] ...\n"] + important_lines[-1000:]
        
        final_content = "".join(important_lines)
        if len(final_content) > max_chars:
            logger.info(f"Tronquage final à {max_chars} caractères.")
            final_content = final_content[:max_chars] + "\n... [FIN TRONQUÉE] ..."

        logger.info(f"Analyse terminée : {total_lines} lignes lues. {selected_count} segments sélectionnés.")
        return final_content

    except Exception as e:
        logger.error(f"Erreur lors de la lecture : {e}")
        sys.exit(1)

def analyser_avec_bedrock(
    contenu_log: str, 
    model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0", 
    region: str = "us-west-2"
) -> str:
    """Envoie les logs à Amazon Bedrock pour analyse cybersécurité."""
    logger.info(f"Initialisation AWS (Région: {region}, Modèle: {model_id})...")
    
    try:
        bedrock_runtime = boto3.client(service_name='bedrock-runtime', region_name=region)
    except Exception as e:
        logger.error(f"Échec initialisation AWS : {e}")
        sys.exit(1)

    system_prompt = (
        "Tu es un expert en cybersécurité senior (SOC Analyst). "
        "Ton rôle est d'analyser des logs FTP pré-filtrés pour détecter des anomalies, "
        "des tentatives de bruteforce, ou des exfiltrations de données."
    )

    user_message = (
        f"Voici un extrait de logs FTP. Note: certains passages sont échantillonnés ou contiennent du contexte.\n\n"
        f"<logs>\n{contenu_log}\n</logs>\n\n"
        "Produis un rapport de sécurité en Markdown structuré comme suit :\n"
        "1. **Résumé Exécutif** (Niveau de risque global)\n"
        "2. **Indicateurs de Compromission (IoCs)** : IPs suspectes, comptes visés.\n"
        "3. **Chronologie des Événements** : Analyse des séquences suspectes.\n"
        "4. **Actions Correctives Immédiates** (Blocage IP, changement de mot de passe, etc.)."
    )

    payload = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "temperature": 0.0,
        "messages": [{"role": "user", "content": user_message}],
        "system": system_prompt
    }

    try:
        logger.info("Analyse en cours par l'IA...")
        response = bedrock_runtime.invoke_model(
            body=json.dumps(payload),
            modelId=model_id,
            accept='application/json',
            contentType='application/json'
        )
        response_body = json.loads(response.get('body').read())
        return response_body.get('content')[0].get('text')
    except ClientError as e:
        logger.error(f"Erreur API Bedrock : {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erreur inattendue lors de l'appel IA : {e}")
        sys.exit(1)

def sauvegarder_rapport(contenu: str, chemin: str) -> None:
    try:
        with open(chemin, 'w', encoding='utf-8') as f:
            f.write(contenu)
        logger.info(f"Rapport généré avec succès : {chemin}")
    except Exception as e:
        logger.error(f"Erreur lors de l'écriture du rapport : {e}")

def main():
    parser = argparse.ArgumentParser(
        description="🚀 Analyseur de Logs FTP intelligent via Amazon Bedrock.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("logfile", help="Chemin vers le fichier de logs")
    parser.add_argument("--output", "-o", default="rapport_securite.md", help="Nom du fichier de sortie")
    parser.add_argument("--max-size", type=int, default=150000, help="Limite de caractères envoyés à l'IA")
    parser.add_argument("--context", type=int, default=3, help="Nombre de lignes de contexte avant chaque alerte")
    parser.add_argument("--keywords", nargs='+', help="Mots-clés personnalisés à filtrer")
    parser.add_argument("--region", "-r", default="us-west-2", help="Région AWS")
    parser.add_argument("--model", "-m", default="anthropic.claude-3-sonnet-20240229-v1:0", help="ID du modèle Bedrock")
    parser.add_argument("--verbose", "-v", action="store_true", help="Active le mode verbeux (DEBUG)")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # 1. Pipeline de traitement
    start_time = datetime.now()
    
    log_content = lire_et_filtrer_logs(
        args.logfile, 
        max_chars=args.max_size, 
        keywords=args.keywords,
        context_lines=args.context
    )

    if not log_content.strip():
        logger.warning("Aucune donnée pertinente identifiée. Fin du traitement.")
        sys.exit(0)

    # 2. IA
    rapport = analyser_avec_bedrock(log_content, model_id=args.model, region=args.region)

    # 3. Sortie
    sauvegarder_rapport(rapport, args.output)
    
    duration = datetime.now() - start_time
    logger.info(f"Temps total d'exécution : {duration.total_seconds():.2f} secondes.")

if __name__ == "__main__":
    main()
