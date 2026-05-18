
VUE D'ENSEMBLE
--------------
Ce module couvre la détection hybride pour les logs Firewall :
1. Pipeline ML (Isolation Forest) pour la détection comportementale d'anomalies.
2. Règles Sigma pour la détection déterministe de menaces connues.
Tous les artefacts sont alignés sur le schéma ECS, validés sur données invisibles,
et prêts pour l'intégration API/Kibana.

ORDRE D'EXÉCUTION (STRICT)
--------------------------
python preprocess_firewall.py
python train_firewall.py
python evaluate_firewall.py

Déja fait -> Génère les fichiers dans models/ et results/

================================================================================
I. SCRIPTS PYTHON (src/)
================================================================================
Fichier                  | Rôle Technique                          | Action Requise (Autres Équipes)
-------------------------|-----------------------------------------|----------------------------------
preprocess_firewall.py   | Feature engineering (4 ratios),         | BACKEND: Doit réimplémenter
                         | normalisation StandardScaler sur base-  | EXACTEMENT ces calculs de ratios
                         | line "allow".                           | et appliquer le même scaler avant
                         |                                         | tout scoring temps réel.

train_firewall.py        | Split 80/20, entraînement Isolation     | BACKEND: Aucun traitement en prod.
                         | Forest (contamination=0.35), export .pkl| Charge simplement les .pkl générés
                         |                                         | au démarrage du service.

evaluate_firewall.py     | Validation sur données invisibles,      | FRONTEND/SOC: Utilise le CSV
                         | calcul métriques, export scoré Kibana.  | généré pour calibrer les seuils
                         |                                         | d'alerte et créer les dashboards.

xai_explainer.py         | Module XAI complet : mapping ECS →      | BACKEND: Appelle directement
                         | Features, calcul ratios, application    | explain_firewall_alert(log_ecs)
                         | du scaler, scoring IA & explication     | ou l'endpoint FastAPI associé.
                         | SHAP.                                   | 
                         |

================================================================================
II. ARTÉFACTS GÉNÉRÉS (models/ & results/)
================================================================================
Fichier                  | Rôle Technique                          | Action Requise (Autres Équipes)
-------------------------|-----------------------------------------|----------------------------------
firewall_isolation.pkl   | Modèle IA entraîné (100 arbres,         | BACKEND: Le charge dans FastAPI
                         | contamination=0.35).                    | pour exécuter .predict() et
                         |                                         | .decision_function().

firewall_scaler_test.pkl | Contient le StandardScaler, la liste    | BACKEND: Extrait scaler/features
                         | exacte des FEATURES et le set de test.  | pour garantir la même transfor-
                         |                                         | mation qu'à l'entraînement.

firewall_eval_kibana.csv | Dataset scoré (true_label, prediction,  | FRONTEND: Import dans Kibana
                         | anomaly_score) prêt pour visualisation. | (Upload CSV) pour visualiser la
                         |                                         | distribution des scores.

================================================================================
III. RÈGLES SIGMA (sigma/)
================================================================================
Fichier                  | Rôle Technique                          | Action Requise (Autres Équipes)
-------------------------|-----------------------------------------|----------------------------------
port_scan.yaml           | Détection Port Scan (>30 ports TCP/min).| SOC/BACKEND: Compile avec
                         | MITRE ATT&CK: T1046 (Network Scanning). | sigmac -t elasticsearch, teste
                         |                                         | la requête JSON sur ES, active
                         |                                         | dans Kibana Detection Engine.

ddos_flood.yaml          | Détection Flood/DDoS (>500KB & >500     | SOC/BACKEND: Compile sigmac ->
                         | paquets/5s). MITRE ATT&CK: T1498 (DoS). | test requête -> déploiement
                         |                                         | Kibana (sévérité critical).

ssh_bruteforce.yaml      | Détection Brute Force SSH (>10 conn/    | SOC/BACKEND: Compile sigmac ->
                         | port 22 en 5min). MITRE ATT&CK: T1110.  | test -> déploiement Kibana.
                         |                                         | Vérifier indexation port 22.

