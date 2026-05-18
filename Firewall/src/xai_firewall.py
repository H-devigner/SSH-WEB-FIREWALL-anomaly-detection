# src/firewall/xai_explainer.py
import shap
import joblib
import numpy as np
import pandas as pd

# Chargement unique au démarrage
MODEL = joblib.load('models/firewall_isolation.pkl')
PIPELINE = joblib.load('models/firewall_scaler_test.pkl')
SCALER = PIPELINE['scaler']
FEATURES = PIPELINE['features']
EXPLAINER = shap.TreeExplainer(MODEL)

# Mapping ECS → Noms bruts attendus par le modèle
ECS_TO_RAW = {
    "source.port": "Source Port",
    "destination.port": "Destination Port",
    "network.bytes": "Bytes",
    "network.packets": "Packets",
    "event.duration": "Elapsed Time (sec)"
}

def _ecs_to_features(ecs_event: dict) -> dict:
    """Traduit un événement ECS nesté en features brutes + dérivées"""
    raw = {}
    # 1. Extraction & aplatissement ECS
    for ecs_key, raw_key in ECS_TO_RAW.items():
        keys = ecs_key.split(".")
        val = ecs_event
        for k in keys:
            val = val.get(k, 0)  # Fallback sécurisé
        raw[raw_key] = val

    # 2. Feature Engineering (EXACTEMENT comme à l'entraînement)
    pkts = max(raw["Packets"], 1)
    dur = max(raw["Elapsed Time (sec)"], 0.001)
    raw["Bytes_per_Packet"] = raw["Bytes"] / pkts
    raw["Packet_Rate"] = raw["Packets"] / dur
    raw["Byte_Rate"] = raw["Bytes"] / dur
    raw["Port_Diversity_Ratio"] = raw["Destination Port"] / max(raw["Source Port"], 1)

    return raw

def explain_firewall_alert(ecs_event: dict) -> dict:
    """Reçoit un log ECS, retourne décision IA + explication SHAP"""
    try:
        # 1. Traduction ECS → Features
        raw_features = _ecs_to_features(ecs_event)
        df_sample = pd.DataFrame([raw_features])
        
        # Validation stricte de l'ordre des colonnes
        if not all(f in df_sample.columns for f in FEATURES):
            missing = [f for f in FEATURES if f not in df_sample.columns]
            raise ValueError(f"Features manquantes après mapping ECS: {missing}")
            
        X_sample = SCALER.transform(df_sample[FEATURES])
        
        # 2. Prédiction & score
        pred = MODEL.predict(X_sample)[0]
        raw_score = float(MODEL.decision_function(X_sample)[0])
        
        # 3. SHAP (API moderne)
        shap_output = EXPLAINER(X_sample)
        shap_vals = shap_output.values[0].flatten()
        
        # 4. Top 2 facteurs
        top_features = sorted(zip(FEATURES, np.abs(shap_vals)), 
                              key=lambda x: x[1], reverse=True)[:2]
        explanation_parts = [f"{f}={raw_features[f]:.0f}" for f, _ in top_features]
        explanation_text = "Anomalie détectée. Facteurs : " + " | ".join(explanation_parts)
        
        return {
            "is_anomaly": bool(pred == -1),
            "anomaly_score": raw_score,
            "risk_score": float(1 / (1 + np.exp(-raw_score))),
            "explanation": explanation_text,
            "recommendation": "Vérifier la règle firewall associée" if pred == -1 else "Trafic conforme à la baseline"
        }
    except Exception as e:
        return {"error": f"Échec scoring IA: {str(e)}", "is_anomaly": False}
