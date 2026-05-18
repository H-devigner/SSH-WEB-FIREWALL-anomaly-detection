import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, roc_auc_score
import warnings
warnings.filterwarnings('ignore')

# 1. Chargement
model = joblib.load('models/firewall_isolation.pkl')
pipeline = joblib.load('models/firewall_scaler_test.pkl')
scaler = pipeline['scaler']
FEATURES = pipeline['features']
X_test = pipeline['X_test']  # 20% jamais vus

# 2. Charger les anomalies depuis le CSV
df = pd.read_csv('data/firewall.csv')
df['Bytes_per_Packet'] = df['Bytes'] / (df['Packets'] + 1)
df['Packet_Rate'] = df['Packets'] / (df['Elapsed Time (sec)'] + 0.001)
df['Byte_Rate'] = df['Bytes'] / (df['Elapsed Time (sec)'] + 0.001)
df['Port_Diversity_Ratio'] = df['Destination Port'] / (df['Source Port'] + 1)

df_anomalies = df[df['Action'] != 'allow'][FEATURES].dropna()
X_anomalies = scaler.transform(df_anomalies)

# 3. Test set final = 20% normal + toutes anomalies
X_test_combined = np.vstack([X_test, X_anomalies])
y_test_labels = [1] * len(X_test) + [-1] * len(df_anomalies)
y_binary = (np.array(y_test_labels) == -1).astype(int)

# 4. Prédictions & Scores
y_pred = model.predict(X_test_combined)
anomaly_scores = -model.decision_function(X_test_combined)

# 5. Métriques
print("=== Classification Report (DONNÉES INVISIBLES) ===")
print(classification_report(
    y_test_labels, y_pred,
    target_names=['Anomalie', 'Normal'],
    labels=[-1, 1],
    zero_division=0
))

roc_auc = roc_auc_score(y_binary, anomaly_scores)
print(f"\n📊 ROC-AUC: {roc_auc:.4f}")
if roc_auc >= 0.85:
    print("✅ Seuil validé pour SENTINEL CORE (≥ 0.85)")
else:
    print("⚠️ Ajustement recommandé : revoir features ou contamination")

# 6. Export pour Kibana
results = pd.DataFrame(X_test_combined, columns=FEATURES)
results['true_label'] = y_test_labels
results['prediction'] = y_pred
results['anomaly_score'] = anomaly_scores
results.to_csv('results/firewall_eval_kibana.csv', index=False)
print("📤 Résultats exportés → results/firewall_eval_kibana.csv")
