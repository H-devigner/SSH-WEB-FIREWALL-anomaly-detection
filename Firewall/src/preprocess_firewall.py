import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib

# 1. Chargement brut
df = pd.read_csv('data/firewall.csv')

# 2. Feature Engineering (ratios comportementaux)
df['Bytes_per_Packet'] = df['Bytes'] / (df['Packets'] + 1)
df['Packet_Rate'] = df['Packets'] / (df['Elapsed Time (sec)'] + 0.001)
df['Byte_Rate'] = df['Bytes'] / (df['Elapsed Time (sec)'] + 0.001)
df['Port_Diversity_Ratio'] = df['Destination Port'] / (df['Source Port'] + 1)

FEATURES = [
    'Source Port', 'Destination Port', 'Bytes', 'Packets', 'Elapsed Time (sec)',
    'Bytes_per_Packet', 'Packet_Rate', 'Byte_Rate', 'Port_Diversity_Ratio'
]

# 3. Extraction baseline normale (uniquement pour l'apprentissage non supervisé)
df_normal = df[df['Action'] == 'allow'][FEATURES].dropna()

# 4. Normalisation
scaler = StandardScaler()
X_train_full = scaler.fit_transform(df_normal)

# 5. Sauvegarde du pipeline
joblib.dump({
    'scaler': scaler,
    'features': FEATURES,
    'X_train_full': X_train_full
}, 'models/firewall_scaler.pkl')
print("✅ Pipeline sauvegardé dans models/firewall_scaler.pkl")
