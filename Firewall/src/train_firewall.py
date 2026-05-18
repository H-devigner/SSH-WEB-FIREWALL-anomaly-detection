from sklearn.ensemble import IsolationForest
import joblib
from sklearn.model_selection import train_test_split

pipeline = joblib.load('models/firewall_scaler.pkl')
scaler = pipeline['scaler']
X_train_full = pipeline['X_train_full']
FEATURES = pipeline['features'] 

# Split 80% train / 20% test
X_train, X_test = train_test_split(X_train_full, test_size=0.2, random_state=42)

# E,trainement
model = IsolationForest(
    n_estimators=100,
    contamination=0.35,
    random_state=42
)
model.fit(X_train)

joblib.dump(model, 'models/firewall_isolation.pkl')

# sauvegarde des 20%
joblib.dump({
    'scaler': scaler,
    'features': FEATURES,
    'X_test': X_test
}, 'models/firewall_scaler_test.pkl')
