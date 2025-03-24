import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Load data
logs = pd.read_csv("network_logs.csv")
logs["timestamp"] = pd.to_datetime(logs["timestamp"])

# Feature engineering
logs["login_count"] = logs.groupby("source_ip")["action"].transform(lambda x: (x == "login").cumsum())
logs["is_threat"] = logs["source_ip"].apply(lambda x: 1 if x == "192.168.1.100" else 0)  # Label our attack IP

# Prepare data
X = logs[["login_count"]]  # Add more features later (e.g., time deltas)
y = logs["is_threat"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=10)
model.fit(X_train, y_train)

# Predict
predictions = model.predict(X)
threats = logs[predictions == 1]["source_ip"].unique()
for ip in threats:
    print(f"Threat detected: {ip} (ML prediction)")

# Accuracy
accuracy = model.score(X_test, y_test)
print(f"Model accuracy: {accuracy:.2f}")