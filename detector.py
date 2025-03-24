import pandas as pd

# Load data
logs = pd.read_csv("network_logs.csv")
logs["timestamp"] = pd.to_datetime(logs["timestamp"])

# Define detection rules
def detect_threats(df):
    alerts = []
    time_window = pd.Timedelta(seconds=10)
    for ip in df["source_ip"].unique():
        ip_logs = df[df["source_ip"] == ip]
        ip_logs = ip_logs.sort_values("timestamp")
        
        for i, row in ip_logs.iterrows():
            window = ip_logs[
                (ip_logs["timestamp"] >= row["timestamp"]) &
                (ip_logs["timestamp"] <= row["timestamp"] + time_window)
            ]
            login_count = len(window[window["action"] == "login"])
            if login_count > 10:
                alert = f"Threat detected: {ip} - {login_count} logins in 10s at {row['timestamp']}"
                if alert not in alerts:  # Avoid duplicates
                    alerts.append(alert)
    
    return alerts

# Run detection
threats = detect_threats(logs)

# Save threats to alerts.txt
with open("alerts.txt", "w") as f:
    for threat in threats:
        f.write(threat + "\n")

# Print results
if threats:
    for threat in threats:
        print(threat)
else:
    print("No threats detected.")