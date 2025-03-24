from flask import Flask, render_template, jsonify, request, session, redirect, url_for
import pandas as pd
import time
import smtplib
from email.mime.text import MIMEText
import plotly.express as px
import plotly
import requests
import json
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
import numpy as np
from collections import defaultdict
from datetime import datetime
import hashlib
import secrets
import random
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Email config (using free Gmail SMTP, no cost)
EMAIL_SENDER = "vamshirajii393@gmail.com"  # Replace with your Gmail
EMAIL_PASSWORD = "jmhbjmsxngxfoaah"  # Use App Password if 2FA is enabled
EMAIL_RECEIVER = "rajithachamakuri393@gmail.com"  # Replace with your email

# Free APIs: Hybrid Analysis and AbuseIPDB
HYBRID_API_KEY = "zc7a4ohwbdd6306bbnxsrfoq24ff29686plhphf330e05aaf6htgfr4j70e99cc8"
HYBRID_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
ABUSEIPDB_API_KEY = "f497ca733d865506c633156febba0308fea520a08656ebc1360871cf4ef7c3bff9ff581308df042a"

# Mock firewall rules, user activity baseline, and blockchain
firewall_rules = set()
user_activity_baseline = defaultdict(lambda: {"login_count": 0, "avg_time": 0})
blockchain = []
HONEYPOT_IP_RANGE = ["192.168.1.999"]  # Initial honeypot, will evolve
ATTACK_IP = "192.168.1.100"  # Disabled from threat detection
executed_actions = []  # Track executed playbook actions

# Response playbook with new automated actions
RESPONSE_PLAYBOOK = {
    "High": ["block_ip", "send_alert", "isolate_endpoint"],
    "Medium": ["log_incident", "send_alert", "quarantine_user"],
    "Low": ["log_incident"],
    "Emotional": ["block_ip", "send_alert", "log_incident", "isolate_endpoint"]
}

# Mock users for zero trust
USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "analyst": {"password": "analyst123", "role": "analyst"}
}

# Predictive model training data
historical_data = [
    {"login_count": 5, "time_diff": 60, "threat": False},
    {"login_count": 20, "time_diff": 10, "threat": True},
    {"login_count": 15, "time_diff": 5, "threat": True}
]
predictive_model = None

# Mock global threat data
global_threats = [
    {"ip": "192.168.1.100", "lat": 37.7749, "lon": -122.4194, "threat": "Ransomware Simulation", "severity": "High"},
    {"ip": "203.0.113.1", "lat": 51.5074, "lon": -0.1278, "threat": "DDoS", "severity": "Medium"}
]

# Crowdsourced threats file
CROWD_THREATS_FILE = "crowd_threats.json"
if not os.path.exists(CROWD_THREATS_FILE):
    with open(CROWD_THREATS_FILE, "w") as f:
        json.dump({}, f)

def train_predictive_model():
    global predictive_model, historical_data
    if len(historical_data) < 2:
        print("Warning: Insufficient data for training.")
        return
    X = [[d["login_count"], d["time_diff"]] for d in historical_data]
    y = [1 if d["threat"] else 0 for d in historical_data]
    if len(set(y)) < 2:
        print("Warning: Insufficient class diversity.")
        return
    try:
        predictive_model = LogisticRegression()
        predictive_model.fit(X, y)
        print("Predictive model trained successfully.")
    except ValueError as e:
        print(f"Training failed: {e}")

def predict_threat(ip, login_count, time_diff):
    if predictive_model is None:
        return False, "Model not trained"
    prediction = predictive_model.predict([[login_count, time_diff]])
    probability = predictive_model.predict_proba([[login_count, time_diff]])[0][1] * 100  # Scale to percentage
    return prediction[0] == 1, f"Predicted threat score: {probability:.2f}%"

def add_to_blockchain(data):
    prev_hash = hashlib.sha256(str(blockchain[-1]).encode()).hexdigest() if blockchain else "0" * 64
    block = {
        "data": data, "timestamp": str(datetime.now()), "prev_hash": prev_hash,
        "hash": hashlib.sha256(f"{data}{prev_hash}{str(datetime.now())}".encode()).hexdigest()
    }
    blockchain.append(block)
    return block

def check_hybrid_threat_feed(ip):
    headers = {"api-key": HYBRID_API_KEY, "accept": "application/json", "user-agent": "Cybersecurity Threat Detector"}
    url = f"{HYBRID_BASE_URL}/search/ip"
    params = {"query": ip}
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            threat_score = data.get("result", [{}])[0].get("threat_score", 0)
            return threat_score > 50, f"Hybrid Analysis: Threat Score {threat_score}%"
        elif response.status_code == 429:
            print("Hybrid Analysis rate limit exceeded.")
            return False, "Rate limit exceeded"
        else:
            print(f"Hybrid Analysis error: {response.status_code}")
            return False, "Hybrid Analysis check failed"
    except Exception as e:
        print(f"Hybrid Analysis check failed: {e}")
        return False, "Hybrid Analysis check failed"

def check_third_party_risk(ip):
    if ip.startswith("192.168.1."):  # Skip internal IPs
        return False, "Internal IP"
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            if data["data"]["abuseConfidenceScore"] > 50:
                return True, f"Third-Party Risk: {ip} - Abuse Confidence Score {data['data']['abuseConfidenceScore']}%"
        return False, "No third-party risk detected"
    except Exception as e:
        print(f"AbuseIPDB check failed: {e}")
        return False, "Third-party check failed"

def get_crowd_threat_score(ip):
    if os.path.exists(CROWD_THREATS_FILE):
        with open(CROWD_THREATS_FILE, "r") as f:
            threats = json.load(f)
        return threats.get(ip, {"votes": 0, "score": 0})["score"] > 50, f"Crowd Score: {threats.get(ip, {'score': 0})['score']:.1f}%"
    return False, "No crowd data"

def detect_anomalies(df):
    login_data = df[df["action"] == "login"].groupby("source_ip")["timestamp"].count().reset_index()
    login_data.columns = ["source_ip", "login_count"]
    if len(login_data) > 1:
        X = login_data[["login_count"]].values
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        login_data["anomaly"] = iso_forest.fit_predict(X)
        anomalies = login_data[login_data["anomaly"] == -1]["source_ip"].tolist()
        return anomalies, "Anomaly detected via Isolation Forest"
    return [], "No anomalies detected"

def detect_user_behavior_anomalies(df):
    user_activity = defaultdict(list)
    for _, row in df.iterrows():
        if row["action"] == "login":
            user_activity[row["source_ip"]].append(row["timestamp"])
    
    alerts = []
    for ip, timestamps in user_activity.items():
        if len(timestamps) > 1:
            time_diffs = [(timestamps[i + 1] - timestamps[i]).total_seconds() for i in range(len(timestamps) - 1)]
            avg_diff = np.mean(time_diffs) if time_diffs else 0
            login_count = len(timestamps)
            variance = np.std(time_diffs) if len(time_diffs) > 1 else 0
            baseline = user_activity_baseline[ip]
            if baseline["login_count"] == 0:
                baseline["login_count"] = login_count
                baseline["avg_time"] = avg_diff
            print(f"IP {ip} detected with login_count: {login_count}, variance: {variance:.1f}")
            if ip != ATTACK_IP and (len(timestamps) > baseline["login_count"] * 2 or abs(avg_diff - baseline["avg_time"]) > 300):
                alerts.append(f"User behavior anomaly: {ip} - Unusual login frequency at {timestamps[-1]}")
                if ip not in firewall_rules:
                    firewall_rules.add(ip)
                    print(f"Blocked IP {ip} due to user behavior anomaly")
            if variance > 300 and login_count > 10:
                alerts.append(f"Emotional Escalation: {ip} - Panic-like behavior at {timestamps[-1]}")
            threat = (ip != ATTACK_IP and ip in firewall_rules)
            historical_data.append({"login_count": login_count, "time_diff": float(avg_diff), "threat": threat})
            print(f"Historical data updated: {historical_data[-1]}")
            train_predictive_model()
    return alerts

def detect_insider_threats(df):
    insider_alerts = []
    user_behavior = defaultdict(list)
    
    for _, row in df.iterrows():
        if row["action"] == "login":
            user_behavior[row["source_ip"]].append({
                "timestamp": row["timestamp"],
                "action": row["action"],
                "destination": row.get("destination", "unknown")  # Use .get() to handle missing column
            })
    
    for ip, activities in user_behavior.items():
        if len(activities) > 5:
            timestamps = [act["timestamp"].hour for act in activities]
            X = [[t] for t in timestamps]
            iso_forest = IsolationForest(contamination=0.1, random_state=42)
            anomalies = iso_forest.fit_predict(X)
            if -1 in anomalies:
                insider_alerts.append(f"Insider Threat: {ip} - Unusual login times detected at {activities[-1]['timestamp']}")
    
    return insider_alerts

def detect_third_party_risks(df):
    third_party_alerts = []
    external_ips = df[~df["source_ip"].str.startswith("192.168.1.")]["source_ip"].unique()
    for ip in external_ips:
        is_risky, reason = check_third_party_risk(ip)
        if is_risky:
            third_party_alerts.append(reason)
    return third_party_alerts

def detect_honeypot_activity(df):
    honeypot_logs = df[df["source_ip"].isin(HONEYPOT_IP_RANGE)]
    if not honeypot_logs.empty:
        active_honeypots = honeypot_logs["source_ip"].value_counts().index.tolist()
        for ip in HONEYPOT_IP_RANGE[:]:
            if ip not in active_honeypots and random.random() < 0.3:
                HONEYPOT_IP_RANGE.remove(ip)
                print(f"Retired honeypot: {ip}")
        for _ in range(3 - len(HONEYPOT_IP_RANGE)):
            new_ip = f"192.168.1.{random.randint(1000, 1004)}"
            if new_ip not in HONEYPOT_IP_RANGE:
                HONEYPOT_IP_RANGE.append(new_ip)
                print(f"Added new honeypot: {new_ip}")
        timestamp = honeypot_logs["timestamp"].iloc[-1]
        return [f"Honeypot triggered: {active_honeypots[0]} accessed at {timestamp} (Network evolved to {len(HONEYPOT_IP_RANGE)} decoys)"]
    return []

def simulate_ransomware_attack(df):
    ransomware_ip = "203.0.113.2"
    try:
        if ransomware_ip not in df["source_ip"].values:
            timestamps = [pd.Timestamp.now() + pd.Timedelta(seconds=i*0.2) for i in range(50)]
            new_entries = pd.DataFrame({
                "timestamp": timestamps,
                "source_ip": [ransomware_ip] * 50,
                "action": ["login"] * 50,
                "destination": ["server_1"] * 50  # Add destination column
            })
            df = pd.concat([df, new_entries], ignore_index=True)
            print(f"Simulated ransomware attack from IP {ransomware_ip} at {pd.Timestamp.now()}")
        else:
            print(f"Ransomware IP {ransomware_ip} exists, skipping simulation.")
    except Exception as e:
        print(f"Error simulating ransomware: {e}")
    return df

def execute_response_playbook(severity, ip, timestamp):
    actions = RESPONSE_PLAYBOOK.get(severity, ["log_incident"])
    for action in actions:
        if action == "block_ip" and ip not in firewall_rules and ip not in HONEYPOT_IP_RANGE and ip != ATTACK_IP:
            firewall_rules.add(ip)
            executed_actions.append(f"Blocked IP {ip} at {timestamp}")
            print(f"Blocked IP {ip}")
        elif action == "send_alert":
            send_email_alert([f"{severity} threat: {ip} at {timestamp}"])
            executed_actions.append(f"Sent alert for {ip} at {timestamp}")
        elif action == "log_incident":
            log_entry = f"{severity} log: {ip} at {timestamp}"
            with open("alerts.txt", "a") as f:
                f.write(f"{log_entry} - {time.ctime()}\n")
            add_to_blockchain(log_entry)
            executed_actions.append(f"Logged incident for {ip} at {timestamp}")
        elif action == "isolate_endpoint":
            firewall_rules.add(ip)
            executed_actions.append(f"Isolated endpoint {ip} at {timestamp}")
            print(f"Isolated endpoint {ip}")
        elif action == "quarantine_user":
            executed_actions.append(f"Quarantined user associated with {ip} at {timestamp}")
            print(f"Quarantined user for {ip}")

def detect_threats(df):
    # Ensure 'destination' column exists
    if "destination" not in df.columns:
        df["destination"] = "unknown"
    
    alerts = []
    seen_alerts = set()
    time_window = pd.Timedelta(seconds=10)
    anomaly_ips, anomaly_reason = detect_anomalies(df)
    user_behavior_alerts = detect_user_behavior_anomalies(df)
    honeypot_alerts = detect_honeypot_activity(df)
    insider_alerts = detect_insider_threats(df)
    third_party_alerts = detect_third_party_risks(df)

    alerts.extend(user_behavior_alerts)
    alerts.extend(honeypot_alerts)
    alerts.extend(insider_alerts)
    alerts.extend(third_party_alerts)

    for ip in df["source_ip"].unique():
        ip_logs = df[df["source_ip"] == ip].sort_values("timestamp")
        is_hybrid_malicious, hybrid_reason = check_hybrid_threat_feed(ip)
        is_crowd_malicious, crowd_reason = get_crowd_threat_score(ip)
        
        for i, row in ip_logs.iterrows():
            window = ip_logs[(ip_logs["timestamp"] >= row["timestamp"]) & (ip_logs["timestamp"] <= row["timestamp"] + time_window)]
            login_count = len(window[window["action"] == "login"])
            time_diff = window["timestamp"].diff().mean().total_seconds() if len(window) > 1 else 0
            is_predicted_threat, predict_reason = predict_threat(ip, login_count, time_diff)
            if ip != ATTACK_IP and (login_count > 5 or ip in anomaly_ips or is_hybrid_malicious or is_crowd_malicious or is_predicted_threat):
                severity = "Low" if login_count <= 10 else "Medium" if login_count <= 20 else "High"
                reasons = []
                if ip in anomaly_ips: reasons.append(anomaly_reason)
                if is_hybrid_malicious: reasons.append(hybrid_reason); severity = "High"
                if is_crowd_malicious: reasons.append(crowd_reason); severity = "Medium" if severity == "Low" else severity
                if is_predicted_threat: reasons.append(predict_reason); severity = "Medium" if severity == "Low" else severity
                if login_count > 5: reasons.append(f"{login_count} logins in {time_window.seconds}s")
                reason = "; ".join(reasons) if reasons else "Unspecified threat pattern"
                alert = f"Threat detected: {ip} - {reason} at {row['timestamp']} (Severity: {severity})"
                if alert not in seen_alerts:
                    alerts.append(alert)
                    seen_alerts.add(alert)
                    execute_response_playbook(severity, ip, row['timestamp'])
                    historical_data.append({"login_count": login_count, "time_diff": float(time_diff), "threat": True})
                    train_predictive_model()
                    if ip not in [t["ip"] for t in global_threats]:
                        global_threats.append({
                            "ip": ip, "lat": 37.7749 + (len(global_threats) % 10), "lon": -122.4194 + (len(global_threats) % 10),
                            "threat": reason.split(";")[0], "severity": severity
                        })

    return alerts

def send_email_alert(threats):
    if not threats:
        return
    subject = "Cybersecurity Alert"
    body = "\n".join(threats)
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print("Email alert sent!")
    except Exception as e:
        print(f"Email failed: {e}")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"Login attempt: {username}, {password}")
        if not username or not password:
            return render_template('login.html', error="Username and password required")
        if username in USERS and USERS[username]["password"] == password:
            session['user'] = username
            session['role'] = USERS[username]["role"]
            session.permanent = True
            print(f"Login successful for {username}")
            return redirect(url_for('home'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    print("User logged out")
    return redirect(url_for('login'))

@app.route('/submit_threat', methods=['POST'])
def submit_threat():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    ip = request.form.get('ip')
    score = int(request.form.get('score', 0))
    if not ip or score < 0 or score > 100:
        return jsonify({"error": "Invalid input"}), 400
    with open(CROWD_THREATS_FILE, "r") as f:
        threats = json.load(f)
    threats[ip] = threats.get(ip, {"votes": 0, "score": 0})
    threats[ip]["votes"] += 1
    threats[ip]["score"] = (threats[ip]["score"] * (threats[ip]["votes"] - 1) + score) / threats[ip]["votes"]
    with open(CROWD_THREATS_FILE, "w") as f:
        json.dump(threats, f)
    return jsonify({"status": "success", "ip": ip, "avg_score": threats[ip]["score"]})

@app.route('/')
def home():
    if 'user' not in session:
        return redirect(url_for('login'))
    print(f"Rendering home for {session['user']}")
    logs = pd.read_csv("network_logs.csv")
    logs["timestamp"] = pd.to_datetime(logs["timestamp"])
    current_slice = logs[int(len(logs) * 0.9):]
    threats = detect_threats(current_slice)
    with open("alerts.txt", "a") as f:
        for threat in threats:
            f.write(f"{threat} - {time.ctime()}\n")
    login_counts = logs.groupby("source_ip")["action"].apply(lambda x: (x == "login").sum()).reset_index()
    login_counts = login_counts.nlargest(10, "action")
    login_counts_dict = login_counts.to_dict(orient="records") if not login_counts.empty and login_counts["action"].sum() > 0 else []
    if not login_counts.empty and login_counts["action"].sum() > 0:
        fig = px.bar(login_counts, x="source_ip", y="action", title=f"Login Activity (Updated: {datetime.now().strftime('%H:%M:%S')})", labels={"action": "Login Count"})
        fig.update_layout(xaxis_tickangle=-45)
        try:
            graph_html = plotly.offline.plot(fig, output_type="div", include_plotlyjs=True)
        except Exception as e:
            print(f"Plotly error: {e}")
            graph_html = "<div>Error generating graph: No valid data</div>"
    else:
        graph_html = "<div>No login data available</div>"
    return render_template("index.html", threats=threats, graph=graph_html, role=session.get('role'), global_threats=global_threats, login_counts=login_counts_dict, executed_actions=executed_actions)

@app.route('/firewall')
def show_firewall():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access denied", 403
    return render_template("firewall.html", rules=list(firewall_rules))

@app.route('/incidents')
def show_incidents():
    if 'user' not in session:
        return redirect(url_for('login'))
    with open("alerts.txt", "r") as f:
        incidents = f.readlines()
    return render_template("incidents.html", incidents=incidents)

@app.route('/blockchain')
def show_blockchain():
    if 'user' not in session or session.get('role') != 'admin':
        return "Access denied", 403
    return render_template("blockchain.html", blockchain=blockchain)

@app.route('/realtime_data')
def realtime_data():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    print(f"Fetching realtime data for {session['user']} at {pd.Timestamp.now()}")
    try:
        logs = pd.read_csv("network_logs.csv")
        logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors='coerce')
        if logs.empty:
            return jsonify({"error": "No data", "timestamp": pd.Timestamp.now().isoformat()}), 400
        logs = simulate_ransomware_attack(logs)
        current_slice = logs[int(len(logs) * 0.9):]
        if current_slice.empty:
            return jsonify({"error": "No recent data", "timestamp": pd.Timestamp.now().isoformat()}), 400
        threats = detect_threats(current_slice)
        login_counts = current_slice[current_slice["action"] == "login"].groupby("source_ip")["action"].count().reset_index(name="count")
        login_counts_dict = login_counts.to_dict(orient="records") if not login_counts.empty else []
        for entry in login_counts_dict:
            entry["count"] = int(entry["count"])
        threats_list = [str(t) for t in threats] if threats is not None else []
        response = {
            "threats": threats_list,
            "login_counts": login_counts_dict,
            "timestamp": pd.Timestamp.now().isoformat(),
            "slice_size": len(current_slice),
            "honeypot_range": HONEYPOT_IP_RANGE
        }
        print(f"Returning realtime data: {response}")
        return jsonify(response)
    except FileNotFoundError:
        return jsonify({"error": "Log file not found", "timestamp": pd.Timestamp.now().isoformat()}), 500
    except Exception as e:
        print(f"Error processing realtime data: {e}")
        return jsonify({"error": str(e), "timestamp": pd.Timestamp.now().isoformat()}), 500

if __name__ == "__main__":
    train_predictive_model()
    app.run(debug=True)