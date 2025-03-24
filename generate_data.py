import pandas as pd
import random
from datetime import datetime, timedelta

data = {
    "timestamp": [],
    "source_ip": [],
    "action": []
}

start_time = datetime.now()
for i in range(1000):
    time = start_time + timedelta(seconds=i // 100)
    ip = f"192.168.1.{random.randint(1, 255)}"
    action = random.choice(["login", "logout", "data_transfer"])
    # Reintroduce the attack simulation
    if i > 900:
        ip = "192.168.1.100"
        action = "login"
    # Simulate honeypot access (1% chance)
    if random.random() < 0.01:
        ip = "192.168.1.999"
        action = "login"
    data["timestamp"].append(time)
    data["source_ip"].append(ip)
    data["action"].append(action)

df = pd.DataFrame(data)
df.to_csv("network_logs.csv", index=False)
print("Sample data generated: network_logs.csv")