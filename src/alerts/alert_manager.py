import uuid
import json
from datetime import datetime
from pathlib import Path

DEDUPLICATION_WINDOW = 300 # 5 min
SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

# Generate the unique id
def generate_alert_id():
    alert_id = uuid.uuid4()
    return str(alert_id)

# Add the unique id, timestamp
def create_alert(alert):
    alert["timestamp"] = datetime.now().astimezone().isoformat()
    alert["alert_id"] = generate_alert_id()

    if alert["severity"] == "CRITICAL":
        alert["description"] = (f"Various login attempts: {alert['failures']}, followed by a login success")
    elif alert["severity"] == "HIGH":
        alert["description"] = (f"Various login attempts: {alert['failures']}, from the same user and IP address")
    return alert

# Check if the alert is duplicate
def is_duplicate(new_alert,existing_alerts):
    new_time = datetime.fromisoformat(new_alert["timestamp"])

    for old_alert in existing_alerts:
        same_user = old_alert["username"] == new_alert["username"]
        same_ip = old_alert["source_ip"] == new_alert["source_ip"]
        same_rule = old_alert["rule"] == new_alert["rule"]

        if same_user and same_ip and same_rule:
            old_time = datetime.fromisoformat(old_alert["timestamp"])
            difference = abs((new_time-old_time).total_seconds())

            if difference <= DEDUPLICATION_WINDOW:
                return True

    return False

# Save the alerts in json format
def save_alerts(alerts, file_path="reports/alerts.json"):
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        with open(path,"r", encoding="utf-8") as file:
            existing_alerts = json.load(file)
    else:
        existing_alerts = []

    for alert in alerts:
        duplicate = None

        for old_alert in existing_alerts:
            if is_duplicate(alert, [old_alert]):
                duplicate = old_alert
                break

        if duplicate:
            new_level = SEVERITY_LEVELS[alert["severity"]]
            old_level = SEVERITY_LEVELS[duplicate["severity"]]

            if new_level > old_level:
                duplicate["severity"] = alert["severity"]
                duplicate["description"] = alert["description"]
                duplicate["timestamp"] = alert["timestamp"]
        else:
            existing_alerts.append(alert)

    with open(path,"w", encoding="utf-8") as file:
        json.dump(existing_alerts,file,indent=4,ensure_ascii=False)

