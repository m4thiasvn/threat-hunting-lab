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
REQUIRED_ALERT_FIELDS = [
    "username",
    "source_ip",
    "rule",
    "timestamp",
    "severity",
    "description"
]

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
            difference = (new_time-old_time).total_seconds()

            if 0 <= difference <= DEDUPLICATION_WINDOW:
                return True

    return False

# Save the alerts in json format
def save_alerts(alerts, file_path="reports/alerts.json"):
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as file:
                existing_alerts = json.load(file)

            if not isinstance(existing_alerts, list):
                raise ValueError("Invalid alerts format: expected a list")

            for alert in existing_alerts:
                if not isinstance(alert, dict):
                    raise ValueError("Invalid alert format: expected a dictionary")

                missing_fields = [
                    field for field in REQUIRED_ALERT_FIELDS
                    if field not in alert
                ]

                if missing_fields:
                    raise ValueError(
                        f"Invalid alert format: missing fields {missing_fields}"
                    )

                if alert["severity"] not in SEVERITY_LEVELS:
                    raise ValueError(f"Invalid severity: {alert['severity']}")

                try:
                    datetime.fromisoformat(alert["timestamp"])
                except ValueError:
                    raise ValueError(f"Invalid timestamp: {alert['timestamp']}")

        except (json.JSONDecodeError, ValueError) as error:
            raise ValueError(
                f"Cannot read alerts file {path}: {error}"
            ) from error

    else:
        existing_alerts = []

    updated_alerts = []    

    # Validate and process new alerts
    for alert in alerts:
        if not isinstance(alert, dict):
            raise ValueError("Invalid alert format: expected a dictionary")

        missing_fields = [
            field for field in REQUIRED_ALERT_FIELDS
            if field not in alert
        ]

        if missing_fields:
            raise ValueError(
                f"Invalid alert format: missing fields {missing_fields}"
            )

        if alert["severity"] not in SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity: {alert['severity']}")

        try:
            datetime.fromisoformat(alert["timestamp"])
        except ValueError:
            raise ValueError(f"Invalid timestamp: {alert['timestamp']}")

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
                updated_alerts.append(duplicate)
        else:
            existing_alerts.append(alert)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(existing_alerts, file, indent=4, ensure_ascii=False)

    return updated_alerts
