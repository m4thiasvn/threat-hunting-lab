from src.ingestion.log_reader import read_logs
from src.processing.normalizer import process_events
from src.detection.brute_force import detect_brute_force
from src.alerts.alert_manager import create_alert, save_alerts

LOG_FILE = "data/authentication.log"


def main():
    events = read_logs(LOG_FILE)
    events = process_events(events)
    alerts = detect_brute_force(events)

    final_alerts = []

    for alert in alerts:
        final_alerts.append(create_alert(alert))

    save_alerts(final_alerts, file_path="reports/alerts.json")

    print(final_alerts)


if __name__ == "__main__":
    main()