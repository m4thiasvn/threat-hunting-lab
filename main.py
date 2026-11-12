import json
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

    updated_alerts = save_alerts(final_alerts,file_path="reports/alerts.json")

    with open("reports/alerts.json", "r", encoding="utf-8") as file:
        stored_alerts = json.load(file)

    print("\n======================================= ALERTAS ALMACENADAS =======================================")
    if stored_alerts:
        for alert in stored_alerts:
                print("\n", alert)
    else:
        print("NO HAY ALERTAS ALMACENADAS")    

    print("\n======================================= ALERTAS ACTUALIZADAS =======================================")
    if updated_alerts:
        for alert in updated_alerts:
            print("\n", alert)
    else:
        print("\nNO HAY ALERTAS ACTUALIZADAS.")

    print("\n======================================== ALERTAS RECIENTES =======================================")
    for alert in final_alerts:
        print("\n",alert)

if __name__ == "__main__":
    main()