import json
from src.ingestion.log_reader import read_logs
from src.processing.normalizer import process_events
from src.detection.brute_force import detect_brute_force
from src.alerts.alert_manager import create_alert, save_alerts
from src.investigation.ip_analyzer import analyze_ip
from src.investigation.ip_reputation import check_ip_reputation
from src.reports.report_generator import generate_report

LOG_FILE = "data/authentication.log"


def main():
    events = read_logs(LOG_FILE)
    events = process_events(events)
    alerts = detect_brute_force(events)

    final_alerts = []

    for alert in alerts:
        ip_analysis = analyze_ip(alert["source_ip"])
        alert["ip_analysis"] = ip_analysis
        if ip_analysis["status"] == "PUBLIC":
            ip_reputation = check_ip_reputation(alert["source_ip"])
            alert["ip_reputation"] = ip_reputation

        final_alerts.append(create_alert(alert))

    updated_alerts = save_alerts(final_alerts,file_path="reports/alerts.json")

    with open("reports/alerts.json", "r", encoding="utf-8") as file:
        stored_alerts = json.load(file)
    report = generate_report(stored_alerts)
    with open("reports/soc_report.json", "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n======================================= SOC REPORT =======================================")
    print(json.dumps(report, indent=4))

    print("\n======================================= STORED ALERTS =======================================")
    if stored_alerts:
        for alert in stored_alerts:
                print("\n", alert)
    else:
        print("\nNO STORED ALERTS")    

    print("\n======================================= UPDATED ALERTS =======================================")
    if updated_alerts:
        for alert in updated_alerts:
            print("\n", alert)
    else:
        print("\nNO UPDATED ALERTS.")

    print("\n======================================== RECENT ALERTS =======================================")
    for alert in final_alerts:
        print("\n",alert)

if __name__ == "__main__":
    main()