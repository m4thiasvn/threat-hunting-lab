from datetime import datetime, timezone
from collections import Counter

# generate an organized report
def generate_report(alerts):
    severity_counts = Counter(alert.get("severity", "UNKNOWN") for alert in alerts)
    source_ips = sorted({alert.get("source_ip","UNKNOWN") for alert in alerts})

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "severity_counts": dict(severity_counts),
        "source_ips" : source_ips
    }

    return report