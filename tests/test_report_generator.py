from src.reports.report_generator import generate_report

# test the report generator
def test_generate_report():
    alerts = [
        {"severity": "HIGH", "source_ip": "8.8.8.8"},
        {"severity": "HIGH", "source_ip": "8.8.8.8"},
        {"severity": "CRITICAL", "source_ip": "1.1.1.1"}
    ]

    report = generate_report(alerts)

    assert report["total_alerts"] == 3
    assert report["severity_counts"] == {
        "HIGH": 2,
        "CRITICAL": 1
    }
    assert report["source_ips"] == [
        "1.1.1.1",
        "8.8.8.8"
    ]
    assert "generated_at" in report

# Try generate a report without alerts
def test_generate_report_without_alerts():
    report = generate_report([])

    assert report["total_alerts"] == 0
    assert report["severity_counts"] == {}
    assert report["source_ips"] == []
    assert "generated_at" in report

# Test unknown severities 
def test_generate_report_with_unknown_severity():
    alerts = [
        {"severity": "UNKNOWN", "source_ip": "8.8.8.8"},
        {"source_ip": "1.1.1.1"}
    ]

    report = generate_report(alerts)

    assert report["total_alerts"] == 2
    assert report["severity_counts"] == {
        "UNKNOWN": 2
    }

# Test a UNKNOWN IP
def test_generate_report_without_source_ip():
    alerts = [
        {"severity": "HIGH"},
        {"severity": "CRITICAL", "source_ip": "8.8.8.8"}
    ]

    report = generate_report(alerts)

    assert report["total_alerts"] == 2
    assert report["source_ips"] == ["8.8.8.8", "UNKNOWN"]