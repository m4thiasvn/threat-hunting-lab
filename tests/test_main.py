
import main


# Test the main program with a private IP
def test_main(monkeypatch, tmp_path):
    events = [{"username": "admin"}]
    alerts = [{
        "username": "admin",
        "source_ip": "192.168.1.50",
        "severity": "HIGH"
    }]
    execution_order = []

    # Mock the log reader
    def mock_read_logs(path):
        execution_order.append("read_logs")
        return events

    # Mock the event processor
    def mock_process_events(data):
        execution_order.append("process_events")
        return data

    # Mock the brute force detector
    def mock_detect_brute_force(data):
        execution_order.append("detect_brute_force")
        return alerts

    # Mock the alert creator
    def mock_create_alert(alert):
        execution_order.append("create_alert")
        return alert

    # Mock the alert storage
    def mock_save_alerts(alerts, file_path):
        execution_order.append("save_alerts")
        output_file.write_text("saved")

    monkeypatch.setattr(main, "read_logs", mock_read_logs)
    monkeypatch.setattr(main, "process_events", mock_process_events)
    monkeypatch.setattr(main, "detect_brute_force", mock_detect_brute_force)
    monkeypatch.setattr(main, "create_alert", mock_create_alert)

    output_file = tmp_path / "alerts.json"

    monkeypatch.setattr(main, "save_alerts", mock_save_alerts)

    main.main()

    assert output_file.read_text() == "saved"

    assert execution_order == [
        "read_logs",
        "process_events",
        "detect_brute_force",
        "create_alert",
        "save_alerts"
    ]


# Test the main program with a public IP
def test_main_with_public_ip(monkeypatch, tmp_path):
    alerts = [{
        "username": "admin",
        "source_ip": "8.8.8.8",
        "severity": "HIGH"
    }]

    reputation_data = {
        "ipAddress": "8.8.8.8",
        "abuseConfidenceScore": 0,
        "isPublic": True
    }

    # Mock the log reader
    monkeypatch.setattr(main, "read_logs", lambda path: [])

    # Mock the event processor
    monkeypatch.setattr(main, "process_events", lambda data: data)

    # Mock the brute force detector
    monkeypatch.setattr(main, "detect_brute_force", lambda data: alerts)

    # Mock the IP analyzer
    monkeypatch.setattr(
        main,
        "analyze_ip",
        lambda ip: {"ip": ip, "status": "PUBLIC"}
    )

    # Mock the IP reputation checker
    def mock_check_ip_reputation(ip):
        return reputation_data

    monkeypatch.setattr(
        main,
        "check_ip_reputation",
        mock_check_ip_reputation
    )

    # Capture the alert before saving it
    captured_alerts = []

    def mock_create_alert(alert):
        captured_alerts.append(alert.copy())
        return alert

    monkeypatch.setattr(main, "create_alert", mock_create_alert)

    # Mock the alert storage
    output_file = tmp_path / "alerts.json"

    def mock_save_alerts(alerts, file_path):
        output_file.write_text("saved")

    monkeypatch.setattr(main, "save_alerts", mock_save_alerts)

    main.main()

    # Verify that the reputation data was added to the alert
    assert captured_alerts[0]["ip_reputation"] == reputation_data

    assert output_file.read_text() == "saved"

    assert captured_alerts[0]["ip_analysis"]["status"] == "PUBLIC"
