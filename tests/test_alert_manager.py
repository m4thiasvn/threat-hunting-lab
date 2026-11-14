import uuid,json,pytest # pyright: ignore[reportMissingImports]
from src.alerts.alert_manager import create_alert, is_duplicate, save_alerts
from datetime import datetime

# Test an alert creation
def test_create_alert():
    alert = {
        "username": "test_user",
        "source_ip": "10.0.0.50",
        "failures": 5,
        "rule": "BRUTE_FORCE_001",
        "severity": "HIGH"
    }

    result = create_alert(alert)

    uuid.UUID(result["alert_id"])

    datetime.fromisoformat(result["timestamp"])

    assert result["severity"] == "HIGH"
    assert result["description"]

# Test if an alert is duplicate
def test_is_duplicate():
    old_alert = {
        "username": "test_user",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:00:00-06:00"
    }

    new_alert = {
        "username": "test_user",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:02:00-06:00"
    }

    assert is_duplicate(new_alert, [old_alert]) is True

# Test 2 same alerts, but with the 5 min window, should not be considered as duplicates
def test_is_not_duplicate_after_window():
    old_alert = {
        "username": "test_user",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:00:00-06:00"
    }

    new_alert = {
        "username": "test_user",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:06:00-06:00"
    }

    assert is_duplicate(new_alert, [old_alert]) is False

# Test, different users, should not be considered as duplicates
def test_different_users_are_not_duplicates():
    old_alert = {
        "username": "admin",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:00:00-06:00"
    }

    new_alert = {
        "username": "test_user",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:02:00-06:00"
    }

    assert is_duplicate(new_alert, [old_alert]) is False

# Test, alerts from differents IPs should not be considered as duplicates
def test_different_ips_are_not_duplicates():
    old_alert = {
        "username": "test_user",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:00:00-06:00"
    }

    new_alert = {
        "username": "test_user",
        "source_ip": "10.0.0.60",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:02:00-06:00"
    }

    assert is_duplicate(new_alert, [old_alert]) is False

# Test the alerts updates severity 
def test_save_alerts_updates_severity(tmp_path):
    file_path = tmp_path / "test_alerts.json"

    high_alert = {
        "username": "test_user",
        "source_ip": "10.0.0.50",
        "failures": 5,
        "rule": "BRUTE_FORCE_001",
        "severity": "HIGH",
        "timestamp": "2026-11-10T13:00:00-06:00",
        "alert_id": "original-id",
        "description": "High severity alert"
    }

    critical_alert = {
        "username": "test_user",
        "source_ip": "10.0.0.50",
        "failures": 5,
        "rule": "BRUTE_FORCE_001",
        "severity": "CRITICAL",
        "timestamp": "2026-11-10T13:02:00-06:00",
        "alert_id": "new-id",
        "description": "Critical severity alert"
    }

    save_alerts([high_alert], file_path)
    save_alerts([critical_alert], file_path)

    with open(file_path, "r", encoding="utf-8") as file:
        saved_alerts = json.load(file)

    assert len(saved_alerts) == 1
    assert saved_alerts[0]["severity"] == "CRITICAL"
    assert saved_alerts[0]["alert_id"] == "original-id"
    assert saved_alerts[0]["description"] == "Critical severity alert"

# Test if we have a CRITICAL alert and a new HIGH from the same user, IP and rule, should not downgrade
def test_lower_severity_does_not_overwrite_higher(tmp_path):
    file_path = tmp_path / "test_alerts.json"

    critical_alert = {
        "username": "test_user",
        "source_ip": "10.0.0.50",
        "failures": 5,
        "rule": "BRUTE_FORCE_001",
        "severity": "CRITICAL",
        "timestamp": "2026-11-10T13:00:00-06:00",
        "alert_id": "original-id",
        "description": "Critical severity alert"
    }

    high_alert = {
        "username": "test_user",
        "source_ip": "10.0.0.50",
        "failures": 5,
        "rule": "BRUTE_FORCE_001",
        "severity": "HIGH",
        "timestamp": "2026-11-10T13:02:00-06:00",
        "alert_id": "new-id",
        "description": "High severity alert"
    }

    save_alerts([critical_alert], file_path)
    save_alerts([high_alert], file_path)

    with open(file_path, "r", encoding="utf-8") as file:
        saved_alerts = json.load(file)

    assert len(saved_alerts) == 1
    assert saved_alerts[0]["severity"] == "CRITICAL"
    assert saved_alerts[0]["alert_id"] == "original-id"
    assert saved_alerts[0]["description"] == "Critical severity alert"

# Test a corrupt JSON file
def test_save_alerts_with_corrupted_json(tmp_path):
    file_path = tmp_path / "alerts.json"
    file_path.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(ValueError, match="Cannot read alerts file"):
        save_alerts([], file_path)

# Test a invalid timestamp in a new alert
def test_is_duplicate_with_invalid_new_timestamp():
    old_alert = {
        "username": "admin",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:00:00-06:00"
    }

    new_alert = {
        "username": "admin",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "invalid-timestamp"
    }

    with pytest.raises(ValueError):
        is_duplicate(new_alert, [old_alert])

# Test a invalir timestamp in a existent alert
def test_is_duplicate_with_invalid_old_timestamp():
    old_alert = {
        "username": "admin",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "invalid-timestamp"
    }

    new_alert = {
        "username": "admin",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:02:00-06:00"
    }

    with pytest.raises(ValueError):
        is_duplicate(new_alert, [old_alert])

# Test if a new alert occurred before the old
def test_new_alert_before_old_alert_is_not_duplicate():
    old_alert = {
        "username": "admin",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:05:00-06:00"
    }

    new_alert = {
        "username": "admin",
        "source_ip": "10.0.0.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:02:00-06:00"
    }

    assert is_duplicate(new_alert, [old_alert]) is False

# Test a valid JSON but wrong structure
def test_save_alerts_with_invalid_existing_alert_structure(tmp_path):
    file_path = tmp_path / "alerts.json"

    file_path.write_text(
        '["alerta_invalida", 123]',
        encoding="utf-8"
    )

    new_alert = {
        "username": "admin",
        "source_ip": "192.168.1.50",
        "failures": 5,
        "rule": "BRUTE_FORCE_001",
        "severity": "HIGH",
        "timestamp": "2026-11-10T13:00:00-06:00",
        "alert_id": "test-id",
        "description": "Test alert"
    }

    with pytest.raises(ValueError):
        save_alerts([new_alert], file_path=file_path)

# Test if there is an alert with missing fields
def test_save_alerts_with_missing_fields_in_existing_alert(tmp_path):
    file_path = tmp_path / "alerts.json"

    file_path.write_text(
        '[{"username": "admin"}]',
        encoding="utf-8"
    )

    new_alert = {
        "username": "admin",
        "source_ip": "192.168.1.50",
        "failures": 5,
        "rule": "BRUTE_FORCE_001",
        "severity": "HIGH",
        "timestamp": "2026-11-10T13:00:00-06:00",
        "alert_id": "test-id",
        "description": "Test alert"
    }

    with pytest.raises(ValueError, match="missing fields"):
        save_alerts([new_alert], file_path=file_path)

# Test a invalid severity a existing alert
def test_save_alerts_with_invalid_severity_in_existing_alert(tmp_path):
    file_path = tmp_path / "alerts.json"

    invalid_alert = {
        "username": "admin",
        "source_ip": "192.168.1.50",
        "rule": "BRUTE_FORCE_001",
        "severity": "URGENT",
        "timestamp": "2026-11-10T13:00:00-06:00",
        "description": "Invalid severity"
    }

    file_path.write_text(
        json.dumps([invalid_alert]),
        encoding="utf-8"
    )

    new_alert = {
        "username": "admin",
        "source_ip": "192.168.1.50",
        "rule": "BRUTE_FORCE_001",
        "severity": "HIGH",
        "timestamp": "2026-11-10T13:01:00-06:00",
        "description": "Test alert"
    }

    with pytest.raises(ValueError, match="Invalid severity"):
        save_alerts([new_alert], file_path=file_path)

# Test a invalid timestamp
def test_save_alerts_with_invalid_timestamp_in_existing_alert(tmp_path):
    file_path = tmp_path / "alerts.json"

    existing_alert = {
        "username": "admin",
        "source_ip": "192.168.1.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "invalid-timestamp",
        "severity": "HIGH",
        "description": "Test alert"
    }

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump([existing_alert], file)

    with pytest.raises(ValueError, match="Invalid timestamp"):
        save_alerts([], file_path)

# Test an invalid severity in a new alert
def test_save_alerts_with_invalid_severity_in_new_alert(tmp_path):
    file_path = tmp_path / "alerts.json"

    alert = {
        "username": "admin",
        "source_ip": "192.168.1.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "2026-11-10T13:00:00-06:00",
        "severity": "URGENT",
        "description": "Test alert"
    }

    with pytest.raises(ValueError, match="Invalid severity"):
        save_alerts([alert], file_path)

# Test a new alert with an invalid timestamp
def test_save_alerts_with_invalid_timestamp_in_new_alert(tmp_path):
    file_path = tmp_path / "alerts.json"

    alert = {
        "username": "admin",
        "source_ip": "192.168.1.50",
        "rule": "BRUTE_FORCE_001",
        "timestamp": "invalid-timestamp",
        "severity": "HIGH",
        "description": "Test alert"
    }

    with pytest.raises(ValueError, match="Invalid timestamp"):
        save_alerts([alert], file_path)



