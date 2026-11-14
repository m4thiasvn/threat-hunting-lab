import json
import pytest  # pyright: ignore[reportMissingImports]
from src.ingestion.log_reader import validate_event,read_logs, REQUIRED_FIELDS

# Test a valid event
def test_valid_event():
    event = {
        "timestamp": "2026-11-06T00:00:00Z",
        "event_type": "login_failure",
        "username": "admin",
        "source_ip": "192.168.1.50",
        "status": "failed"
    }

    assert validate_event(event) == []

# Test missing ip
def test_missing_ip():
    event = {
        "timestamp": "2026-11-06T00:00:00Z",
        "event_type": "login_failure",
        "username": "admin",
        "status": "failed"
    }

    assert validate_event(event) == ["source_ip"]

# Test missing user
def test_missing_user():
    event = {
        "timestamp": "2026-11-06T00:00:00Z",
        "event_type": "login_failure",
        "source_ip": "192.168.1.50"
    }

    assert validate_event(event) == ["username", "status"]

# Test empty username
def test_empty_username():
    event = {
        "timestamp": "2026-11-06T00:00:00Z",
        "event_type": "login_failure",
        "username": "",
        "source_ip": "192.168.1.50",
        "status": "failed"
    }

    assert validate_event(event) == ["username"]

# Test null username
def test_null_username():
    event = {
        "timestamp": "2026-11-06T00:00:00Z",
        "event_type": "login_failure",
        "username": None,
        "source_ip": "192.168.1.50",
        "status": "failed"
    }

    assert validate_event(event) == ["username"]

# Test the log reading
def test_read_logs(tmp_path):
    log_file = tmp_path / "authentication.log"

    events = [
        {
            "timestamp": "2026-11-06T00:00:00Z",
            "event_type": "login_failure",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-06T00:01:00Z",
            "event_type": "login_success",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "status": "success"
        }
    ]

    with open(log_file, "w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")

    result = read_logs(log_file)

    assert len(result) == 2
    assert result == events

# Test the log file not found
def test_read_logs_file_not_found(tmp_path):
    log_file = tmp_path / "nonexistent.log"

    with pytest.raises(FileNotFoundError):
        read_logs(log_file)

# Test empty lines in the JSON
def test_read_logs_ignores_empty_lines(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        '{"username": "admin"}\n\n{"username": "root"}\n',
        encoding="utf-8"
    )

    events = read_logs(log_file)

    assert len(events) == 2

# Test if the JSON file is a dictionary in Python
def test_invalid_event_type():
    event = "this is not a dictionary"

    result = validate_event(event)

    assert result == REQUIRED_FIELDS