from src.processing.normalizer import normalize_event,process_events

# Test an event normalization
def test_normalize_event():
    event = {
        "timestamp": "2026-11-06T00:00:00Z",
        "event_type": " LOGIN_FAILURE ",
        "username": " ADMIN ",
        "source_ip": " 192.168.1.50 ",
        "status": " FAILED "
    }

    result = normalize_event(event)

    assert result["username"] == "admin"
    assert result["source_ip"] == "192.168.1.50"
    assert result["event_type"] == "login_failure"
    assert result["status"] == "failed"

# Test the normalization should not edit the original event
def test_normalize_event_does_not_modify_original():
    event = {
        "timestamp": "2026-11-06T00:00:00Z",
        "event_type": " LOGIN_FAILURE ",
        "username": " ADMIN ",
        "source_ip": " 192.168.1.50 ",
        "status": " FAILED "
    }

    original = event.copy()

    result = normalize_event(event)

    assert event == original
    assert result is not event

# Test process correctly some valid events and normalize them
def test_process_events():
    events = [
        {
            "timestamp": "2026-11-06T00:00:00Z",
            "event_type": " LOGIN_FAILURE ",
            "username": " ADMIN ",
            "source_ip": " 192.168.1.50 ",
            "status": " FAILED "
        },
        {
            "timestamp": "2026-11-06T00:01:00Z",
            "event_type": " LOGIN_SUCCESS ",
            "username": " USER1 ",
            "source_ip": " 192.168.1.60 ",
            "status": " SUCCESS "
        }
    ]

    result = process_events(events)

    assert len(result) == 2
    assert result[0]["username"] == "admin"
    assert result[1]["username"] == "user1"
    assert result[0]["event_type"] == "login_failure"
    assert result[1]["event_type"] == "login_success"

# Test process the valid events and discar de invalid ones
def test_process_events_discards_invalid_events():
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
            "event_type": "login_failure",
            "username": "admin",
            "status": "failed"
        }
    ]

    result = process_events(events)

    assert len(result) == 1
    assert result[0]["username"] == "admin"
    assert result[0]["source_ip"] == "192.168.1.50"

# Test all the invalid events
def test_process_events_with_all_invalid_events():
    events = [
        {
            "timestamp": "2026-11-06T00:00:00Z",
            "event_type": "login_failure",
            "username": "admin"
        },
        {
            "timestamp": "2026-11-06T00:01:00Z",
            "event_type": "login_failure",
            "source_ip": "192.168.1.50"
        }
    ]

    result = process_events(events)

    assert result == []

# Test if a event is not a dictionary do not interrumpt the processing
def test_process_events_with_invalid_data_types():
    events = [
        {
            "timestamp": "2026-11-06T00:00:00Z",
            "event_type": "LOGIN_FAILURE",
            "username": "ADMIN",
            "source_ip": "192.168.1.50",
            "status": "FAILED"
        },
        "invalid event",
        123,
        None
    ]

    result = process_events(events)

    assert len(result) == 1
    assert result[0]["username"] == "admin"