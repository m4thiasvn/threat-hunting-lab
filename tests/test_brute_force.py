from src.detection.brute_force import detect_brute_force
from datetime import datetime,timedelta

# Brute force test with 5 login_failure in less than 60s
def test_detect_brute_force():
    events = [
        {
            "timestamp": "2026-11-05T20:30:00Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:15Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:30Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:45Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:31:00Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        }
    ]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"

# Brute force test with 5 login_failure in 90s
def test_brute_force_outside_time_window():
    events = [
        {
            "timestamp": "2026-11-05T20:30:00Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:15Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:30Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:45Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:31:30Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        }
    ]
    alerts = detect_brute_force(events)
    assert not alerts

# Brute force test with 5 login_failure and 1 login_success
def test_brute_force_with_success():
    events = [
        {
            "timestamp": "2026-11-05T20:30:00Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:15Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:30Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:45Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:31:00Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:31:15Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_success",
            "status": "success"
        }
    ]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"

# Test diffrent users, no alerts expected (admin-2, root-3)
def test_brute_force_different_users():
    events = [
        {
            "timestamp": "2026-11-05T20:30:00Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:10Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:20Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:30Z",
            "username": "admin",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:40Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        }
    ]
    alerts = detect_brute_force(events)
    assert not alerts

# Test 6 fails from the same user
def test_brute_force_multiple_failures():
    events = [
        {
            "timestamp": "2026-11-05T20:30:00Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:10Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:20Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:30Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:40Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:31:05Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        }
    ]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0]["failures"] == 5

# Test 5 Unsorted events 
def test_brute_force_unsorted_events():
    events = [
        {
            "timestamp": "2026-11-05T20:31:00Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:45Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:30Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:15Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        },
        {
            "timestamp": "2026-11-05T20:30:00Z",
            "username": "root",
            "source_ip": "192.168.1.50",
            "event_type": "login_failure",
            "status": "failed"
        }
    ]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"

# 5 login success should not generate an alert
def test_successful_logins_do_not_generate_alerts():
    events = [
        {
            "timestamp": f"2026-11-10T13:0{i}:00-06:00",
            "event_type": "login_success",
            "username": "admin",
            "source_ip": "192.168.1.50"
        }
        for i in range(5)
    ]

    result = detect_brute_force(events)

    assert result == []

# Mix of login success and failures
def test_mixed_logins_below_threshold_do_not_generate_alerts():
    events = [
        {
            "timestamp": "2026-11-10T13:00:00-06:00",
            "event_type": "login_failure",
            "username": "admin",
            "source_ip": "192.168.1.50"
        },
        {
            "timestamp": "2026-11-10T13:00:10-06:00",
            "event_type": "login_success",
            "username": "admin",
            "source_ip": "192.168.1.50"
        },
        {
            "timestamp": "2026-11-10T13:00:20-06:00",
            "event_type": "login_failure",
            "username": "admin",
            "source_ip": "192.168.1.50"
        }
    ]

    result = detect_brute_force(events)

    assert result == []

# Test one login success before 5 failures, should not raise the alert level
def test_success_before_failures_does_not_raise_critical():
    events = [
        {
            "timestamp": "2026-11-10T13:00:00-06:00",
            "event_type": "login_success",
            "username": "admin",
            "source_ip": "192.168.1.50"
        },
        *[
            {
                "timestamp": f"2026-11-10T13:00:{second:02d}-06:00",
                "event_type": "login_failure",
                "username": "admin",
                "source_ip": "192.168.1.50"
            }
            for second in range(10, 60, 10)
        ]
    ]

    result = detect_brute_force(events)

    assert len(result) == 1
    assert result[0]["severity"] == "HIGH"

# 5 alerts in 60sec exactly, should make a HIGH alert not a CRITICAL
def test_failures_exactly_at_60_seconds_generate_alert():
    start = datetime.fromisoformat("2026-11-10T13:00:00-06:00")
    events = [
        {
            "timestamp": (start + timedelta(seconds=second)).isoformat(),
            "event_type": "login_failure",
            "username": "admin",
            "source_ip": "192.168.1.50"
        }
        for second in [0, 15, 30, 45, 60]
    ]

    result = detect_brute_force(events)

    assert len(result) == 1
    assert result[0]["severity"] == "HIGH"
    assert result[0]["failures"] == 5


