from src.investigation.ip_analyzer import analyze_ip

# Test a private IP
def test_analyze_private_ip():
    result = analyze_ip("192.168.1.10")

    assert result == {
        "ip": "192.168.1.10",
        "status": "PRIVATE"
    }

# Test a public IP
def test_analyze_public_ip():
    result = analyze_ip("8.8.8.8")

    assert result == {
        "ip": "8.8.8.8",
        "status": "PUBLIC"
    }

# Test IP lookback
def test_analyze_loopback_ip():
    result = analyze_ip("127.0.0.1")

    assert result == {
        "ip": "127.0.0.1",
        "status": "LOOPBACK"
    }

# Test an invalid IP
def test_analyze_invalid_ip():
    result = analyze_ip("999.999.999.999")

    assert result == {
        "ip": "999.999.999.999",
        "status": "INVALID"
    }

# Test a reserved IP
def test_analyze_reserved_ip():
    result = analyze_ip("240.0.0.1")

    assert result == {
        "ip": "240.0.0.1",
        "status": "RESERVED"
    }