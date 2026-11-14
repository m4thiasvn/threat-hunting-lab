from src.investigation.ip_reputation import check_ip_reputation
from src.investigation.ip_reputation import HEADERS, API_URL, MAX_AGE_IN_DAYS
from unittest.mock import patch, Mock
import pytest,requests

# Test reputation success
@patch("src.investigation.ip_reputation.requests.get")
def test_check_ip_reputation_success(mock_get):
    mock_response = Mock()
    mock_response.json.return_value = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
            "isPublic": True
        }
    }

    mock_get.return_value = mock_response

    result = check_ip_reputation("8.8.8.8")

    assert result["ipAddress"] == "8.8.8.8"
    assert result["abuseConfidenceScore"] == 0
    assert result["isPublic"] is True

# Verify the petition params
@patch("src.investigation.ip_reputation.requests.get")
def test_check_ip_reputation_request_params(mock_get):
    mock_response = Mock()
    mock_response.json.return_value = {"data": {}}
    mock_get.return_value = mock_response

    check_ip_reputation("8.8.8.8")

    mock_get.assert_called_once_with(
    API_URL,
    headers=HEADERS,
    params={
        "ipAddress": "8.8.8.8",
        "maxAgeInDays": MAX_AGE_IN_DAYS
    },
    timeout=10
)

# Test error catch from HTTP
@patch("src.investigation.ip_reputation.requests.get")
def test_check_ip_reputation_http_error(mock_get):
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "401 Unauthorized"
    )
    mock_get.return_value = mock_response

    with pytest.raises(requests.exceptions.HTTPError):
        check_ip_reputation("8.8.8.8")


# Test timeout
@patch("src.investigation.ip_reputation.requests.get")
def test_check_ip_reputation_connection_error(mock_get):
    mock_get.side_effect = requests.exceptions.ConnectionError(
        "Connection failed"
    )

    with pytest.raises(requests.exceptions.ConnectionError):
        check_ip_reputation("8.8.8.8")

# Test invalid JSON response 
@patch("src.investigation.ip_reputation.requests.get")
def test_check_ip_reputation_invalid_json(mock_get):
    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "invalid", 0
    )
    mock_get.return_value = mock_response

    with pytest.raises(requests.exceptions.JSONDecodeError):
        check_ip_reputation("8.8.8.8")


