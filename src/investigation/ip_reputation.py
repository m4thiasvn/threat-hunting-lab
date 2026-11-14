import os, requests,ipaddress
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
API_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_IN_DAYS = 90
HEADERS = {
    "Accept": "application/json",
    "Key": ABUSEIPDB_API_KEY
}

# Check the IP reputation
def check_ip_reputation(ip_address):

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip_address}")


    params = {
        "ipAddress":ip_address,
        "maxAgeInDays": MAX_AGE_IN_DAYS
    }

    response = requests.get(
        API_URL,
        headers=HEADERS,
        params=params,
        timeout=10
    )

    response.raise_for_status()

    data = response.json()

    return data ["data"]