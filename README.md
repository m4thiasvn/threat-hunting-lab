# Threat Hunting Lab

A practical cybersecurity lab focused on developing Security Operations Center (SOC) analysis and Threat Hunting skills using Python.

## Project Objective

Build a modular security analysis system capable of collecting, processing, and analyzing security events to identify suspicious behavior, investigate potential threats, and generate security alerts.

## Technologies

- Python 3.12
- JSON
- Requests
- Python-dotenv
- AbuseIPDB API
- Git
- pytest
- Docker (planned for the final stage)

## Architecture

```text
threat-hunting-lab/
├── data/                   # Security logs
├── src/
│   ├── ingestion/          # Log ingestion
│   ├── processing/         # Event validation and normalization
│   ├── detection/          # Threat detection engine
│   ├── alerts/             # Alert management
│   ├── investigation/      # IP analysis and reputation checks
│   └── utils/              # Shared utility functions
├── rules/                  # Detection rules
├── reports/                # SOC reports and alerts
├── tests/                  # Automated tests
├── docs/                   # Project documentation
├── requirements.txt
├── main.py
├── README.md
└── .gitignore
```

## Implemented Features

- JSON log ingestion.
- Event validation and normalization.
- Brute-force attack detection.
- Detection of repeated failed login attempts.
- Automatic alert generation and severity classification.
- Alert deduplication and severity escalation.
- IP address classification (public, private, loopback, reserved, and invalid).
- IP reputation checks using the AbuseIPDB API.
- Automated unit and integration testing.

## Project Roadmap

- [x] Initial environment setup.
- [x] JSON log ingestion.
- [x] Event normalization.
- [x] Threat detection engine.
- [x] Alert management system.
- [x] Alert investigation and IP reputation analysis.
- [ ] SOC report generation.
- [ ] Documentation updates.
- [ ] Docker integration.
- [ ] Final testing and project integration.

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd threat-hunting-lab
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

The project uses AbuseIPDB for public IP reputation checks.

Create a `.env` file in the project root and configure your API key:

```env
ABUSEIPDB_API_KEY=your_api_key
```

Never commit your `.env` file or expose your API key.

## Execution

Run the main program:

```bash
python main.py
```

## Testing

Run the complete automated test suite:

```bash
python -m pytest -v
```

## Disclaimer

This project uses simulated security data and is intended for educational purposes only. It is not designed to replace a production SIEM platform.