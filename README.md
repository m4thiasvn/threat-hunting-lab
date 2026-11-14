# Threat Hunting Lab

A practical cybersecurity laboratory focused on developing SOC Analysis and Threat Hunting skills using Python.

## Objective

Build a security monitoring system capable of collecting, processing, and analyzing security events to identify suspicious behavior, generate alerts, investigate IP addresses, and produce automated SOC reports.

## Technologies

- Python 3.12
- Docker
- Docker Compose
- JSON / JSONL
- Requests
- Python-dotenv
- AbuseIPDB API
- Pytest
- Git

## Architecture

The project follows a modular architecture that separates each stage of the security monitoring process.

```text
Threat Hunting Lab
│
├── Data Ingestion
├── Event Processing
├── Threat Detection
├── Alert Management
├── IP Investigation
└── SOC Reporting
```

### Project Structure

```text
threat-hunting-lab/
│
├── data/
│   └── authentication.log
│
├── docs/
│   └── architecture.md
│
├── reports/
│   ├── alerts.json
│   ├── test_alerts.json
│   └── soc_report.json
│
├── rules/
│
├── src/
│   ├── ingestion/
│   │   └── log_reader.py
│   │
│   ├── processing/
│   │   └── normalizer.py
│   │
│   ├── detection/
│   │   └── brute_force.py
│   │
│   ├── alerts/
│   │   └── alert_manager.py
│   │
│   ├── investigation/
│   │   ├── ip_analyzer.py
│   │   └── ip_reputation.py
│   │
│   └── reports/
│       └── report_generator.py
│
├── tests/
│   ├── test_log_reader.py
│   ├── test_normalizer.py
│   ├── test_brute_force.py
│   ├── test_alert_manager.py
│   ├── test_main.py
│   ├── test_ip_analyzer.py
│   ├── test_ip_reputation.py
│   └── test_report_generator.py
│
├── main.py
├── Dockerfile
├── .dockerignore
├── .gitignore
├── requirements.txt
└── README.md
```

## Implemented Features

### 1. Log Ingestion

- Reads authentication logs in JSONL format.
- Processes security events from log files.

### 2. Event Normalization

- Validates incoming security events.
- Normalizes event data before analysis.

### 3. Threat Detection

- Detects brute-force login attempts.
- Identifies repeated authentication failures.
- Detects successful logins following repeated failures.
- Assigns severity levels based on detected behavior.

### 4. Alert Management

- Generates unique alert identifiers using UUID4.
- Adds timezone-aware timestamps.
- Implements alert deduplication with a 300-second window.
- Supports alert severity escalation.

### 5. IP Investigation

- Validates IP address formats.
- Classifies IP addresses as:
  - PUBLIC
  - PRIVATE
  - LOOPBACK
  - RESERVED
  - INVALID
- Integrates with AbuseIPDB to retrieve public IP reputation information.

### 6. SOC Reporting

- Generates automated SOC reports.
- Calculates total alert counts.
- Groups alerts by severity.
- Identifies unique source IP addresses.
- Saves reports in JSON format.

## Detection Rules

The current detection engine includes brute-force detection.

| Condition | Severity |
|---|---|
| 5 or more failed login attempts within 60 seconds | HIGH |
| 5 or more failed attempts followed by a successful login | CRITICAL |

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd threat-hunting-lab
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate the environment:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

The project uses environment variables to protect API credentials.

Create a `.env` file in the project root:

```env
ABUSEIPDB_API_KEY=your_api_key
```

Obtain an API key from [AbuseIPDB](https://www.abuseipdb.com/).

The `.env` file is excluded from version control and Docker build context.

## Execution

Run the application locally:

```bash
python main.py
```

The application processes authentication events, generates alerts, investigates source IP addresses, and produces a SOC report.

Generated reports are stored in:

```text
reports/
├── alerts.json
└── soc_report.json
```

## Testing

Run the complete automated test suite:

```bash
python -m pytest -v
```

The project currently includes **58 automated tests** covering ingestion, normalization, detection, alert management, investigation, reporting, and application integration.

## Docker Integration

Build the Docker image:

```bash
docker build -t threat-hunting-lab .
```

Run the container:

```bash
docker run --rm \
  --env-file .env \
  -v "$(pwd)/reports:/app/reports" \
  threat-hunting-lab
```

The reports directory is mounted as a volume to preserve generated alerts and SOC reports on the host machine.

Run automated tests inside Docker:

```bash
docker run --rm threat-hunting-lab python -m pytest -v
```

## Project Roadmap

- [x] Initial environment setup.
- [x] JSON log ingestion.
- [x] Event normalization.
- [x] Threat detection engine.
- [x] Alert management system.
- [x] IP investigation and reputation analysis.
- [x] Automated SOC report generation.
- [x] Documentation.
- [x] Docker integration.
- [x] Automated testing inside Docker.
- [ ] Final integration review.

## Disclaimer

This project is intended for educational purposes and cybersecurity skill development.

It uses simulated authentication logs and should not be considered a production-ready Security Information and Event Management (SIEM) solution.