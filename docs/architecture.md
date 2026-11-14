# Threat Hunting Lab Architecture

## Overview

The project uses a modular architecture designed to analyze security events and identify suspicious behavior.

Each component has a specific responsibility.

## Components

### Ingestion
Reads security events from JSON log files.

### Processing
Validates and normalizes incoming events.

### Detection
Analyzes events using detection rules, such as brute-force detection.

### Investigation
Enriches alerts through IP analysis and external IP reputation checks using AbuseIPDB.

### Alerts
Generates, classifies, and manages security alerts, including deduplication and severity escalation.

### Reports
Stores generated alerts and investigation results in JSON files.

### Utils
Contains shared utility functions.

## Processing Flow

```text
JSON Logs
    ↓
Ingestion
    ↓
Processing
    ↓
Detection
    ↓
Investigation
    ↓
Alerts
    ↓
Reports
```
