import json
from pathlib import Path

REQUIRED_FIELDS = [
    "timestamp",
    "event_type",
    "username",
    "source_ip",
    "status"
]

# Read the log from a file_path
def read_logs(file_path):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"\nFile not found: {path}")

    events = []

    with open(path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError as error:
                print(f"ERROR on line: {line_number}: {error}")

    return events

# Validate the logs
def validate_event(event):
    missing_fields = []

    if not isinstance(event, dict):
        return REQUIRED_FIELDS.copy()

    for field in REQUIRED_FIELDS:
        if field not in event or event[field] == "" or event[field] is None:
            missing_fields.append(field)

    return missing_fields
    


