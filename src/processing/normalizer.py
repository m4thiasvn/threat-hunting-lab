from src.ingestion.log_reader import validate_event
from src.ingestion.log_reader import read_logs

file_path = "data/authentication.log"
events = read_logs(file_path)

# Function for normalize a log
def normalize_event(event):
    normalized = event.copy()

    normalized["username"] = normalized["username"].strip().lower()
    normalized["source_ip"] = normalized["source_ip"].strip().lower()
    normalized["event_type"] = normalized["event_type"].strip().lower()
    normalized["status"] = normalized["status"].strip().lower()

    return normalized

# Process the logs (validate them) and normalize them
def process_events(events):
    valid_events = []
    for event in events:
        missing_fields = validate_event(event)
        if not missing_fields:
            valid_events.append(event)
        else:
            print(missing_fields)

    normalized_events = []

    for event in valid_events:
        event = normalize_event(event)
        normalized_events.append(event)

    return normalized_events
