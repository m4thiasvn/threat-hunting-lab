from datetime import datetime 

MAX_LOGIN_ATTEMPTS = 5


# Turn timestamp strings to objects
def parse_timestamp(timestamp):
    date = datetime.fromisoformat(timestamp)
    return date

# Group events by ip and username
def group_events(events):
    groups = {}

    for event in events:
        key = (event["username"],event["source_ip"])
        if key not in groups:
            groups[key] = []
        groups[key].append(event)

    for group in groups.values():
        group.sort(key=lambda event: event["timestamp"])
    
    return groups

# Count the login failures
def count_failures(events):
    count = 0
    for event in events:
        if event["event_type"] == "login_failure" :
            count += 1
    return count

# Detect Brute Force Attacks
def detect_brute_force(events):
    groups = group_events(events)
    alerts = []

    for key, group in groups.items():
        start = 0
        end = 0
        while end <len(group):
            first_event = parse_timestamp(group[start]["timestamp"])
            last_event = parse_timestamp(group[end]["timestamp"])
            time_window = last_event - first_event
            seconds = time_window.total_seconds()
            while seconds > 60:
                start += 1
                first_event = parse_timestamp(group[start]["timestamp"])
                last_event = parse_timestamp(group[end]["timestamp"])
                time_window = last_event - first_event
                seconds = time_window.total_seconds()
            fails = count_failures(group[start:end+1])
            if MAX_LOGIN_ATTEMPTS <= fails and seconds <= 60:
                success = False
                for event in group[end + 1:]:
                    if event["event_type"] == "login_success":
                        success = True
                if success:
                    alerts.append({"username":key[0],"source_ip":key[1],"failures":fails,
                                               "rule":"BRUTE_FORCE_001","severity":"CRITICAL"})
                else:
                    alerts.append({"username":key[0],"source_ip":key[1],"failures":fails,
                                                "rule":"BRUTE_FORCE_001","severity":"HIGH"})
                break
            end += 1
    return alerts

