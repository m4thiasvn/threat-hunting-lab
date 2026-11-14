import ipaddress


# Validate the format of the IP
def analyze_ip(ip_address):
    try: 
        ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return  {"ip": ip_address, "status":"INVALID"}

    if ip.is_loopback:
        status = "LOOPBACK"
    elif ip.is_private and not ip.is_reserved:
        status = "PRIVATE"
    elif ip.is_global:
        status = "PUBLIC"
    else:
        status = "RESERVED"

    return {
        "ip":str(ip),
        "status": status
    }