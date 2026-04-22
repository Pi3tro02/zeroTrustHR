from datetime import datetime

def create_device(user_id, device_name, device_type, os, ip_address, trusted=False, ja3_fingerprint=None):
    return {
        "user_id": user_id,
        "device_name": device_name,
        "device_type": device_type,
        "os": os,
        "ip_address": ip_address,
        "trustued": trusted,
        "ja3_fingerprint": ja3_fingerprint,
        "last_seen": datetime.utcnow()
    }
    