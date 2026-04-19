from datetime import datetime
from database import db

def log_event(user_id, event_type, status, source_ip=None, details=None):
    log_doc = {
        "timestamp": datetime.utcnow(),
        "user_id": user_id,
        "event_type": event_type,
        "status": status,
        "source_ip": source_ip,
        "details": details or {}
    }
    db.audit_logs.insert_one(log_doc)
    