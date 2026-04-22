from datetime import datetime

def create_user(username, password_hash, role, first_name, last_name, email, department, mfa_enabled=True):
    return {
        "username": username,
        "password_hash": password_hash,
        "role": role,
        "name": {
            "first": first_name,
            "last": last_name
        },
        "email": email,
        "department": department,
        "status": "active",
        "mfa_enabled": mfa_enabled,
        "created_at": datetime.utcnow()
    }
    