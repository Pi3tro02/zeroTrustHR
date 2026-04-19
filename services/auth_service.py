from database import db 
from models.user_model import create_user
from utils.helpers import hash_password
from services.log_service import log_event

def register_user(username, password, role, first_name, last_name, email, department, mfa_enabled=True):
    password_hash = hash_password(password)

    user_doc = create_user(
        username=username,
        password_hash=password_hash,
        role=role,
        first_name=first_name,
        last_name=last_name,
        email=email,
        department=department,
        mfa_enabled=mfa_enabled
    )

    result = db.users.insert_one(user_doc)
    return result.inserted_id

def authenticate_user(username, password, source_ip=None):
    user = db.users.find_one({"username": username})

    if not user:
        return None
    
    if user["password_hash"] != hash_password(password):
        log_event(user["_id"], "login", "failed", source_ip, {"reason": "wrong_password"})
        return None
    
    if user["status"] != "active":
        log_event(user["_id"], "login", "failed", source_ip, {"reason": "inactive_user"})
        return None
    
    log_event(user["_id"], "login", "success", source_ip, {"role": user["role"]})
    return user
    