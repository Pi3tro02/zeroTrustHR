from datetime import datetime
from mod_iniziale_python.database import db 
from mod_iniziale_python.services.log_service import log_event

def evaluate_access(user, device, resource_name, action="read", source_ip=None):
    policy = db.access_policies.find_one({
        "resource_name": resource_name,
        "status": "active"
    })

    if not policy:
        decision = "deny"
        reason = "no_policy_found"
    elif user["role"] not in policy["allowed_roles"]:
        decision = "deny"
        reason = "role_not_allowed"
    elif policy["conditions"].get("mfa_required", False) and not user.get("mfa_enabled", False):
        decision = "deny"
        reason = "mfa_required"
    elif policy["conditions"].get("trusted_device_required", False) and not device.get("trusted", False):
        decision = "deny"
        reason = "untrusted_device"
    else:
        decision = "allow"
        reason = "policy_satisfied"

    access_request = {
        "user_id": user["_id"],
        "device_id": device["_id"],
        "resource_name": resource_name,
        "action": action,
        "request_time": datetime.utcnow(),
        "context": {
            "ip_address": source_ip,
            "mfa_verified": user.get("mfa_enabled", False),
            "trusted_device": device.get("trusted", False)
        },
        "decision": decision,
        "decision_reason": reason
    }

    db.access_requests.insert_one(access_request)
    log_event(user["_id"], "access_request", decision, source_ip, {
        "resource_name": resource_name,
        "reason": reason
    })

    return decision, reason
    