def create_policy(policy_name, resource_name, allowed_roles, mfa_required=True, trusted_device_required=True, effect="allow"):
    return {
        "policy_name": policy_name,
        "resource_name": resource_name,
        "allowed_roles": allowed_roles,
        "conditions": {
            "mfa_required": mfa_required,
            "trusted_device_required": trusted_device_required
        },
        "effect": effect,
        "status": "active"
    }
    