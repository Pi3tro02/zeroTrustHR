import requests
import time
import random
import json

OPA_URL = "http://localhost:8181/v1/data/authz/response"

USERS = [
    {"user": "alice_hr", "role": "hr", "department": "HR"},
    {"user": "bob_dev", "role": "employee", "department": "Engineering"},
    {"user": "charlie_admin", "role": "admin", "department": "Security"},
    {"user": "eve_attacker", "role": "customer", "department": "External"},
    {"user": "david_manager", "role": "hr", "department": "Finance"}
]

# Risorse corrette in base a opa/data/resources.json
RESOURCES = [
    "employee_records",
    "payroll_data",
    "company_policies",
    "public_products",
    "audit_logs"
]

IPS = ["192.168.1.50", "10.0.0.15", "10.8.0.5", "203.0.113.42", "172.16.0.100"]

print("Avvio simulazione traffico verso OPA...")
print(f"Target: {OPA_URL}")

def send_request(user_obj, resource, action, ip, trusted=False):
    payload = {
        "input": {
            "attributes": {
                "request": {
                    "http": {
                        "method": "POST",
                        "headers": {
                            "x-user": user_obj["user"],
                            "x-role": user_obj["role"],
                            "x-department": user_obj["department"],
                            "x-resource-name": resource,
                            "x-action": action,
                            "x-device-ip": ip,
                            "x-device-trusted": "true" if trusted else "false",
                            "x-device-status": "active",
                            "x-device-os": "Windows",
                            "x-mfa-enabled": "true"
                        }
                    }
                }
            }
        }
    }
    
    try:
        response = requests.post(OPA_URL, json=payload)
        result = response.json().get("result", {})
        allowed = result.get("allowed", False)
        reasons = result.get("deny_reasons", [])
        risk = result.get("risk_score", 0.0)
        
        status_msg = "Allowed: True" if allowed else f"Allowed: False (Risk: {risk}, Reasons: {reasons})"
        print(f"User: {user_obj['user']:<15} | Res: {resource:<18} | Act: {action:<6} -> {status_msg}")
    except Exception as e:
        print(f"Errore di connessione a OPA: {e}")

try:
    for i in range(1, 51):
        print(f"\n--- Iterazione {i}/50 ---")
        
        # 1. Traffico Legittimo Frequente (Basso rischio)
        # Nota: alice_hr e bob_dev potrebbero essere bloccati di notte per 'outside_working_hours'
        send_request(USERS[0], "employee_records", "read", IPS[0], trusted=True)  # Alice -> employee_records
        send_request(USERS[1], "company_policies", "read", IPS[1], trusted=True)  # Bob -> company_policies
        send_request(USERS[2], "audit_logs", "read", IPS[2], trusted=True)        # Charlie (Admin) -> audit_logs
        send_request(USERS[0], "company_policies", "read", IPS[0], trusted=True)  # Alice -> company_policies
        send_request(USERS[3], "public_products", "read", IPS[3], trusted=False)  # Eve (Customer) -> public_products
        
        # 2. Traffico Malevolo / Anomalie (1 o 2 tentativi per iterazione)
        if i % 3 == 0:
            # Eve (customer) tenta di accedere ad audit_logs
            send_request(USERS[3], "audit_logs", "write", IPS[3], trusted=False)
        if i % 5 == 0:
            # Bob (employee) tenta di leggere payroll_data (solo admin autorizzato)
            send_request(USERS[1], "payroll_data", "read", IPS[1], trusted=True)

        time.sleep(random.uniform(0.5, 1.5))
        
    print("\nSimulazione completata. I log sono stati inviati a Splunk.")
    
except KeyboardInterrupt:
    print("\nSimulazione interrotta dall'utente.")

