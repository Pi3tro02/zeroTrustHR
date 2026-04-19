from database import connect_to_mongo, init_db, db 
from services.auth_service import register_user, authenticate_user
from services.access_service import evaluate_access
from models.device_model import create_device
from models.policy_model import create_policy

def seed_data():
    if db.access_policies.count_documents({}) == 0:
        db.access_policies.insert_one(
            create_policy(
                policy_name="HR records policy",
                resource_name="employee_records",
                allowed_roles=["admin", "hr_manager"],
                mfa_required=True,
                trusted_device_required=True
            )
        )

    if db.users.count_documents({"username": "admin"}) == 0:
        user_id = register_user(
            username="admin",
            password="admin123",
            role="admin",
            first_name="Pietro",
            last_name="Salvatore",
            email="admin@company.com",
            department="IT",
            mfa_enabled=True
        )

        device_doc = create_device(
            user_id=user_id,
            device_name="Admin Laptop",
            device_type="laptop",
            os="macOS",
            ip_address="192.168.1.10",
            trusted=True,
            ja3_fingerprint="sample_ja3_hash"
        )
        db.devices.insert_one(device_doc)

def main():
    connect_to_mongo()
    init_db()
    seed_data()

    user = authenticate_user("admin", "admin123", source_ip="192.168.1.10")

    if not user:
        print("Autenticazione fallita")
        return
    
    device = db.devices.find_one({"user_id": user["_id"]})

    if not device:
        print("Dispositivo non trovato")
        return

    decision, reason = evaluate_access(
        user=user,
        device=device,
        resource_name="employee_records",
        action="read",
        source_ip="192.168.1.10"
    )

    print("Decisione accesso:", decision)
    print("Motivo:", reason)

if __name__ == "__main__":
    main()
    