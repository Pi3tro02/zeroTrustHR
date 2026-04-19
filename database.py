from pymongo import MongoClient, ASCENDING
from config import MONGO_URI, DB_NAME

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

# Metodo che gestisce la connessione al database
def connect_to_mongo():
    try:
        client.admin.command("ping")
        print("Connessione a MongoDB riuscita!")
    except Exception as e:
        print("Errore di connesisone a MongoDB: ", e)
        raise

# Metodo che gestisce la creazione degli indici
def init_db():
    db.users.create_index([("username", ASCENDING)], unique=True)
    db.users.create_index([("email", ASCENDING)], unique=True)

    db.devices.create_index([("user_id", ASCENDING)])
    db.devices.create_index([("trusted", ASCENDING)])

    db.access_policies.create_index([("policy_name", ASCENDING)], unique=True)
    db.access_policies.create_index([("resource_name", ASCENDING)])

    db.audit_logs.create_index([("timestamp", ASCENDING)])
    db.audit_logs.create_index([("user_id", ASCENDING)])
    db.audit_logs.create_index([("event_type", ASCENDING)])

    db.access_requests.create_index([("user_id", ASCENDING)])
    db.access_requests.create_index([("resource_name", ASCENDING)])
    db.access_requests.create_index([("request_time", ASCENDING)])

    print("Database inizializzato correttamente!")
