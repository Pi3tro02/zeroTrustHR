package utils.helpers

import rego.v1

# Recupera un header HTTP dalla richiesta Envoy ext_authz.
# Se l'header non esiste, restituisce stringa vuota.
http_request := object.get(object.get(object.get(input, "attributes", {}), "request", {}), "http", {})
http_headers := object.get(http_request, "headers", {})
header(name) := object.get(http_headers, name, "")

bearer_token := token if {
	auth_header := header("authorization")
	startswith(lower(auth_header), "bearer ")
	token := substring(auth_header, 7, -1)
}

jwt_payload := payload if {
	[_, payload, _] := io.jwt.decode(bearer_token)
}

# ──────────────────────────────────────────────
# Mapping campi request Envoy -> valori logici usati dalle policy
# ──────────────────────────────────────────────

# Identità utente
username := header("x-user") if {
	header("x-user") != ""
}

username := object.get(object.get(input, "user", {}), "username", "") if {
	header("x-user") == ""
	not jwt_payload.user
}

username := jwt_payload.user if {
	header("x-user") == ""
	jwt_payload.user
}

role := header("x-role") if {
	header("x-role") != ""
}

role := object.get(object.get(input, "user", {}), "role", "") if {
	header("x-role") == ""
	not jwt_payload.role
}

role := jwt_payload.role if {
	header("x-role") == ""
	jwt_payload.role
}

department := header("x-department") if {
	header("x-department") != ""
}

department := object.get(object.get(input, "user", {}), "department", "") if {
	header("x-department") == ""
	not jwt_payload.department
}

department := jwt_payload.department if {
	header("x-department") == ""
	jwt_payload.department
}

# Contesto risorsa/azione
resource_name := header("x-resource-name") if {
	header("x-resource-name") != ""
}

resource_name := object.get(input, "resource_name", "") if {
	header("x-resource-name") == ""
}

action := header("x-action") if {
	header("x-action") != ""
}

action := "read" if {
	header("x-action") == ""
	object.get(http_request, "method", "") == "GET"
}

action := object.get(input, "action", "") if {
	header("x-action") == ""
	object.get(http_request, "method", "") != "GET"
}

# Contesto dispositivo
xfcc := header("x-forwarded-client-cert")

cert_device_uri := uri if {
	some segment in split(xfcc, ";")
	part := trim(segment, " ")
	startswith(part, "URI=")
	raw := trim_prefix(part, "URI=")
	uri := trim(raw, "\"")
}

cert_device_uri := "" if {
	not contains(xfcc, "URI=")
}

cert_device_id := device_id if {
	startswith(cert_device_uri, "urn:zerotrusthr:device:")
	device_id := trim_prefix(cert_device_uri, "urn:zerotrusthr:device:")
}

cert_device_id := "" if {
	not startswith(cert_device_uri, "urn:zerotrusthr:device:")
}

trusted_device_record := device if {
	cert_device_id != ""
	some device in data.trusted_devices
	device.device_id == cert_device_id
	device.certificate_san_uri == cert_device_uri
}

has_trusted_device_record if {
	trusted_device_record.device_id != ""
}

device_ip := trusted_device_record.ip_address if {
	has_trusted_device_record
}

device_ip := header("x-device-ip") if {
	not has_trusted_device_record
	header("x-device-ip") != ""
}

device_ip := object.get(object.get(input, "device", {}), "ip_address", "") if {
	not has_trusted_device_record
	header("x-device-ip") == ""
}

device_os := trusted_device_record.os if {
	has_trusted_device_record
}

device_os := header("x-device-os") if {
	not has_trusted_device_record
	header("x-device-os") != ""
}

device_os := object.get(object.get(input, "device", {}), "os", "") if {
	not has_trusted_device_record
	header("x-device-os") == ""
}

device_status := trusted_device_record.status if {
	has_trusted_device_record
}

device_status := header("x-device-status") if {
	not has_trusted_device_record
	header("x-device-status") != ""
}

device_status := object.get(object.get(input, "device", {}), "status", "") if {
	not has_trusted_device_record
	header("x-device-status") == ""
}

ja3_fingerprint := trusted_device_record.ja3_fingerprint if {
	has_trusted_device_record
}

ja3_fingerprint := header("x-ja3") if {
	not has_trusted_device_record
	header("x-ja3") != ""
}

ja3_fingerprint := object.get(object.get(input, "device", {}), "ja3_fingerprint", "") if {
	not has_trusted_device_record
	header("x-ja3") == ""
}

# Booleani codificati come header stringa ("true" / "false")
mfa_enabled if {
	lower(header("x-mfa-enabled")) == "true"
}

mfa_enabled if {
	header("x-mfa-enabled") == ""
	jwt_payload.mfa_enabled == true
}

mfa_enabled if {
	header("x-mfa-enabled") == ""
	not jwt_payload.mfa_enabled
	object.get(object.get(input, "user", {}), "mfa_enabled", false) == true
}

device_trusted if {
	has_trusted_device_record
	trusted_device_record.trusted == true
	trusted_device_record.hardware_key_type in {"tpm", "secure_enclave"}
}

device_trusted if {
	has_trusted_device_record
	trusted_device_record.trusted == true
	trusted_device_record.hardware_key_type == "software"
	trusted_device_record.ja3_fingerprint != ""
	header("x-ja3") != ""
	trusted_device_record.ja3_fingerprint == header("x-ja3")
}

device_trusted if {
	not has_trusted_device_record
	lower(header("x-device-trusted")) == "true"
}

device_trusted if {
	not has_trusted_device_record
	header("x-device-trusted") == ""
	object.get(object.get(input, "device", {}), "trusted", false) == true
}

# Risk score ricevuto come stringa da header HTTP.
# Se convertibile, restituisce il numero.
risk_score := n if {
	raw := header("x-risk-score")
	raw != ""
	n := to_number(raw)
}

risk_score := n if {
	header("x-risk-score") == ""
	object.get(input, "risk_score", "") != ""
	n := object.get(input, "risk_score", 1.0)
}

# Fallback: se il risk score non è presente, assume rischio massimo.
risk_score := 1.0 if {
	header("x-risk-score") == ""
	object.get(input, "risk_score", "") == ""
}

# ──────────────────────────────────────────────
# Utility generiche
# ──────────────────────────────────────────────

# Controlla se un valore è presente in un array
value_in_array(array, value) if {
	some item in array
	item == value
}

# Controlla se un IP è contenuto in un range CIDR
ip_in_cidr(ip, cidr) if {
	net.cidr_contains(cidr, ip)
}

# Controlla se un IP è in almeno uno dei range CIDR forniti
ip_in_any_cidr(ip, cidrs) if {
	some cidr in cidrs
	net.cidr_contains(cidr, ip)
}

# Normalizza il risk_score nel range [0.0, 1.0]
normalize_risk(score) := 1.0 if {
	score > 1.0
}

normalize_risk(score) := 0.0 if {
	score < 0.0
}

normalize_risk(score) := score if {
	score >= 0.0
	score <= 1.0
}

# Verifica che un ruolo sia valido secondo la gerarchia
role_in_hierarchy(role, allowed_roles) if {
	some allowed in allowed_roles
	hierarchy := data.role_hierarchy[allowed]
	role in hierarchy
}

# Restituisce true se il set di deny_reasons è vuoto (accesso potenzialmente concesso)
no_deny_reasons(reasons) if {
	count(reasons) == 0
}

# Formatta una risposta di audit con timestamp
audit_entry(decision, user, resource, action, reasons) := {
	"decision": decision,
	"user": user,
	"resource": resource,
	"action": action,
	"deny_reasons": reasons,
	"evaluated_at": time.now_ns(),
}
