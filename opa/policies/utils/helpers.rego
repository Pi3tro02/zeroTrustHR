package utils.helpers

import rego.v1

# Recupera un header HTTP dalla richiesta Envoy ext_authz.
# Se l'header non esiste, restituisce stringa vuota.
header(name) := object.get(input.attributes.request.http.headers, name, "")

# ──────────────────────────────────────────────
# Mapping campi request Envoy -> valori logici usati dalle policy
# ──────────────────────────────────────────────

# Identità utente
username := header("x-user")
role := header("x-role")
department := header("x-department")

# Contesto risorsa/azione
resource_name := header("x-resource-name")
action := header("x-action")

# Contesto dispositivo
device_ip := header("x-device-ip")
device_os := header("x-device-os")
device_status := header("x-device-status")
ja3_fingerprint := header("x-ja3")

# Booleani codificati come header stringa ("true" / "false")
mfa_enabled if {
	lower(header("x-mfa-enabled")) == "true"
}

device_trusted if {
	lower(header("x-device-trusted")) == "true"
}

# Risk score ricevuto come stringa da header HTTP.
# Se convertibile, restituisce il numero.
risk_score := n if {
	raw := header("x-risk-score")
	raw != ""
	n := to_number(raw)
}

# Fallback: se il risk score non è presente, assume rischio massimo.
risk_score := 1.0 if {
	header("x-risk-score") == ""
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