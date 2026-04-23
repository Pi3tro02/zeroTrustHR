package utils.helpers

import rego.v1

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
	hierarchy := data.roles.role_hierarchy[allowed]
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
