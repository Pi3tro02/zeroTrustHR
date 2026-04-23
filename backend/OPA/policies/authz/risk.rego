package authz.risk

import rego.v1

# Soglia di rischio dalla policy della risorsa; fallback al default globale 0.7
risk_threshold := threshold if {
	some policy in data.resources.resources
	policy.resource_name == input.resource_name
	threshold := policy.max_risk_score
}

risk_threshold := 0.7 if {
	not _resource_policy_exists
}

_resource_policy_exists if {
	some policy in data.resources.resources
	policy.resource_name == input.resource_name
}

# Il risk_score inviato da Splunk deve essere strettamente inferiore alla soglia
risk_acceptable if {
	input.risk_score < risk_threshold
}

# Classificazione del livello di rischio per audit e log
risk_level := "low" if {
	input.risk_score < 0.3
}

risk_level := "medium" if {
	input.risk_score >= 0.3
	input.risk_score < 0.6
}

risk_level := "high" if {
	input.risk_score >= 0.6
	input.risk_score < risk_threshold
}

risk_level := "critical" if {
	input.risk_score >= risk_threshold
}

# ──────────────────────────────────────────────
# Verifica orario lavorativo (employee e hr)
# ──────────────────────────────────────────────

# Solo employee e hr sono vincolati all'orario; admin e customer non lo sono
_time_restricted_roles := {"employee", "hr"}

# Accesso temporalmente valido per ruoli non soggetti a restrizione oraria
access_time_valid if {
	not input.user.role in _time_restricted_roles
}

# Accesso temporalmente valido se il ruolo è ristretto ma si è nell'orario lavorativo
access_time_valid if {
	input.user.role in _time_restricted_roles
	within_working_hours
}

# Orario lavorativo: lunedì–venerdì, 07:00–19:59 nel fuso orario Europe/Rome
within_working_hours if {
	tz := "Europe/Rome"
	now := time.now_ns()
	[hour, _, _] := time.clock([now, tz])
	hour >= 7
	hour < 20
	time.weekday([now, tz]) in {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
}
