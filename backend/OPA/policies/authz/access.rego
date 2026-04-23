package authz

import rego.v1

import data.authz.user
import data.authz.device
import data.authz.risk

default allow := false
default deny_reasons := set()

# Decisione finale: accesso consentito solo se tutte le condizioni Zero Trust sono soddisfatte
allow if {
	user.role_allowed
	user.mfa_valid
	user.action_allowed
	device.device_trusted
	device.device_active
	device.ja3_not_blocked
	risk.risk_acceptable
	risk.access_time_valid
}

# Raccolta dei motivi di rifiuto (uno o più possono essere presenti)
deny_reasons contains "role_not_allowed" if {
	not user.role_allowed
}

deny_reasons contains "action_not_allowed" if {
	not user.action_allowed
}

deny_reasons contains "mfa_required" if {
	not user.mfa_valid
}

deny_reasons contains "untrusted_device" if {
	not device.device_trusted
}

deny_reasons contains "device_not_active" if {
	not device.device_active
}

deny_reasons contains "ja3_fingerprint_blocked" if {
	not device.ja3_not_blocked
}

deny_reasons contains "risk_score_too_high" if {
	not risk.risk_acceptable
}

deny_reasons contains "outside_working_hours" if {
	not risk.access_time_valid
}

# Risposta strutturata per Envoy / PDP
response := {
	"allow": allow,
	"deny_reasons": deny_reasons,
	"user": input.user.username,
	"resource": input.resource_name,
	"action": input.action,
	"risk_score": input.risk_score,
}
