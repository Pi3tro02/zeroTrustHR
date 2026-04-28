package authz

import rego.v1

import data.authz.user
import data.authz.device
import data.authz.risk
import data.utils.helpers as h

default allow := false

# Decisione finale: accesso consentito solo se tutte le condizioni Zero Trust sono soddisfatte.
# I valori usati dalle policy sono ricavati dagli header HTTP della richiesta Envoy.
allow if {
	user.role_allowed
	user.mfa_valid
	user.action_allowed
	user.department_allowed
	device.device_trusted
	device.device_active
	device.ja3_not_blocked
	device.ip_in_allowed_zone
	device.os_supported
	risk.risk_acceptable
	risk.access_time_valid
	risk.user_not_blocked
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

deny_reasons contains "department_not_allowed" if {
	not user.department_allowed
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

deny_reasons contains "ip_not_in_allowed_zone" if {
	not device.ip_in_allowed_zone
}

deny_reasons contains "unsupported_os" if {
	not device.os_supported
}

deny_reasons contains "risk_score_too_high" if {
	not risk.risk_acceptable
}

deny_reasons contains "outside_working_hours" if {
	not risk.access_time_valid
}

# NUOVO: motivo di rifiuto per blocco BARAC
deny_reasons contains "user_blocked_by_barac" if {
    not risk.user_not_blocked
}

# Risposta strutturata per Envoy / PDP.
# Il plugin ext_authz di OPA si aspetta la chiave "allowed".
response := {
	"allowed": allow,
	"deny_reasons": deny_reasons,
	"user": h.username,
	"resource": h.resource_name,
	"action": h.action,
	"risk_score": h.risk_score,
}