package authz_test

import rego.v1

# ──────────────────────────────────────────────
# Timestamp di riferimento — lunedì 2025-01-13 10:00 Europe/Rome
# ──────────────────────────────────────────────

monday_10h := 1736758800000000000

monday_23h := 1736805600000000000

saturday := 1737190800000000000

# ──────────────────────────────────────────────
# Dati di test condivisi
# ──────────────────────────────────────────────

mock_resources := {"resources": [
	{
		"resource_name": "employee_records",
		"resource_sensitivity": "high",
		"allowed_roles": ["hr", "admin"],
		"allowed_actions": ["read", "write", "update"],
		"max_risk_score": 0.7,
		"conditions": {
			"mfa_required": true,
			"trusted_device_required": true,
		},
	},
	{
		"resource_name": "leave_requests",
		"resource_sensitivity": "medium",
		"allowed_roles": ["hr", "employee", "admin"],
		"allowed_actions": ["read", "write", "update"],
		"max_risk_score": 0.7,
		"conditions": {
			"mfa_required": false,
			"trusted_device_required": false,
		},
	},
]}

mock_roles := {
	"sensitive_departments": ["HR", "Finance", "Legal"],
	"blocked_ja3_fingerprints": [],
	"allowed_network_zones": {"internal": ["10.0.0.0/8"]},
}

valid_input := {
	"user": {
		"username": "alice_hr",
		"role": "hr",
		"mfa_enabled": true,
		"department": "HR",
	},
	"device": {
		"trusted": true,
		"ja3_fingerprint": "abc123",
		"ip_address": "10.0.1.42",
		"os": "Windows 11",
		"device_type": "laptop",
		"status": "active",
	},
	"resource_name": "employee_records",
	"action": "read",
	"source_ip": "10.0.1.42",
	"risk_score": 0.25,
}

# ──────────────────────────────────────────────
# Test: accesso consentito
# ──────────────────────────────────────────────

test_allow_hr_reads_employee_records if {
	authz.allow
		with input as valid_input
		with data.resources as mock_resources
		with data.roles as mock_roles
		with time.now_ns as monday_10h
}

test_response_allow_true if {
	r := authz.response
		with input as valid_input
		with data.resources as mock_resources
		with data.roles as mock_roles
		with time.now_ns as monday_10h
	r.allow == true
	r.user == "alice_hr"
	r.resource == "employee_records"
	r.action == "read"
}

test_deny_reasons_empty_on_allow if {
	reasons := authz.deny_reasons
		with input as valid_input
		with data.resources as mock_resources
		with data.roles as mock_roles
		with time.now_ns as monday_10h
	count(reasons) == 0
}

# ──────────────────────────────────────────────
# Test: ruolo non autorizzato
# ──────────────────────────────────────────────

test_deny_wrong_role if {
	not authz.allow
		with input as object.union(valid_input, {"user": {
			"username": "bob",
			"role": "customer",
			"mfa_enabled": true,
			"department": "Sales",
		}})
		with data.resources as mock_resources
		with data.roles as mock_roles
}

test_deny_reason_role_not_allowed if {
	"role_not_allowed" in authz.deny_reasons
		with input as object.union(valid_input, {"user": {
			"username": "bob",
			"role": "customer",
			"mfa_enabled": true,
			"department": "Sales",
		}})
		with data.resources as mock_resources
		with data.roles as mock_roles
}

# ──────────────────────────────────────────────
# Test: MFA assente
# ──────────────────────────────────────────────

test_deny_no_mfa if {
	not authz.allow
		with input as object.union(valid_input, {"user": {
			"username": "alice_hr",
			"role": "hr",
			"mfa_enabled": false,
			"department": "HR",
		}})
		with data.resources as mock_resources
		with data.roles as mock_roles
}

test_deny_reason_mfa_required if {
	"mfa_required" in authz.deny_reasons
		with input as object.union(valid_input, {"user": {
			"username": "alice_hr",
			"role": "hr",
			"mfa_enabled": false,
			"department": "HR",
		}})
		with data.resources as mock_resources
		with data.roles as mock_roles
}

# ──────────────────────────────────────────────
# Test: risk score sopra soglia
# ──────────────────────────────────────────────

test_deny_high_risk_score if {
	not authz.allow
		with input as object.union(valid_input, {"risk_score": 0.85})
		with data.resources as mock_resources
		with data.roles as mock_roles
}

test_deny_reason_risk_too_high if {
	"risk_score_too_high" in authz.deny_reasons
		with input as object.union(valid_input, {"risk_score": 0.85})
		with data.resources as mock_resources
		with data.roles as mock_roles
}

# ──────────────────────────────────────────────
# Test: risk score esattamente al limite (0.7 non è < 0.7 → deny)
# ──────────────────────────────────────────────

test_deny_risk_score_at_threshold if {
	not authz.allow
		with input as object.union(valid_input, {"risk_score": 0.7})
		with data.resources as mock_resources
		with data.roles as mock_roles
}

# ──────────────────────────────────────────────
# Test: deny multiplo (ruolo errato + MFA assente)
# ──────────────────────────────────────────────

test_multiple_deny_reasons if {
	reasons := authz.deny_reasons
		with input as {
			"user": {
				"username": "bob",
				"role": "employee",
				"mfa_enabled": false,
				"department": "Sales",
			},
			"device": {
				"trusted": false,
				"ja3_fingerprint": "xyz",
				"ip_address": "192.168.50.10",
				"os": "Windows 10",
				"device_type": "laptop",
				"status": "active",
			},
			"resource_name": "employee_records",
			"action": "read",
			"source_ip": "192.168.50.10",
			"risk_score": 0.85,
		}
		with data.resources as mock_resources
		with data.roles as mock_roles
	"role_not_allowed" in reasons
	"mfa_required" in reasons
	"untrusted_device" in reasons
	"risk_score_too_high" in reasons
}

# ──────────────────────────────────────────────
# Test: restrizione orario lavorativo
# ──────────────────────────────────────────────

test_deny_hr_outside_working_hours if {
	not authz.allow
		with input as valid_input
		with data.resources as mock_resources
		with data.roles as mock_roles
		with time.now_ns as monday_23h
}

test_deny_reason_outside_working_hours if {
	"outside_working_hours" in authz.deny_reasons
		with input as valid_input
		with data.resources as mock_resources
		with data.roles as mock_roles
		with time.now_ns as monday_23h
}

test_deny_hr_on_weekend if {
	not authz.allow
		with input as valid_input
		with data.resources as mock_resources
		with data.roles as mock_roles
		with time.now_ns as saturday
}

test_allow_admin_on_weekend if {
	authz.allow
		with input as object.union(valid_input, {"user": {
			"username": "admin_user",
			"role": "admin",
			"mfa_enabled": true,
			"department": "HR",
		}})
		with data.resources as mock_resources
		with data.roles as mock_roles
		with time.now_ns as saturday
}
