package authz.device_test

import rego.v1

mock_resources := {"resources": [
	{
		"resource_name": "employee_records",
		"resource_sensitivity": "high",
		"allowed_roles": ["hr", "admin"],
		"allowed_actions": ["read"],
		"max_risk_score": 0.7,
		"conditions": {
			"mfa_required": true,
			"trusted_device_required": true,
			"allowed_network_zones": ["internal"],
		},
	},
	{
		"resource_name": "company_policies",
		"resource_sensitivity": "low",
		"allowed_roles": ["customer", "employee", "hr", "admin"],
		"allowed_actions": ["read"],
		"max_risk_score": 0.9,
		"conditions": {"mfa_required": false, "trusted_device_required": false},
	},
]}

mock_roles := {
	"blocked_ja3_fingerprints": ["BLOCKED_FP_001", "BLOCKED_FP_002"],
	"allowed_network_zones": {
		"internal": ["10.0.0.0/8", "172.16.0.0/12"],
		"vpn": ["10.8.0.0/24"],
	},
}

# ──────────────────────────────────────────────
# Test device_trusted
# ──────────────────────────────────────────────

test_trusted_device_passes if {
	authz.device.device_trusted
		with input as {"device": {"trusted": true}, "resource_name": "employee_records"}
		with data.resources as mock_resources
}

test_untrusted_device_fails_when_required if {
	not authz.device.device_trusted
		with input as {"device": {"trusted": false}, "resource_name": "employee_records"}
		with data.resources as mock_resources
}

test_untrusted_device_passes_when_not_required if {
	authz.device.device_trusted
		with input as {"device": {"trusted": false}, "resource_name": "company_policies"}
		with data.resources as mock_resources
}

# ──────────────────────────────────────────────
# Test device_active
# ──────────────────────────────────────────────

test_active_device_passes if {
	authz.device.device_active
		with input as {"device": {"status": "active"}, "resource_name": "employee_records"}
		with data.resources as mock_resources
}

test_suspended_device_fails if {
	not authz.device.device_active
		with input as {"device": {"status": "suspended"}, "resource_name": "employee_records"}
		with data.resources as mock_resources
}

test_revoked_device_fails if {
	not authz.device.device_active
		with input as {"device": {"status": "revoked"}, "resource_name": "employee_records"}
		with data.resources as mock_resources
}

# ──────────────────────────────────────────────
# Test ja3_not_blocked
# ──────────────────────────────────────────────

test_clean_ja3_passes if {
	authz.device.ja3_not_blocked
		with input as {"device": {"ja3_fingerprint": "CLEAN_FP_XYZ"}, "resource_name": "employee_records"}
		with data.resources as mock_resources
		with data.roles as mock_roles
}

test_blocked_ja3_fails if {
	not authz.device.ja3_not_blocked
		with input as {"device": {"ja3_fingerprint": "BLOCKED_FP_001"}, "resource_name": "employee_records"}
		with data.resources as mock_resources
		with data.roles as mock_roles
}

test_null_ja3_passes if {
	authz.device.ja3_not_blocked
		with input as {"device": {}, "resource_name": "employee_records"}
		with data.resources as mock_resources
		with data.roles as mock_roles
}

# ──────────────────────────────────────────────
# Test ip_in_allowed_zone
# ──────────────────────────────────────────────

test_internal_ip_passes if {
	authz.device.ip_in_allowed_zone
		with input as {"device": {"ip_address": "10.0.1.42"}, "resource_name": "employee_records"}
		with data.resources as mock_resources
		with data.roles as mock_roles
}

test_external_ip_fails if {
	not authz.device.ip_in_allowed_zone
		with input as {"device": {"ip_address": "8.8.8.8"}, "resource_name": "employee_records"}
		with data.resources as mock_resources
		with data.roles as mock_roles
}

test_no_zone_restriction_passes if {
	authz.device.ip_in_allowed_zone
		with input as {"device": {"ip_address": "8.8.8.8"}, "resource_name": "company_policies"}
		with data.resources as mock_resources
		with data.roles as mock_roles
}
