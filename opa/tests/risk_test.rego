package authz.risk_test

import rego.v1

mock_resources := {"resources": [
	{
		"resource_name": "employee_records",
		"resource_sensitivity": "high",
		"allowed_roles": ["hr", "admin"],
		"allowed_actions": ["read"],
		"max_risk_score": 0.7,
		"conditions": {},
	},
	{
		"resource_name": "payroll_data",
		"resource_sensitivity": "critical",
		"allowed_roles": ["admin"],
		"allowed_actions": ["read"],
		"max_risk_score": 0.3,
		"conditions": {},
	},
]}

# ──────────────────────────────────────────────
# Test risk_threshold
# ──────────────────────────────────────────────

test_threshold_from_resource_policy if {
	authz.risk.risk_threshold == 0.7
		with input as {"resource_name": "employee_records", "risk_score": 0.25}
		with data.resources as mock_resources
}

test_threshold_critical_resource if {
	authz.risk.risk_threshold == 0.3
		with input as {"resource_name": "payroll_data", "risk_score": 0.1}
		with data.resources as mock_resources
}

# ──────────────────────────────────────────────
# Test risk_acceptable
# ──────────────────────────────────────────────

test_low_risk_acceptable if {
	authz.risk.risk_acceptable
		with input as {"resource_name": "employee_records", "risk_score": 0.25}
		with data.resources as mock_resources
}

test_risk_just_below_threshold_acceptable if {
	authz.risk.risk_acceptable
		with input as {"resource_name": "employee_records", "risk_score": 0.69}
		with data.resources as mock_resources
}

test_risk_at_threshold_not_acceptable if {
	not authz.risk.risk_acceptable
		with input as {"resource_name": "employee_records", "risk_score": 0.7}
		with data.resources as mock_resources
}

test_high_risk_not_acceptable if {
	not authz.risk.risk_acceptable
		with input as {"resource_name": "employee_records", "risk_score": 0.9}
		with data.resources as mock_resources
}

test_critical_resource_low_threshold if {
	not authz.risk.risk_acceptable
		with input as {"resource_name": "payroll_data", "risk_score": 0.35}
		with data.resources as mock_resources
}

# ──────────────────────────────────────────────
# Test risk_level
# ──────────────────────────────────────────────

test_risk_level_low if {
	authz.risk.risk_level == "low"
		with input as {"resource_name": "employee_records", "risk_score": 0.1}
		with data.resources as mock_resources
}

test_risk_level_medium if {
	authz.risk.risk_level == "medium"
		with input as {"resource_name": "employee_records", "risk_score": 0.45}
		with data.resources as mock_resources
}

test_risk_level_high if {
	authz.risk.risk_level == "high"
		with input as {"resource_name": "employee_records", "risk_score": 0.65}
		with data.resources as mock_resources
}

test_risk_level_critical if {
	authz.risk.risk_level == "critical"
		with input as {"resource_name": "employee_records", "risk_score": 0.85}
		with data.resources as mock_resources
}

# ──────────────────────────────────────────────
# Timestamp di riferimento (Europe/Rome, UTC+1 in gennaio 2025)
#   monday_10h  = 2025-01-13 10:00 Rome → within_working_hours
#   monday_23h  = 2025-01-13 23:00 Rome → fuori orario (notte)
#   monday_6h30 = 2025-01-13 06:30 Rome → fuori orario (troppo presto)
#   saturday    = 2025-01-18 10:00 Rome → weekend
#   monday_20h  = 2025-01-13 20:00 Rome → esattamente alle 20:00 (fuori)
# ──────────────────────────────────────────────

monday_10h  := 1736758800000000000
monday_23h  := 1736805600000000000
monday_6h30 := 1736746200000000000
saturday    := 1737190800000000000
monday_20h  := 1736794800000000000

# ──────────────────────────────────────────────
# Test within_working_hours
# ──────────────────────────────────────────────

test_within_hours_monday_morning if {
	authz.risk.within_working_hours
		with time.now_ns as monday_10h
}

test_outside_hours_monday_night if {
	not authz.risk.within_working_hours
		with time.now_ns as monday_23h
}

test_outside_hours_monday_too_early if {
	not authz.risk.within_working_hours
		with time.now_ns as monday_6h30
}

test_outside_hours_saturday if {
	not authz.risk.within_working_hours
		with time.now_ns as saturday
}

test_outside_hours_exactly_20h if {
	not authz.risk.within_working_hours
		with time.now_ns as monday_20h
}

# ──────────────────────────────────────────────
# Test access_time_valid — ruolo hr (time-restricted)
# ──────────────────────────────────────────────

test_hr_valid_inside_hours if {
	authz.risk.access_time_valid
		with input as {"user": {"role": "hr"}, "resource_name": "employee_records", "risk_score": 0.1}
		with data.resources as mock_resources
		with time.now_ns as monday_10h
}

test_hr_denied_outside_hours if {
	not authz.risk.access_time_valid
		with input as {"user": {"role": "hr"}, "resource_name": "employee_records", "risk_score": 0.1}
		with data.resources as mock_resources
		with time.now_ns as monday_23h
}

test_hr_denied_on_weekend if {
	not authz.risk.access_time_valid
		with input as {"user": {"role": "hr"}, "resource_name": "employee_records", "risk_score": 0.1}
		with data.resources as mock_resources
		with time.now_ns as saturday
}

# ──────────────────────────────────────────────
# Test access_time_valid — ruolo employee (time-restricted)
# ──────────────────────────────────────────────

test_employee_valid_inside_hours if {
	authz.risk.access_time_valid
		with input as {"user": {"role": "employee"}, "resource_name": "employee_records", "risk_score": 0.1}
		with data.resources as mock_resources
		with time.now_ns as monday_10h
}

test_employee_denied_outside_hours if {
	not authz.risk.access_time_valid
		with input as {"user": {"role": "employee"}, "resource_name": "employee_records", "risk_score": 0.1}
		with data.resources as mock_resources
		with time.now_ns as monday_6h30
}

# ──────────────────────────────────────────────
# Test access_time_valid — ruolo admin (NON time-restricted)
# ──────────────────────────────────────────────

test_admin_valid_at_night if {
	authz.risk.access_time_valid
		with input as {"user": {"role": "admin"}, "resource_name": "payroll_data", "risk_score": 0.1}
		with data.resources as mock_resources
		with time.now_ns as monday_23h
}

test_admin_valid_on_weekend if {
	authz.risk.access_time_valid
		with input as {"user": {"role": "admin"}, "resource_name": "payroll_data", "risk_score": 0.1}
		with data.resources as mock_resources
		with time.now_ns as saturday
}
