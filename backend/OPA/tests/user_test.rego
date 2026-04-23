package authz.user_test

import rego.v1

mock_resources := {"resources": [
	{
		"resource_name": "employee_records",
		"resource_sensitivity": "high",
		"allowed_roles": ["hr", "admin"],
		"allowed_actions": ["read", "write", "update"],
		"max_risk_score": 0.7,
		"conditions": {"mfa_required": true, "trusted_device_required": true},
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

mock_roles := {"sensitive_departments": ["HR", "Finance", "Legal"]}

# ──────────────────────────────────────────────
# Test role_allowed
# ──────────────────────────────────────────────

test_hr_role_allowed_for_employee_records if {
	authz.user.role_allowed
		with input as {"user": {"role": "hr"}, "resource_name": "employee_records", "action": "read"}
		with data.resources as mock_resources
}

test_admin_role_allowed_for_employee_records if {
	authz.user.role_allowed
		with input as {"user": {"role": "admin"}, "resource_name": "employee_records", "action": "read"}
		with data.resources as mock_resources
}

test_employee_role_denied_for_employee_records if {
	not authz.user.role_allowed
		with input as {"user": {"role": "employee"}, "resource_name": "employee_records", "action": "read"}
		with data.resources as mock_resources
}

test_customer_role_allowed_for_company_policies if {
	authz.user.role_allowed
		with input as {"user": {"role": "customer"}, "resource_name": "company_policies", "action": "read"}
		with data.resources as mock_resources
}

# ──────────────────────────────────────────────
# Test mfa_valid
# ──────────────────────────────────────────────

test_mfa_valid_when_enabled_and_required if {
	authz.user.mfa_valid
		with input as {"user": {"mfa_enabled": true}, "resource_name": "employee_records", "action": "read"}
		with data.resources as mock_resources
}

test_mfa_invalid_when_disabled_and_required if {
	not authz.user.mfa_valid
		with input as {"user": {"mfa_enabled": false}, "resource_name": "employee_records", "action": "read"}
		with data.resources as mock_resources
}

test_mfa_valid_when_not_required if {
	authz.user.mfa_valid
		with input as {"user": {"mfa_enabled": false}, "resource_name": "company_policies", "action": "read"}
		with data.resources as mock_resources
}

# ──────────────────────────────────────────────
# Test action_allowed
# ──────────────────────────────────────────────

test_read_action_allowed if {
	authz.user.action_allowed
		with input as {"user": {"role": "hr"}, "resource_name": "employee_records", "action": "read"}
		with data.resources as mock_resources
}

test_delete_action_denied_for_employee_records if {
	not authz.user.action_allowed
		with input as {"user": {"role": "hr"}, "resource_name": "employee_records", "action": "delete"}
		with data.resources as mock_resources
}

# ──────────────────────────────────────────────
# Test department_allowed
# ──────────────────────────────────────────────

test_hr_dept_allowed_for_high_sensitivity if {
	authz.user.department_allowed
		with input as {"user": {"department": "HR"}, "resource_name": "employee_records"}
		with data.resources as mock_resources
		with data.roles as mock_roles
}

test_sales_dept_denied_for_high_sensitivity if {
	not authz.user.department_allowed
		with input as {"user": {"department": "Sales"}, "resource_name": "employee_records"}
		with data.resources as mock_resources
		with data.roles as mock_roles
}

test_any_dept_allowed_for_low_sensitivity if {
	authz.user.department_allowed
		with input as {"user": {"department": "Sales"}, "resource_name": "company_policies"}
		with data.resources as mock_resources
		with data.roles as mock_roles
}
