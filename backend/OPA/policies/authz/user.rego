package authz.user

import rego.v1

# Recupera la policy della risorsa richiesta da data/resources.json
resource_policy := policy if {
	some policy in data.resources.resources
	policy.resource_name == input.resource_name
}

# Verifica che il ruolo dell'utente sia tra quelli autorizzati per la risorsa
role_allowed if {
	resource_policy
	some role in resource_policy.allowed_roles
	role == input.user.role
}

# Verifica MFA: obbligatorio se la policy lo richiede
mfa_valid if {
	resource_policy.conditions.mfa_required == true
	input.user.mfa_enabled == true
}

mfa_valid if {
	resource_policy.conditions.mfa_required == false
}

mfa_valid if {
	not resource_policy.conditions.mfa_required
}

# Verifica che l'azione richiesta sia permessa dalla policy
action_allowed if {
	resource_policy
	some action in resource_policy.allowed_actions
	action == input.action
}

# Verifica dipartimento per risorse ad alta sensibilità
department_allowed if {
	resource_policy.resource_sensitivity in {"high", "critical"}
	input.user.department in data.roles.sensitive_departments
}

department_allowed if {
	resource_policy.resource_sensitivity in {"low", "medium"}
}
