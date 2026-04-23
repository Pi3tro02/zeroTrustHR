package authz.user

import rego.v1
import data.utils.helpers as h

# Recupera la policy della risorsa richiesta da data/resources.json.
# La risorsa viene letta dagli header HTTP inviati tramite Envoy.
resource_policy := policy if {
        some policy in data.resources
        policy.resource_name == h.resource_name
}

# Verifica che il ruolo dell'utente sia tra quelli autorizzati per la risorsa
role_allowed if {
        resource_policy
        some role in resource_policy.allowed_roles
        role == h.role
}

# Verifica MFA: obbligatorio se la policy lo richiede.
# In questa demo il valore MFA viene letto dall'header x-mfa-enabled.
mfa_valid if {
        resource_policy.conditions.mfa_required == true
        h.mfa_enabled
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
        action == h.action
}

# Verifica dipartimento per risorse ad alta sensibilità
department_allowed if {
        resource_policy.resource_sensitivity in {"high", "critical"}
        h.department in data.sensitive_departments
}

department_allowed if {
        resource_policy.resource_sensitivity in {"low", "medium"}
}