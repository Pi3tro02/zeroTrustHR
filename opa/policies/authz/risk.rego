package authz.risk

import rego.v1
import data.utils.helpers as h

# ──────────────────────────────────────────────
# Soglia di rischio
# ──────────────────────────────────────────────

risk_threshold := threshold if {
    some policy in data.resources
    policy.resource_name == h.resource_name
    threshold := policy.max_risk_score
}

risk_threshold := 0.7 if {
    not _resource_policy_exists
}

_resource_policy_exists if {
    some policy in data.resources
    policy.resource_name == h.resource_name
}

risk_acceptable if {
    h.risk_score < risk_threshold
}

# ──────────────────────────────────────────────
# Blocklist BARAC (aggiornata da Splunk via backend)
#
# data.authz.blocked_users viene scritto dal backend
# quando Splunk rileva profit < 0 (webhook BARAC).
# OPA legge la lista ad ogni valutazione → Decision Continuity.
# ──────────────────────────────────────────────

# Utente bloccato dalla blocklist BARAC
user_not_blocked if {
    not h.username in data.authz.blocked_users
}

# Se blocked_users non è definito, considera tutti sbloccati (fail-open controllato)
user_not_blocked if {
    not data.authz.blocked_users
}

# ──────────────────────────────────────────────
# Classificazione livello di rischio
# ──────────────────────────────────────────────

risk_level := "low" if {
    h.risk_score < 0.3
}

risk_level := "medium" if {
    h.risk_score >= 0.3
    h.risk_score < 0.6
}

risk_level := "high" if {
    h.risk_score >= 0.6
    h.risk_score < risk_threshold
}

risk_level := "critical" if {
    h.risk_score >= risk_threshold
}

# ──────────────────────────────────────────────
# Verifica orario lavorativo (employee e hr)
# ──────────────────────────────────────────────

_time_restricted_roles := {"employee", "hr"}

access_time_valid if {
    not h.role in _time_restricted_roles
}

access_time_valid if {
    h.role in _time_restricted_roles
    within_working_hours
}

within_working_hours if {
    tz := "Europe/Rome"
    now := time.now_ns()
    [hour, _, _] := time.clock([now, tz])
    hour >= 7
    hour < 20
    time.weekday([now, tz]) in {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
}
