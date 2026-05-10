package authz.risk

import rego.v1
import data.utils.helpers as h

# Endpoint interno della componente rischio
risk_service_url := "http://backend:3000/api/risk/evaluate"

# ──────────────────────────────────────────────
# Conversione booleani per body JSON
# ──────────────────────────────────────────────

device_trusted_value := true if {
    h.device_trusted
}

device_trusted_value := false if {
    not h.device_trusted
}

mfa_enabled_value := true if {
    h.mfa_enabled
}

mfa_enabled_value := false if {
    not h.mfa_enabled
}

# ──────────────────────────────────────────────
# Chiamata live al risk endpoint
# ──────────────────────────────────────────────
risk_http_status := code if {
    code := risk_api_response.status_code
}

risk_http_status := 0 if {
    not risk_api_response.status_code
}

risk_http_body := body if {
    body := risk_api_response.body
}

risk_http_body := {} if {
    not risk_api_response.body
}

risk_http_error := err if {
    err := object.get(risk_api_response, "error", "")
}

risk_http_error := "" if {
    not object.get(risk_api_response, "error", "")
}

risk_request_body := {
    "user": h.username,
    "role": h.role,
    "department": h.department,
    "device": {
        "trusted": device_trusted_value,
        "status": h.device_status,
        "os": h.device_os,
        "ip": h.device_ip,
        "ja3": h.ja3_fingerprint
    },
    "network": {
        "ip": h.device_ip,
        "zone": "internal"
    },
    "request": {
        "resource": h.resource_name,
        "action": h.action
    }
}

risk_api_response := resp if {
    resp := http.send({
        "method": "post",
        "url": risk_service_url,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": risk_request_body,
        "timeout": "5s",
        "cache": false,
        "raise_error": false
    })
}

risk_service_ok if {
    risk_api_response.status_code == 200
    object.get(risk_api_response.body, "risk_score", null) != null
}

# ──────────────────────────────────────────────
# Risk score: preferisci Splunk live, fallback a header
# ──────────────────────────────────────────────

risk_score := score if {
    risk_service_ok
    raw := object.get(risk_api_response.body, "risk_score", 1.0)
    score := to_number(sprintf("%v", [raw]))
}

risk_score := h.risk_score if {
    not risk_service_ok
}

risk_source := "splunk_live" if {
    risk_service_ok
}

risk_source := "header_fallback" if {
    not risk_service_ok
}

risk_severity := sev if {
    risk_service_ok
    sev := object.get(risk_api_response.body, "severity", "unknown")
}

risk_severity := "unknown" if {
    not risk_service_ok
}

risk_profit := profit if {
    risk_service_ok
    raw := object.get(risk_api_response.body, "profit", -1)
    profit := to_number(sprintf("%v", [raw]))
}

risk_profit := -1 if {
    not risk_service_ok
}

# ──────────────────────────────────────────────
# Soglia di rischio per risorsa
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
    risk_score < risk_threshold
}

# ──────────────────────────────────────────────
# Blocklist BARAC (aggiornata da Splunk via backend)
# ──────────────────────────────────────────────

user_not_blocked if {
    not h.username in data.authz.blocked_users
}

user_not_blocked if {
    not data.authz.blocked_users
}

# ──────────────────────────────────────────────
# Classificazione rischio
# ──────────────────────────────────────────────

risk_level := "low" if {
    risk_score < 0.3
}

risk_level := "medium" if {
    risk_score >= 0.3
    risk_score < 0.6
}

risk_level := "high" if {
    risk_score >= 0.6
    risk_score < risk_threshold
}

risk_level := "critical" if {
    risk_score >= risk_threshold
}

# ──────────────────────────────────────────────
# Fascia oraria lavorativa
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