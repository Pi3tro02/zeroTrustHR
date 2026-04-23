package authz.device

import rego.v1
import data.utils.helpers as h

# Recupera la policy della risorsa richiesta.
# La risorsa viene letta dagli header HTTP inviati tramite Envoy.
resource_policy := policy if {
        some policy in data.resources
        policy.resource_name == h.resource_name
}

# Verifica trusted: se la policy richiede dispositivo trusted, deve essere true.
# In questa demo il valore viene letto dall'header x-device-trusted.
device_trusted if {
        resource_policy.conditions.trusted_device_required == true
        h.device_trusted
}

device_trusted if {
        resource_policy.conditions.trusted_device_required == false
}

device_trusted if {
        not resource_policy.conditions.trusted_device_required
}

# Verifica stato dispositivo: deve essere "active"
device_active if {
        h.device_status == "active"
}

# Verifica JA3 fingerprint: non deve essere nella lista bloccata
ja3_not_blocked if {
        count(data.blocked_ja3_fingerprints) == 0
}

ja3_not_blocked if {
        count(data.blocked_ja3_fingerprints) > 0
        not h.ja3_fingerprint in data.blocked_ja3_fingerprints
}

ja3_not_blocked if {
        h.ja3_fingerprint == ""
}

# Verifica IP: deve essere in una zona di rete autorizzata (se configurata dalla policy)
ip_in_allowed_zone if {
        not resource_policy.conditions.allowed_network_zones
}

ip_in_allowed_zone if {
        count(resource_policy.conditions.allowed_network_zones) == 0
}

ip_in_allowed_zone if {
        some zone_name in resource_policy.conditions.allowed_network_zones
        some cidr in data.allowed_network_zones[zone_name]
        net.cidr_contains(cidr, h.device_ip)
}

# Verifica OS: deve essere tra quelli supportati (se configurati)
os_supported if {
        not data.allowed_os_types
}

os_supported if {
        some allowed_os in data.allowed_os_types
        startswith(lower(h.device_os), lower(allowed_os))
}