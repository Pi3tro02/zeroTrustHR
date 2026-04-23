package authz.device

import rego.v1

# Recupera la policy della risorsa richiesta
resource_policy := policy if {
	some policy in data.resources.resources
	policy.resource_name == input.resource_name
}

# Verifica trusted: se la policy richiede dispositivo trusted, deve essere true
device_trusted if {
	resource_policy.conditions.trusted_device_required == true
	input.device.trusted == true
}

device_trusted if {
	resource_policy.conditions.trusted_device_required == false
}

device_trusted if {
	not resource_policy.conditions.trusted_device_required
}

# Verifica stato dispositivo: deve essere "active"
device_active if {
	input.device.status == "active"
}

# Verifica JA3 fingerprint: non deve essere nella lista bloccata
ja3_not_blocked if {
	count(data.roles.blocked_ja3_fingerprints) == 0
}

ja3_not_blocked if {
	count(data.roles.blocked_ja3_fingerprints) > 0
	not input.device.ja3_fingerprint in data.roles.blocked_ja3_fingerprints
}

ja3_not_blocked if {
	not input.device.ja3_fingerprint
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
	some cidr in data.roles.allowed_network_zones[zone_name]
	net.cidr_contains(cidr, input.device.ip_address)
}

# Verifica OS: deve essere tra quelli supportati (se configurati)
os_supported if {
	not data.roles.allowed_os_types
}

os_supported if {
	some allowed_os in data.roles.allowed_os_types
	startswith(lower(input.device.os), lower(allowed_os))
}
