import {
  Policy,
  PolicyAction,
  PolicyEffect,
  PolicyStatus,
  ResourceSensitivity
} from "../types/policy";
import { UserRole } from "../types/user";

interface CreatePolicyParams {
  policy_name: string;
  resource_name: string;
  resource_sensitivity: ResourceSensitivity;
  allowed_roles: UserRole[];
  allowed_actions: PolicyAction[];
  max_risk_score: number;
  conditions?: {
    mfa_required?: boolean;
    trusted_device_required?: boolean;
    allowed_network_zones?: string[];
    require_known_device?: boolean;
  };
  effect?: PolicyEffect;
  status?: PolicyStatus;
  created_by?: string;
}

/**
 * Crea un documento policy.
 *
 * Logica:
 * - la policy definisce chi può accedere a una risorsa
 * - quali azioni può fare
 * - entro quale soglia di rischio l’accesso è consentito
 * - con eventuali condizioni aggiuntive
 */
export function createPolicy({
  policy_name,
  resource_name,
  resource_sensitivity,
  allowed_roles,
  allowed_actions,
  max_risk_score,
  conditions = {},
  effect = "allow",
  status = "active",
  created_by
}: CreatePolicyParams): Policy {
  const now = new Date();

  return {
    policy_name,
    resource_name,
    resource_sensitivity,
    allowed_roles,
    allowed_actions,
    max_risk_score,
    conditions,
    effect,
    status,
    created_by,
    created_at: now,
    updated_at: now
  };
}