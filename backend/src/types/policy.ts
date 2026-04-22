import { UserRole } from "./user";

export type PolicyEffect = "allow" | "deny";
export type PolicyStatus = "active" | "inactive";
export type ResourceSensitivity = "low" | "medium" | "high" | "critical";
export type PolicyAction = "read" | "write" | "update" | "delete";

export interface PolicyConditions {
  mfa_required?: boolean;
  trusted_device_required?: boolean;
  allowed_network_zones?: string[];
  require_known_device?: boolean;
}

/**
 * Definisce:
 * - quale risorsa viene protetta
 * - quali ruoli e azioni sono consentiti
 * - fino a quale livello di rischio è permesso l'accesso
 * - eventuali condizioni aggiuntive come MFA, device trusted e rete ammessa
 */
export interface Policy {
  policy_name: string;
  resource_name: string;
  resource_sensitivity: ResourceSensitivity;
  allowed_roles: UserRole[];
  allowed_actions: PolicyAction[];
  max_risk_score: number;
  conditions: PolicyConditions;
  effect: PolicyEffect;
  status: PolicyStatus;
  created_by?: string;
  created_at: Date;
  updated_at: Date;
}