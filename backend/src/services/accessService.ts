import { ObjectId } from "mongodb";
import { getDb } from "../config/db";
import { logEvent } from "./logService";
import { User } from "../types/user";
import { Device } from "../types/device";
import {
  AccessAction,
  AccessDecision,
  AccessRequest,
  NetworkZone
} from "../types/accessRequest";
import { Policy } from "../types/policy";

type UserDocument = User & { _id: ObjectId };
type DeviceDocument = Device & { _id: ObjectId };

interface EvaluateAccessParams {
  user: UserDocument;
  device: DeviceDocument;
  resource_name: string;
  action: AccessAction;
  source_ip?: string;
  network_zone?: NetworkZone;
  mfa_verified?: boolean;
}

interface RiskEvaluationResult {
  score: number;
  reasons: string[];
  known_device: boolean;
  trusted_device: boolean;
  network_zone: NetworkZone;
  mfa_verified: boolean;
}

/**
 * Calcola un punteggio di rischio iniziale basato su dispositivo, rete e MFA.
 *
 * Questa è una prima versione locale nel backend:
 * più avanti il rischio potrà arrivare da Splunk / OPA.
 */
function evaluateRisk({
  device,
  network_zone = "unknown",
  mfa_verified = false
}: {
  device: DeviceDocument;
  network_zone?: NetworkZone;
  mfa_verified?: boolean;
}): RiskEvaluationResult {
  let score = 0;
  const reasons: string[] = [];

  const known_device = true;
  const trusted_device = device.trusted;

  if (!trusted_device) {
    score += 25;
    reasons.push("untrusted_device");
  }

  if (device.status === "suspended") {
    score += 40;
    reasons.push("device_suspended");
  }

  if (device.status === "revoked") {
    score += 100;
    reasons.push("device_revoked");
  }

  if (network_zone === "external") {
    score += 20;
    reasons.push("external_network");
  }

  if (network_zone === "unknown") {
    score += 15;
    reasons.push("unknown_network");
  }

  if (network_zone === "internal") {
    score -= 5;
    reasons.push("internal_network");
  }

  if (network_zone === "vpn") {
    score -= 5;
    reasons.push("vpn_network");
  }

  if (!mfa_verified) {
    score += 20;
    reasons.push("mfa_not_verified");
  } else {
    score -= 10;
    reasons.push("mfa_verified");
  }

  if (score < 0) {
    score = 0;
  }

  return {
    score,
    reasons,
    known_device,
    trusted_device,
    network_zone,
    mfa_verified
  };
}

/**
 * Valuta una richiesta di accesso confrontando utente, device, policy e rischio.
 */
export async function evaluateAccess({
  user,
  device,
  resource_name,
  action,
  source_ip,
  network_zone = "unknown",
  mfa_verified = false
}: EvaluateAccessParams): Promise<{ decision: AccessDecision; reason: string }> {
  const db = getDb();

  const policy = await db.collection<Policy>("access_policies").findOne({
    resource_name,
    status: "active"
  });

  let decision: AccessDecision = "deny";
  let reason = "policy_not_found";

  const risk = evaluateRisk({
    device,
    network_zone,
    mfa_verified
  });

  if (!policy) {
    reason = "policy_not_found";
  } else if (user.status !== "active") {
    reason = "user_not_active";
  } else if (device.status !== "active") {
    reason = "device_not_active";
  } else if (!policy.allowed_roles.includes(user.role)) {
    reason = "role_not_allowed";
  } else if (!policy.allowed_actions.includes(action)) {
    reason = "action_not_allowed";
  } else if (
    policy.conditions.mfa_required &&
    !risk.mfa_verified
  ) {
    reason = "mfa_required";
  } else if (
    policy.conditions.trusted_device_required &&
    !risk.trusted_device
  ) {
    reason = "trusted_device_required";
  } else if (
    policy.conditions.allowed_network_zones &&
    !policy.conditions.allowed_network_zones.includes(risk.network_zone)
  ) {
    reason = "network_zone_not_allowed";
  } else if (
    policy.conditions.require_known_device &&
    !risk.known_device
  ) {
    reason = "known_device_required";
  } else if (risk.score > policy.max_risk_score) {
    reason = "risk_score_too_high";
  } else {
    decision = "allow";
    reason = "policy_satisfied";
  }

  const accessRequest: AccessRequest = {
    user_id: user._id.toString(),
    device_id: device._id.toString(),
    resource_name,
    action,
    request_time: new Date(),
    context: {
      ip_address: source_ip,
      network_zone: risk.network_zone,
      mfa_verified: risk.mfa_verified,
      trusted_device: risk.trusted_device,
      known_device: risk.known_device
    },
    risk: {
      score: risk.score,
      reasons: risk.reasons,
      known_device: risk.known_device,
      trusted_device: risk.trusted_device,
      network_zone: risk.network_zone,
      mfa_verified: risk.mfa_verified
    },
    decision,
    decision_reason: reason
  };

  await db.collection("access_requests").insertOne(accessRequest);

  await logEvent({
    user_id: user._id.toString(),
    username: user.username,
    role: user.role,
    action: "ACCESS_REQUEST",
    resource_type: "resource",
    resource_id: resource_name,
    outcome: decision === "allow" ? "success" : "failure",
    ip_address: source_ip,
    details: {
      requested_action: action,
      resource_name,
      decision_reason: reason,
      risk_score: risk.score,
      risk_reasons: risk.reasons,
      network_zone: risk.network_zone
    }
  });

  return { decision, reason };
}