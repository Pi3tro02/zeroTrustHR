import { ObjectId } from "mongodb"
import { getDb } from "../config/db"
import { logEvent } from "./logService"
import { readSync } from "fs";
import { Log } from "web3";

interface AuthorizeRequestParams {
    user_id: string;
    resource_name: string;
    action: string;
    source_ip?: string;
    user_agent: string;

    // Dati provenienti da Envoy o mTLS
    mtls_verified: boolean;
    certificate_serial: string;
    certificate_subject?: string;

    ja3_fingerprint?: string;

    mfa_verified?: boolean;
}

interface AuthorizationDecision {
    allow: boolean;
    reason: string;
}

interface LogParams {
    user_id?: string;
    username?: string;
    role?: string;
    device_id?: string;
    resource_name: string;
    action: string;
    source_ip?: string;
    user_agent?: string;
    certificate_serial?: string;
    certificate_subject?: string;
    ja3_fingerprint?: string;
    has_tpm?: boolean;
    policy_name?: string;
    reason: string;
}

async function allowAndLog(params: LogParams): Promise<AuthorizationDecision> {
    const db = getDb();

    await db.collection("access_requests").insertOne({
        user_id: params.user_id ? new ObjectId(params.user_id) : null,
        device_id: params.device_id ? new ObjectId(params.device_id) : null,
        resource_name: params.resource_name,
        action: params.action,
        request_time: new Date(),
        context: {
            ip_address: params.source_ip,
            mtls_verified: true,
            certificate_serial: params.certificate_serial,
            certificate_subject: params.certificate_subject,
            ja3_fingerprint: params.ja3_fingerprint,
            has_tpm: params.has_tpm
        },
        decision: "allow",
        decision_reason: params.reason
    });

    await logEvent({
        user_id: params.user_id,
        username: params.username,
        role: params.role,
        action: "ACCESS_REQUEST",
        resource_type: "resource",
        resource_id: params.resource_name,
        outcome: "success",
        ip_address: params.source_ip,
        user_agent: params.user_agent,
        details: {
            device_id: params.device_id,
            certificate_serial: params.certificate_serial,
            certificate_subject: params.certificate_subject,
            ja3_fingerprint: params.ja3_fingerprint,
            has_tpm: params.has_tpm,
            policy_applied: params.policy_name,
            reason: params.reason
        }
    });

    return {
        allow: true,
        reason: params.reason
    };
}

async function denyAndLog(params: LogParams): Promise<AuthorizationDecision> {
    const db = getDb();

    await db.collection("access_requests").insertOne({
        user_id: params.user_id ? new ObjectId(params.user_id) : null,
        device_id: params.device_id ? new ObjectId(params.device_id) : null,
        resource_name: params.resource_name,
        action: params.action,
        request_time: new Date(),
        context: {
            ip_address: params.source_ip,
            mtls_verified: false,
            certificate_serial: params.certificate_serial,
            certificate_subject: params.certificate_subject,
            ja3_fingerprint: params.ja3_fingerprint,
            has_tpm: params.has_tpm
        },
        decision: "deny",
        decision_reason: params.reason
    });

    await logEvent({
        user_id: params.user_id,
        username: params.username,
        role: params.role,
        action: "ACCESS_REQUEST",
        resource_type: "resource",
        resource_id: params.resource_name,
        outcome: "failure",
        ip_address: params.source_ip,
        user_agent: params.user_agent,
        details: {
        device_id: params.device_id,
        certificate_serial: params.certificate_serial,
        certificate_subject: params.certificate_subject,
        ja3_fingerprint: params.ja3_fingerprint,
        has_tpm: params.has_tpm,
        reason: params.reason
        }
    });

    return {
        allow: false,
        reason: params.reason
    };
}

export async function authorizeRequest({
    user_id,
    resource_name,
    action,
    source_ip,
    user_agent,
    mtls_verified,
    certificate_serial,
    certificate_subject,
    ja3_fingerprint, 
    mfa_verified = false
}: AuthorizeRequestParams): Promise<AuthorizationDecision> {
    const db = getDb();

    const userObjectId = new ObjectId(user_id);

    const user = await db.collection("users").findOne({
        _id: userObjectId
    });

    if (!user) {
        return await denyAndLog({
            user_id,
            resource_name,
            action,
            source_ip,
            user_agent,
            reason: "user_not_found"
        });
    }

    if (user.status !== "active") {
        return await denyAndLog({
            user_id,
            username: user.username,
            role: user.role,
            resource_name,
            action,
            source_ip,
            user_agent,
            reason: "user_not_active"
        });
    }

    if (!mtls_verified) {
        return await denyAndLog({
            user_id,
            username: user.username,
            role: user.role,
            resource_name,
            action,
            source_ip,
            user_agent,
            reason: "mtls_not_verified"
        });
    }

    const certificate = await db.collection("certificates").findOne({
        serial_number: certificate_serial
    });

    if (!certificate) {
        return await denyAndLog({
            user_id,
            username: user.username,
            role: user.role,
            resource_name,
            action,
            source_ip,
            user_agent,
            certificate_serial,
            ja3_fingerprint,
            reason: "certificate_not_registered"
        });
    }

    if (certificate.revoked === true) {
        return await denyAndLog({
            user_id,
            username: user.username,
            role: user.role,
            resource_name,
            action,
            source_ip,
            user_agent,
            certificate_serial,
            ja3_fingerprint,
            reason: "certificate_revoked"
        });
    }

    const device = await db.collection("devices").findOne({
        _id: certificate.device_id
    });

    if (!device) {
        return await denyAndLog({
            user_id,
            username: user.username,
            role: user.role,
            resource_name, 
            action,
            source_ip,
            user_agent,
            certificate_serial,
            ja3_fingerprint,
            reason: "device_not_found"
        });
    }

    if (!device.user_id.equals(userObjectId)) {
        return await denyAndLog({
            user_id,
            username: user.username,
            role: user.role,
            device_id: device._id.toString(),
            resource_name,
            action,
            source_ip,
            user_agent,
            certificate_serial,
            ja3_fingerprint,
            reason: "device_not_owned_by_user"
        });
    }

    if (device.status !== "active" || device.trusted !== true) {
        return await denyAndLog({
          user_id,
          username: user.username,
          role: user.role,
          device_id: device._id.toString(),
          resource_name,
          action,
          source_ip,
          user_agent,
          certificate_serial,
          ja3_fingerprint,
          reason: "device_not_trusted"
        });
      }
    
    const policy = await db.collection("access_policies").findOne({
    resource_name,
    status: "active"
    });

    if (!policy) {
    return await denyAndLog({
        user_id,
        username: user.username,
        role: user.role,
        device_id: device._id.toString(),
        resource_name,
        action,
        source_ip,
        user_agent,
        certificate_serial,
        ja3_fingerprint,
        reason: "policy_not_found"
    });
    }

    if (!policy.allowed_roles.includes(user.role)) {
    return await denyAndLog({
        user_id,
        username: user.username,
        role: user.role,
        device_id: device._id.toString(),
        resource_name,
        action,
        source_ip,
        user_agent,
        certificate_serial,
        ja3_fingerprint,
        reason: "role_not_allowed"
    });
    }

    if (policy.conditions?.mfa_required === true && !mfa_verified) {
    return await denyAndLog({
        user_id,
        username: user.username,
        role: user.role,
        device_id: device._id.toString(),
        resource_name,
        action,
        source_ip,
        user_agent,
        certificate_serial,
        ja3_fingerprint,
        reason: "mfa_required"
    });
    }

    if (policy.conditions?.mtls_required === true && !mtls_verified) {
    return await denyAndLog({
        user_id,
        username: user.username,
        role: user.role,
        device_id: device._id.toString(),
        resource_name,
        action,
        source_ip,
        user_agent,
        certificate_serial,
        ja3_fingerprint,
        reason: "mtls_required"
    });
    }

    // Device con TPM o Secure Enclave
    if (device.has_tpm === true) {
        if (certificate.bound_to_hardware !== true) {
            return await denyAndLog({
                user_id,
                username: user.username,
                role: user.role,
                device_id: device._id.toString(),
                resource_name,
                action,
                source_ip,
                user_agent,
                certificate_serial,
                ja3_fingerprint,
                reason: "certificate_not_bound_to_hardware"
            });
        }

        return await allowAndLog({
            user_id,
            username: user.username,
            role: user.role,
            device_id: device._id.toString(),
            resource_name,
            action,
            source_ip,
            user_agent,
            certificate_serial,
            certificate_subject,
            ja3_fingerprint,
            has_tpm: true,
            policy_name: policy.policy_name,
            reason: "valid_mtls_tpm_bound_device"
        });
    }

    // Caso dispositivo senza TPM
    if (device.has_tpm === false) {
        if (policy.conditions?.require_ja3_if_no_tpm === true) {
            if (!ja3_fingerprint) {
                return await denyAndLog({
                    user_id,
                    username: user.username,
                    role: user.role,
                    device_id: device._id.toString(),
                    resource_name,
                    action,
                    source_ip,
                    user_agent,
                    certificate_serial,
                    ja3_fingerprint,
                    reason: "ja3_missing"
                });
            }

            if (device.ja3_fingerprint !== ja3_fingerprint) {
                return await denyAndLog({
                    user_id,
                    username: user.username,
                    role: user.role,
                    device_id: device._id.toString(),
                    resource_name,
                    action,
                    source_ip,
                    user_agent,
                    certificate_serial,
                    ja3_fingerprint,
                    reason: "ja3_mismatch"
                });
            }
        }

        return await allowAndLog({
            user_id,
            username: user.username,
            role: user.role,
            device_id: device._id.toString(),
            resource_name,
            action,
            source_ip,
            user_agent,
            certificate_serial,
            certificate_subject,
            ja3_fingerprint,
            has_tpm: false,
            policy_name: policy.policy_name,
            reason: "valid_mtls_non_tpm_matching_ja3"
        });
    }

    return await denyAndLog({
        user_id,
        username: user.username,
        role: user.role,
        device_id: device._id.toString(),
        resource_name,
        action,
        source_ip,
        user_agent,
        certificate_serial,
        ja3_fingerprint,
        reason: "invalid_device_tpm_state"
    });
}
