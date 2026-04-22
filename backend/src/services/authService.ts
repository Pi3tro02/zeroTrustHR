import { ObjectId } from "mongodb";
import { getDb } from "../config/db";
import { createUser } from "../models/userModel";
import { User, UserRole } from "../types/user";
import { hashPassword, comparePassword } from "../utils/hash";
import { logEvent } from "./logService";

interface RegisterUserParams {
  username: string;
  password: string;
  role: UserRole;
  first_name: string;
  last_name: string;
  email: string;
  department: string;
  mfa_enabled?: boolean;
  created_by?: string;
}

interface AuthenticateUserParams {
  username: string;
  password: string;
  source_ip?: string;
  user_agent?: string;
}

type UserDocument = User & { _id: ObjectId };

/**
 * Registra un nuovo utente nel database.
 */
export async function registerUser({
  username,
  password,
  role,
  first_name,
  last_name,
  email,
  department,
  mfa_enabled = true,
  created_by
}: RegisterUserParams): Promise<ObjectId> {
  const db = getDb();
  const password_hash = await hashPassword(password);

  const userDoc = createUser({
    username,
    password_hash,
    role,
    first_name,
    last_name,
    email,
    department,
    mfa_enabled,
    created_by
  });

  const result = await db.collection("users").insertOne(userDoc);

  await logEvent({
    user_id: result.insertedId.toString(),
    username,
    role,
    action: "REGISTER_USER",
    resource_type: "user",
    resource_id: result.insertedId.toString(),
    outcome: "success",
    details: {
      created_by: created_by ?? "system"
    }
  });

  return result.insertedId;
}

/**
 * Autentica un utente tramite username e password.
 */
export async function authenticateUser({
  username,
  password,
  source_ip,
  user_agent
}: AuthenticateUserParams): Promise<UserDocument | null> {
  const db = getDb();

  const user = await db.collection<UserDocument>("users").findOne({ username });

  if (!user) {
    await logEvent({
      username,
      action: "LOGIN",
      resource_type: "user",
      outcome: "failure",
      ip_address: source_ip,
      user_agent,
      details: {
        reason: "user_not_found"
      }
    });

    return null;
  }

  const passwordMatches = await comparePassword(password, user.password_hash);

  if (!passwordMatches) {
    await logEvent({
      user_id: user._id.toString(),
      username: user.username,
      role: user.role,
      action: "LOGIN",
      resource_type: "user",
      resource_id: user._id.toString(),
      outcome: "failure",
      ip_address: source_ip,
      user_agent,
      details: {
        reason: "wrong_password"
      }
    });

    return null;
  }

  if (user.status !== "active") {
    await logEvent({
      user_id: user._id.toString(),
      username: user.username,
      role: user.role,
      action: "LOGIN",
      resource_type: "user",
      resource_id: user._id.toString(),
      outcome: "failure",
      ip_address: source_ip,
      user_agent,
      details: {
        reason: "user_not_active",
        status: user.status
      }
    });

    return null;
  }

  await logEvent({
    user_id: user._id.toString(),
    username: user.username,
    role: user.role,
    action: "LOGIN",
    resource_type: "user",
    resource_id: user._id.toString(),
    outcome: "success",
    ip_address: source_ip,
    user_agent,
    details: {
      mfa_enabled: user.mfa_enabled
    }
  });

  return user;
}