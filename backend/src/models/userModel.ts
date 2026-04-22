import { User, UserRole, UserStatus } from "../types/user";

interface CreateUserParams {
  username: string;
  password_hash: string;
  role: UserRole;
  first_name: string;
  last_name: string;
  email: string;
  department: string;
  mfa_enabled?: boolean;
  created_by?: string;
  status?: UserStatus;
}

/**
 * Crea un documento utente.
 */
export function createUser({
  username,
  password_hash,
  role,
  first_name,
  last_name,
  email,
  department,
  mfa_enabled = true,
  created_by,
  status = "active"
}: CreateUserParams): User {
  const now = new Date();

  return {
    username,
    password_hash,
    role,
    name: {
      first: first_name,
      last: last_name
    },
    email,
    department,
    status,
    mfa_enabled,
    created_by,
    created_at: now,
    updated_at: now
  };
}