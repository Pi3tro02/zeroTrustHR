export type UserRole = "customer" | "employee" | "hr" | "admin";
export type UserStatus = "active" | "suspended" | "terminated";

export interface User {
  username: string;
  password_hash: string;
  role: UserRole;
  name: {
    first: string;
    last: string;
  };
  email: string;
  department: string;
  status: UserStatus;
  mfa_enabled: boolean;
  created_by?: string;
  created_at: Date;
  updated_at: Date;
}