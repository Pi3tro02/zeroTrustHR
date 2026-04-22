import bcrypt from "bcrypt";

const SALT_ROUNDS = 12;

/**
 * Faccio l'hash bcrypt di una password in chiaro.
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

/**
 * Confronto una password in chiaro con il relativo hash bcrypt.
 */
export async function comparePassword(
  plainPassword: string,
  hashedPassword: string
): Promise<boolean> {
  return bcrypt.compare(plainPassword, hashedPassword);
}

// Rispetto a SHA256 l'hash cambia ogni volta per il salt che cambia per ogni funzione