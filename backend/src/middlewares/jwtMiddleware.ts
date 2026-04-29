import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export interface JwtPayload {
  user: string;
  role: string;
  department?: string;
}

/**
 * Verifica il token JWT presente nell'header Authorization.
 *
 * Il formato atteso è:
 * Authorization: Bearer <token>
 *
 * Se il token è valido, i claim principali vengono aggiunti agli header della request,
 * così il resto del sistema può continuare a usare x-user, x-role e x-department.
 */
export function requireJwt(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.header("authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({
      message: "Accesso negato: token JWT mancante"
    });
    return;
  }

  const token = authHeader.replace("Bearer ", "").trim();
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    res.status(500).json({
      message: "JWT_SECRET non configurato"
    });
    return;
  }

  try {
    const decoded = jwt.verify(token, secret) as JwtPayload;

    if (!decoded.user || !decoded.role) {
      res.status(401).json({
        message: "Token JWT non valido: claim user o role mancanti"
      });
      return;
    }

    req.headers["x-user"] = decoded.user;
    req.headers["x-role"] = decoded.role;

    if (decoded.department) {
      req.headers["x-department"] = decoded.department;
    }

    next();
  } catch (error) {
    res.status(401).json({
      message: "Accesso negato: token JWT non valido o scaduto"
    });
  }
}