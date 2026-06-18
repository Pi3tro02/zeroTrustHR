import { Router } from "express";
import jwt, { SignOptions } from "jsonwebtoken";
import { ObjectId } from "mongodb";
import { getDb } from "../config/db";
import { requireJwt } from "../middlewares/jwtMiddleware";
import { authenticateUser } from "../services/authService";
import { User } from "../types/user";

const router = Router();

type UserDocument = User & { _id: ObjectId };

interface LoginBody {
  username?: string;
  password?: string;
}

function sanitizeUser(user: UserDocument) {
  return {
    id: user._id.toString(),
    username: user.username,
    role: user.role,
    department: user.department,
    name: user.name,
    email: user.email,
    status: user.status,
    mfa_enabled: user.mfa_enabled
  };
}

router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body as LoginBody;

    if (!username || !password) {
      return res.status(400).json({
        message: "Campi obbligatori mancanti",
        required_fields: ["username", "password"]
      });
    }

    const user = await authenticateUser({
      username,
      password,
      source_ip: req.ip,
      user_agent: req.header("user-agent")
    });

    if (!user) {
      return res.status(401).json({
        message: "Credenziali non valide"
      });
    }

    const secret = process.env.JWT_SECRET;

    if (!secret) {
      return res.status(500).json({
        message: "JWT_SECRET non configurato"
      });
    }

    const tokenTtl = process.env.JWT_EXPIRES_IN ?? "1h";
    const signOptions: SignOptions = {
      expiresIn: tokenTtl as SignOptions["expiresIn"]
    };

    const token = jwt.sign(
      {
        user: user._id.toString(),
        username: user.username,
        role: user.role,
        department: user.department
      },
      secret,
      signOptions
    );

    return res.status(200).json({
      message: "Login completato",
      token,
      user: sanitizeUser(user)
    });
  } catch (error) {
    console.error("Errore nella route /api/auth/login:", error);

    return res.status(500).json({
      message: "Errore interno durante il login"
    });
  }
});

router.get("/me", requireJwt, async (req, res) => {
  try {
    const userId = req.header("x-user");

    if (!userId || !ObjectId.isValid(userId)) {
      return res.status(401).json({
        message: "Token JWT non valido: user id non valido"
      });
    }

    const db = getDb();
    const user = await db.collection<UserDocument>("users").findOne({
      _id: new ObjectId(userId)
    });

    if (!user) {
      return res.status(404).json({
        message: "Utente non trovato"
      });
    }

    return res.status(200).json({
      user: sanitizeUser(user)
    });
  } catch (error) {
    console.error("Errore nella route /api/auth/me:", error);

    return res.status(500).json({
      message: "Errore interno durante il recupero dell'utente"
    });
  }
});

export default router;
