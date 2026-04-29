import { Request, Response, NextFunction } from "express";

export function requireMtls(req: Request, res: Response, next: NextFunction): void {
    const mtlsVerified = req.header("x-mtls-verified");
    const certSubject = req.header("x-mtls-subject");

    if (mtlsVerified !== "true") {
        res.status(401).json({
            message: "Accesso negato: certificato mTLS mancante o non valido"
        });
        return;
    }

    if (!certSubject) {
        res.status(401).json({
            message: "Accesso negato: subject del certificato mTLS mancante"
        });
        return;
    }

    next();
}
