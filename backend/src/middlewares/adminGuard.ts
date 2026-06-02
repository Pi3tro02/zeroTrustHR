import { Request, Response, NextFunction } from "express";

export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
    const role = req.header("x-role");

    if (role !== "admin") {
        res.status(403).json({
            message: "Operazione consentita solo ad admin"
        });
        return;
    }

    next();
}
