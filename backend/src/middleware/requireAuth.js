import { verifyAccessToken } from "../services/sessionService.js";

export function requireAuth(req, res, next) {
    const cookieToken = req.cookies && req.cookies.accessToken;
    const token = cookieToken;

    const decoded = verifyAccessToken(token);
    req.auth = { userId: decoded.sub };
    next();
}
