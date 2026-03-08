import { verifyAccessToken } from "../services/sessionService.js";

export function requireAuth(req, res, next) {
    const cookieToken = req.cookies && req.cookies.accessToken;
    const decoded = verifyAccessToken(cookieToken);
    req.auth = { userId: decoded.sub };
    next();
}
