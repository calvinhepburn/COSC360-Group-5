import crypto from "crypto";
import jwt from "jsonwebtoken";
import { config } from "../config/env.js";
import { httpError } from "../utils/httpError.js";

export function signAccessToken(userId) {
    if (!userId) {
        throw httpError("INVALID_TOKEN_PAYLOAD", "Cannot sign access token without user id");
    }

    return jwt.sign(
        { sub: String(userId), type: "access" },
        config.JWT_ACCESS_SECRET,
        { expiresIn: config.JWT_ACCESS_EXPIRES_IN }
    );
}

export function signRefreshToken(userId) {
    if (!userId) {
        throw httpError("INVALID_TOKEN_PAYLOAD", "Cannot sign refresh token without user id");
    }

    return jwt.sign(
        { sub: String(userId), type: "refresh" },
        config.JWT_REFRESH_SECRET,
        { expiresIn: config.JWT_REFRESH_EXPIRES_IN }
    );
}

export function verifyAccessToken(token) {
    if (!token) {
        throw httpError("MISSING_ACCESS_TOKEN", "Access token is required");
    }

    try {
        const decoded = jwt.verify(token, config.JWT_ACCESS_SECRET);
        if (decoded.type !== "access") {
            throw httpError("INVALID_ACCESS_TOKEN", "Invalid access token type");
        }
        return decoded;
    } catch (error) {
        if (error.isAppError) throw error;
        throw httpError("INVALID_ACCESS_TOKEN", "Access token is invalid or expired");
    }
}

export function verifyRefreshToken(token) {
    if (!token) {
        throw httpError("MISSING_REFRESH_TOKEN", "Refresh token is required");
    }

    try {
        const decoded = jwt.verify(token, config.JWT_REFRESH_SECRET);
        if (decoded.type !== "refresh") {
            throw httpError("INVALID_REFRESH_TOKEN", "Invalid refresh token type");
        }
        return decoded;
    } catch (error) {
        if (error.isAppError) throw error;
        throw httpError("INVALID_REFRESH_TOKEN", "Refresh token is invalid or expired");
    }
}

export function hashRefreshToken(refreshToken) {
    if (!refreshToken) {
        throw httpError("MISSING_REFRESH_TOKEN", "Refresh token is required");
    }

    return crypto.createHash("sha256").update(refreshToken).digest("hex");
}
