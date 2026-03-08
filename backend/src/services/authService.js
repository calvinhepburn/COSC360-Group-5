import { clearRefreshTokenHash, createUser, findByEmail, findById, setRefreshTokenHash, } from "../repositories/userRepository.js";
import { hashRefreshToken, signAccessToken, signRefreshToken, verifyRefreshToken, } from "./sessionService.js";
import { httpError } from "../utils/httpError.js";

export async function registerUser(payload) {
    const safePayload = payload || {};
    const { name: rawName, email: rawEmail, password: rawPassword, role } = safePayload;
    const name = typeof rawName === "string" ? rawName.trim() : "";
    const email = typeof rawEmail === "string" ? rawEmail.trim().toLowerCase() : "";
    const password = typeof rawPassword === "string" ? rawPassword : "";

    if (!name || !email || !password) {
        throw httpError("INVALID_REQUEST", "Name, email, and password are required");
    }

    if (role === "admin") {
        throw httpError("ROLE_NOT_ALLOWED", "Admin role cannot be selected during registration");
    }

    const existingUser = await findByEmail(email);
    if (existingUser) {
        throw httpError("EMAIL_ALREADY_IN_USE", "Email is already registered");
    }

    const user = await createUser({ name, email, password, role, });

    const accessToken = signAccessToken(user.id);
    const refreshToken = signRefreshToken(user.id);
    const refreshTokenHash = hashRefreshToken(refreshToken);
    await setRefreshTokenHash(user.id, refreshTokenHash);

    return {
        user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
        },
        accessToken,
        refreshToken,
    };
}

export async function loginUser(payload) {
    const safePayload = payload || {};
    const { email: rawEmail, password: rawPassword } = safePayload;
    const email = typeof rawEmail === "string" ? rawEmail.trim().toLowerCase() : "";
    const password = typeof rawPassword === "string" ? rawPassword : "";

    if (!email || !password) {
        throw httpError("INVALID_REQUEST", "Email and password are required");
    }

    const user = await findByEmail(email, { includePassword: true });
    if (!user) {
        throw httpError("INVALID_CREDENTIALS", "Invalid email or password");
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
        throw httpError("INVALID_CREDENTIALS", "Invalid email or password");
    }

    const accessToken = signAccessToken(user.id);
    const refreshToken = signRefreshToken(user.id);
    const refreshTokenHash = hashRefreshToken(refreshToken);
    await setRefreshTokenHash(user.id, refreshTokenHash);

    return {
        user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
        },
        accessToken,
        refreshToken,
    };
}

export async function refreshSession(refreshToken) {
    const decoded = verifyRefreshToken(refreshToken);
    const user = await findById(decoded.sub, { includeRefreshTokenHash: true });

    if (!user || !user.refreshTokenHash) {
        throw httpError("INVALID_REFRESH_TOKEN", "Refresh token is invalid or expired");
    }

    const incomingHash = hashRefreshToken(refreshToken);
    if (user.refreshTokenHash !== incomingHash) {
        await clearRefreshTokenHash(user.id);
        throw httpError("INVALID_REFRESH_TOKEN", "Refresh token is invalid or expired");
    }

    const nextAccessToken = signAccessToken(user.id);
    const nextRefreshToken = signRefreshToken(user.id);
    const nextRefreshTokenHash = hashRefreshToken(nextRefreshToken);
    await setRefreshTokenHash(user.id, nextRefreshTokenHash);

    return {
        user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
        },
        accessToken: nextAccessToken,
        refreshToken: nextRefreshToken,
    };
}

export async function logoutSession(userId) {
    if (!userId) {
        throw httpError("MISSING_USER_ID", "User id is required");
    }

    await clearRefreshTokenHash(userId);
    return { success: true };
}

export async function getCurrentUser(userId) {
    if (!userId) {
        throw httpError("UNAUTHORIZED", "Not authenticated");
    }

    const user = await findById(userId);
    if (!user) {
        throw httpError("USER_NOT_FOUND", "User not found");
    }

    return {
        user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
        },
    };
}
