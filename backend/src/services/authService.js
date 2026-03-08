import { clearRefreshTokenHash, createUser, findByEmail, findById, setRefreshTokenHash, } from "../repositories/userRepository.js";
import { hashRefreshToken, signAccessToken, signRefreshToken, verifyRefreshToken, } from "./sessionService.js";
import { httpError } from "../utils/httpError.js";

export async function registerUser(payload) {
    let { name, email, password, role } = payload;
    name = name.trim();
    email = email.trim().toLowerCase();

    if (!name || !email || !password) {
        throw httpError(400, "INVALID_REQUEST", "Name, email, and password are required");
    }

    if (role === "admin") {
        throw httpError(403, "ROLE_NOT_ALLOWED", "Admin role cannot be selected during registration");
    }

    const existingUser = await findByEmail(email);
    if (existingUser) {
        throw httpError(409, "EMAIL_ALREADY_IN_USE", "Email is already registered");
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
    let { email, password } = payload;
    email = email.trim().toLowerCase();

    if (!email || !password) {
        throw httpError(400, "INVALID_CREDENTIALS", "Email and password are required");
    }

    const user = await findByEmail(email, { includePassword: true });
    if (!user) {
        throw httpError(401, "INVALID_CREDENTIALS", "Invalid email or password");
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
        throw httpError(401, "INVALID_CREDENTIALS", "Invalid email or password");
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
        throw httpError(401, "INVALID_REFRESH_TOKEN", "Refresh token is invalid or expired");
    }

    const incomingHash = hashRefreshToken(refreshToken);
    if (user.refreshTokenHash !== incomingHash) {
        await clearRefreshTokenHash(user.id);
        throw httpError(401, "INVALID_REFRESH_TOKEN", "Refresh token is invalid or expired");
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
        throw httpError(400, "MISSING_USER_ID", "User id is required");
    }

    await clearRefreshTokenHash(userId);
    return { success: true };
}

export async function getCurrentUser(userId) {
    if (!userId) {
        throw httpError(401, "UNAUTHORIZED", "Not authenticated");
    }

    const user = await findById(userId);
    if (!user) {
        throw httpError(404, "USER_NOT_FOUND", "User not found");
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
