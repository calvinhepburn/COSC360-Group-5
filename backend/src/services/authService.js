import {
    clearRefreshTokenHash,
    createUser,
    findByEmail,
    findById,
    setRefreshTokenHash,
} from "../repositories/userRepository.js";
import {
    createSessionTokens,
    hashRefreshToken,
    verifyRefreshToken,
} from "./sessionService.js";
import { httpError } from "../utils/httpError.js";

function toPublicUser(user) {
    const userObject = user.toObject();
    delete userObject.password;
    delete userObject.refreshTokenHash;
    return userObject;
}

function normalizeEmail(email) {
    if (!email) return email;
    return email.trim().toLowerCase();
}

export async function registerUser(payload) {
    if (!payload) {
        throw httpError(400, "INVALID_REQUEST", "Request payload is required");
    }

    const email = normalizeEmail(payload && payload.email);
    if (!email || !payload.password || !payload.name) {
        throw httpError(400, "INVALID_REQUEST", "Name, email, and password are required");
    }

    const existingUser = await findByEmail(email);
    if (existingUser) {
        throw httpError(409, "EMAIL_ALREADY_IN_USE", "Email is already registered");
    }

    const user = await createUser({
        name: payload.name,
        email,
        password: payload.password,
        role: payload.role,
    });

    const { accessToken, refreshToken, refreshTokenHash } = createSessionTokens(user.id);
    await setRefreshTokenHash(user.id, refreshTokenHash);

    return {
        user: toPublicUser(user),
        accessToken,
        refreshToken,
    };
}

export async function loginUser(payload) {
    const email = normalizeEmail(payload && payload.email);
    const password = payload && payload.password;

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

    const { accessToken, refreshToken, refreshTokenHash } = createSessionTokens(user.id);
    await setRefreshTokenHash(user.id, refreshTokenHash);

    return {
        user: toPublicUser(user),
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

    const nextTokens = createSessionTokens(user.id);
    await setRefreshTokenHash(user.id, nextTokens.refreshTokenHash);

    return {
        user: toPublicUser(user),
        accessToken: nextTokens.accessToken,
        refreshToken: nextTokens.refreshToken,
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

    return { user: toPublicUser(user) };
}
