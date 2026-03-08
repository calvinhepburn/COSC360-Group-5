import { asyncHandler } from "../middleware/asyncHandler.js";
import { getCurrentUser, loginUser, logoutSession, refreshSession, registerUser } from "../services/authService.js";
import { clearAuthCookies, setAuthCookies } from "../utils/cookies.js";

export const register = asyncHandler(async (req, res) => {
    const { user, accessToken, refreshToken } = await registerUser(req.body);
    setAuthCookies(res, accessToken, refreshToken);

    return res.status(201).json({ user });
});

export const login = asyncHandler(async (req, res) => {
    const { user, accessToken, refreshToken } = await loginUser(req.body);
    setAuthCookies(res, accessToken, refreshToken);

    return res.status(200).json({ user });
});

export const me = asyncHandler(async (req, res) => {
    const userId = req.auth && req.auth.userId;
    const result = await getCurrentUser(userId);
    return res.status(200).json(result);
});

export const refresh = asyncHandler(async (req, res) => {
    const refreshToken = req.cookies && req.cookies.refreshToken;
    const { user, accessToken, refreshToken: nextRefreshToken } = await refreshSession(refreshToken);
    setAuthCookies(res, accessToken, nextRefreshToken);
    return res.status(200).json({ user });
});

export const logout = asyncHandler(async (req, res) => {
    const userId = req.auth && req.auth.userId;
    try {
        await logoutSession(userId);
    } finally {
        clearAuthCookies(res);
    }
    return res.status(200).json({ success: true });
});
