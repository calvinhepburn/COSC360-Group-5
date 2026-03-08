import { asyncHandler } from "../middleware/asyncHandler.js";
import { getCurrentUser, loginUser, registerUser } from "../services/authService.js";
import { setAuthCookies } from "../utils/cookies.js";

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
    const userId = (req.user && req.user.id) || req.userId;
    const result = await getCurrentUser(userId);
    return res.status(200).json(result);
});
