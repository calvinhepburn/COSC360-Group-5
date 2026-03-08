import express from "express";
import { login, logout, me, refresh, register } from "../controllers/authController.js";
import { requireAuth } from "../middleware/requireAuth.js";

const authRouter = express.Router();

authRouter.post("/register", register);
authRouter.post("/login", login);
authRouter.post("/refresh", refresh);
authRouter.post("/logout", requireAuth, logout);
authRouter.get("/me", requireAuth, me);

export default authRouter;
