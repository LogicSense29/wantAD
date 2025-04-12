import express from "express";
import {
  login,
  signup,
  forgetPassword,
  resetPassword,
} from "../controller/authController";

const route = express.Router();

route.post("/login", login);

route.post("/signup", signup);

route.post("/forget_password/", forgetPassword);

route.post("reset_password/:token", resetPassword);

export { route as authRoute };
