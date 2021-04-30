const express = require("express");
const controller = require("./controller");
const auth = require("../../../middleware/auth");
const userRouter = express.Router();

userRouter
  .post("/signup", controller.signupUser)
  .post("/login", controller.loginUser)
  .get("/info", auth, controller.getInfoUser);

module.exports = userRouter;
