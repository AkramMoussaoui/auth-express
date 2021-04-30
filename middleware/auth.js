const jwt = require("jsonwebtoken");

const authUser = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      const error = new Error("access denied");
      return next(error);
    }
    const data = jwt.verify(token, process.env.PRIVATE_KEY);
    req.data = data;
    next();
  } catch (error) {
    next(error);
  }
};

module.exports = authUser;
