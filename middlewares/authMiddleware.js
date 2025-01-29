const jwt = require("jsonwebtoken");
const Token = require("../models/tokenModel");

const authMiddleware = async (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  
  if (!token) return res.status(401).json({ message: "Access Denied" });

  try {
    const blacklistedToken = await Token.findOne({ token });
    if (blacklistedToken) return res.status(401).json({ message: "Token is revoked" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid Token" });
  }
};

module.exports = authMiddleware;
