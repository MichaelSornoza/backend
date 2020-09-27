const jwt = require("jsonwebtoken");

const SECRET = "esta&es%la&password2020";

const JWTIssuer = (payload, expiresIn) => {
  return jwt.sign(payload, SECRET, { expiresIn });
};

const JWTVerify = (token) => {
  return jwt.verify(token, SECRET);
};

module.exports = {
  JWTIssuer,
  JWTVerify,
};
