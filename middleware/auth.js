const jwt = require("jsonwebtoken");

module.exports = function(req, res, next){
  const authHeader = req.headers.authorization;

  if(!authHeader || !authHeader.startsWith("Bearer ")){
    return res.status(401).json({ msg: "No token" });
  }

  const token = authHeader.slice(7); // 去掉 "Bearer "

  try{
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  }catch(err){
  if(err.name === "TokenExpiredError"){
    return res.status(401).json({ msg: "Token expired" });
  }
  return res.status(401).json({ msg: "Invalid token" });
}
