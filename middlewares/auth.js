

const jwt = require("jsonwebtoken")

function verificarToken(req,res,next){
    const token = req.cookies.token
    if(!token){
        res.status(401).send("Acceso denegado")
        return;
    }
    try{
        const user = jwt.verify(token, process.env.JWT_SECRET)
        req.user = user;
        next();

    }catch(err){
        res.status(401).send("Error")
        return;
    }
}
module.exports = verificarToken;