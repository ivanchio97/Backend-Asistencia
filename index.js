const express = require('express')
const db = require('./database.js')
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const cookieParser = require('cookie-parser')
const app = express()
const PORT = process.env.PORT ?? 4000;
const verificarToken = require('./middlewares/auth.js')
const cors = require('cors')
const rateLimit = require('express-rate-limit')

const authLimiter = rateLimit({
    windowMs: 15*60*1000,
    max: 10,
    message: "Demasiados intentos. Intenta de nuevo más tarde."
})

app.use(express.json())
app.use(cookieParser())

app.use(cors({
    origin: ['https://asistencia-icastillo.netlify.app'],
    credentials: true
}));

app.get("/api", verificarToken, async (req,res)=>{
    try{
        const [data] = await db.execute("SELECT * FROM asistencia")
        res.status(200).json(data)

    }catch(err){
        res.status(500).send("Error al obtener los datos")
    }
})
app.post("/api/crear", verificarToken, async (req,res)=>{
    try{
        const {grupo, nivel, alumnos, fecha} = req.body
        const data = await db.execute("INSERT INTO asistencia (grupo,nivel,alumnos,fecha) VALUES (?,?,?,?)", [grupo,nivel,alumnos,fecha])
        res.status(201).send("Alumnos registrados")
    }catch(err){
        res.status(401).send("Error al registrar")
    }
})


app.get("/api/protectedroute", verificarToken , (req,res)=>{
    res.json({mensaje: "Sesión válida", usuario: req.user })
})

app.post('/api/registrar', authLimiter, async (req, res) => {
    const {email, password} = req.body
    if(!email || !password){
        return res.status(401).send("Datos incompletos")
        
    }
    const salt = await bcrypt.genSalt(5)
    const encriptedPassword = await bcrypt.hash(password,salt);
    const data = await db.execute("INSERT INTO usuarios (correo, contrasena) VALUES (?, ?)",[email,encriptedPassword])
    res.status(201).send(`${email} agregado exitosamente`)
})

app.post('/api/login', authLimiter, async (req,res) => {
    const {email, password} = req.body
    if(!email || !password){
        return res.status(401).json({mensaje:"Datos incompletos"})
        
    }
   try{
    const [data] = await db.execute("SELECT * FROM usuarios WHERE correo = ? ",[email])
    if (data.length === 0 ) return res.status(401).json({mensaje:"Datos incorrectos"})

    //obtener correo y comparar contraseña
    const user = data[0]
    const comparation = await bcrypt.compare(password,user.contrasena)
    if(!comparation){
        return res.status(401).json({mensaje:"Datos incorrectos"})

    }
    
    //crear el token
    const token = jwt.sign(
        {id: user.id, email: user.correo},
        process.env.JWT_SECRET,
        {expiresIn: '5h'}
    )
    //enviar el token una cookie httpOnly
    res.cookie('token',token,{
        httpOnly:true,
        secure:true,
        sameSite:"None",
        maxAge: 1 * 60 * 60 *1000
    })
    res.send("login exitoso")


   } catch(err){
    res.status(401).send("Error al iniciar sesión")
    console.log(err)
   }
})

app.post('/api/logout',(req,res)=>{
    try{
        res.clearCookie('token',{
            httpOnly:true,
            secure:true,
            sameSite:"None"
        });
        res.status(200).send("Sesión cerrada")
    }catch(err){
        res.status(400).json({mensaje:"Error al iniciar sesión"})
    }
})

app.listen(PORT,()=>{
    console.log("Servidor escuchando en el puerto: ",PORT)
})