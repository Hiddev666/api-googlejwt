import express from "express"
import session from "express-session"
import dotenv from "dotenv"
import jwt from "jsonwebtoken"
import cookieParser from "cookie-parser"
import cors from "cors"
import passport from "./auth/google.mjs"

dotenv.config()

const app = express()
const PORT = 8000

app.use(cookieParser())
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
}))

app.use(passport.initialize())

// ==== AUTH ROUTES ====

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
)

app.get("/auth/google/callback",
    passport.authenticate("google", { session: false }),
    (req, res) => {
        const user = req.user
        const payload = {
            id: user.id,
            displayName: user.displayName,
            email: user.emails[0].value,
            profile_picture: user.photos[0].value
        }

        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1h" })

        res.cookie("token", token, {
            httpOnly: false,
            secure: true, // penting di Vercel
            sameSite: "None", // wajib buat cross-site
            maxAge: 24 * 60 * 60 * 1000
        })

        res.redirect(`${process.env.FRONTEND_URL}/dashboard`)
    }
)

app.get("/auth/failure", (req, res) => {
    res.status(401).send("Auth gagal cuy 😢")
})

app.get("/api/user", (req, res) => {
    const bearerToken = req.header("Authorization")
    const jwtToken = bearerToken.split(" ")[1]

    if (!bearerToken) return res.status(401).json({ message: "No token" })

    try {
        const decoded = jwt.verify(jwtToken, process.env.JWT_SECRET)
        console.log("[DEBUG] TOKEN VERIFIED!", jwtToken)
        res.json(decoded)
    } catch (err) {
        res.status(403).json({ message: "Invalid token" })
    }
})

app.get("/logout", (req, res) => {
    res.clearCookie("token")
    req.logout(() => {
        res.redirect(`${process.env.FRONTEND_URL}/`)
    })
})


app.listen(PORT, () => {
    console.log(`🚀 Server ready di http://localhost:${PORT}`)
})

export default app
