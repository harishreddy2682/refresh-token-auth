import express from 'express'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import asyncHandler from 'express-async-handler'
import cookieParser from 'cookie-parser'

const users = [
    {
        id: "1",
        username: "john",
        password: "john123",
        isAdmin: true
    },
    {
        id: "2",
        username: "jane",
        password: "jane123",
        isAdmin: false
    },
]

let refreshTokens = []

const app = express()
app.use(express.json())
app.use(cors())
app.use(cookieParser())

app.post("/api/refresh", (req, res) => {
    // take the refresh token from the user
    const refreshToken = req.body.token

    //send error if there is no token or token is invalid
    if (!refreshToken) return res.status(401).json("Yout are not authenticated!")
    if (!refreshTokens.includes(refreshToken)) {
        return res.status(403).json("Refresh token is not valid!")
    }
    jwt.verify(refreshToken, "myRefreshSecretkey", (err, user) => {
        err && console.log(err)
        refreshTokens = refreshTokens.filter(token => token !== refreshToken)

        const newAccessToken = generateAccessToken(user)
        const newRefreshToken = generateRefreshToken(user)

        refreshTokens.push(newRefreshToken)

        res.status(200).json({
            accessToken: newAccessToken, refreshToken: newRefreshToken
        })
    })
    //if everything is ok, create new acess token, refresh token and send to user
})

const generateAccessToken = (user) => {
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecretKey", {
        expiresIn: "5s"
    })
}

const generateRefreshToken = (user) => {
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "myRefreshSecretkey")
}

app.post('/api/login', asyncHandler(async (req, res) => {
    const { username, password } = req.body
    const user = users.find(u => u.username === username && u.password === password)
    if (user) {
        //Generate an access token
        const accessToken = generateAccessToken(user)
        const refreshToken = generateRefreshToken(user)
        refreshTokens.push(refreshToken)

        res.json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken
        })
    } else {
        res.status(400).json("Username or password is incorrect!")
    }

}))

const verify = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(" ")[1];

        jwt.verify(token, "mySecretKey", (err, user) => {
            if (err) {
                return res.status(403).json("Token is not valid!");
            }

            req.user = user;
            next();
        });
    } else {
        res.status(401).json("You are not authenticated!");
    }
};

app.post("/api/logout", verify, (req, res) => {
    const refreshToken = req.body.token

    refreshTokens = refreshTokens.filter(token => token !== refreshToken)

    res.status(200).json("You logged out successfully!")
})

app.delete("/api/users/:userId", verify, asyncHandler(async (req, res) => {
    if (req.user.id === req.params.userId || req.user.isAdmin) {
        res.status(200).json("User has been deleted!")
    } else {
        res.status(403).json("You are not allowed to delete this user!")
    }
}))

app.listen(5000, console.log("Server running on port 5000"))