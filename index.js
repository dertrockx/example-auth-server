const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const app = express();

require("dotenv").config();

app.use(cors());
app.use(express.json());

const SECRET_KEY = process.env.SECRET_KEY || "secret";
const AUTH_TOKEN_EXPIRY = 5; // 5 seconds
const REFRESH_TOKEN_EXPIRY = 10; // 10 seconds

// POST /auth/login
app.post("/auth/login", (req, res) => {
	const { username = "", password = "" } = req.body;
	return res.json({
		token: {
			auth: jwt.sign({ username, password }, SECRET_KEY, {
				expiresIn: AUTH_TOKEN_EXPIRY,
			}),
			refresh: jwt.sign({ username, password }, SECRET_KEY, {
				expiresIn: REFRESH_TOKEN_EXPIRY,
			}),
		},
		token_expiry: AUTH_TOKEN_EXPIRY * 1000, // 5000 milliseconds
	});
});
// GET /auth/refresh
app.get("/auth/refresh", (req, res) => {
	const { authorization = "" } = req.headers;

	// Check if token exists
	const [_ = null, token = null] = authorization.match(/^Bearer (.+)$/) || [];
	// return a 401 if not
	if (!token) {
		return res.status(401).json({
			message: "No token provided",
			code: "token/missing",
			error: "token/missing",
		});
	}

	// validate token
	try {
		jwt.verify(token, SECRET_KEY);
		const { iat, exp, ...rest } = jwt.decode(token);
		const now = Date.now();

		if (now < exp) throw new jwt.TokenExpiredError();
		const response = {
			token: {
				auth: jwt.sign(rest, SECRET_KEY, {
					expiresIn: AUTH_TOKEN_EXPIRY,
				}),
				refresh: jwt.sign(rest, SECRET_KEY, {
					expiresIn: REFRESH_TOKEN_EXPIRY,
				}),
			},
			token_expiry: AUTH_TOKEN_EXPIRY * 1000, // 5000 milliseconds
		};
		return res.json(response);
	} catch (error) {
		/**
		 * jwt.TokenExpiredError is a child class of jwt.JsonWebTokenError, so we need to check if it's an instance of the child class first before the parent class
		 */
		if (error instanceof jwt.TokenExpiredError) {
			return res.status(401).json({
				message: "Token has expired",
				error: "token/expired",
				code: "token/expired",
			});
		} else if (error instanceof jwt.JsonWebTokenError) {
			return res.status(401).json({
				message: "Token is invalid",
				error: "token/invalid",
				code: "token/invalid",
			});
		}
	}
});

app.listen(8000, (err) => {
	if (err) throw err;
	console.log("🚀 Running on :8000");
});
