require("dotenv").config();

const express = require("express");
const morgan = require("morgan");
const mongoose = require("mongoose");
const passport = require("passport");
const session = require("express-session");
const MongoStore = require("connect-mongo")(session);
const flash = require("connect-flash");

const app = express();

// Adding database to project
require("./middleware/mongoose")(mongoose);

// Passing passport instance to passport.js
require("./middleware/passport")(passport);

// Express session middlewares
// NOTE: Must be before passport.session()
app.use(
	session({
		secret: process.env.SESSION_SECRET,
		resave: false,
		saveUninitialized: true,
		store: new MongoStore({
			mongooseConnection: mongoose.connection,
			ttl: 2 * 24 * 60 * 60,
		}),
	})
);

// Passport middlewares

// Runs on every request, to ensure the session contains a `req.user` object
app.use(passport.initialize());

// Is a passport strategy which loads the user object to `req.user`
// if it finds a corresponding serialized user (invokes deserializeUser)
app.use(passport.session());

// Allows us to store a message inside `req.flash()` and access it anywhere
app.use(flash());

// Express middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// req.session.passport.user (session data) is same as the user id in user model from database

// app.use((req, res, next) => {
// 	console.log(req.session);
// 	console.log("=================");
// 	console.log(req.user);
// 	next();
// });

// Setup server logging
app.use(morgan("dev"));

// Routes
const auth = require("./routes/auth");
app.use("/auth", auth);

// All routes go here
app.get("/", (req, res) => res.send("Sunshine is bright"));
app.get("/profile", (req, res) => res.json(req.user));

const PORT = 5000 || process.env.PORT;

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
