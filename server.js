require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const passport = require("passport");
const session = require("express-session");
const MongoStore = require("connect-mongo")(session);
const flash = require("connect-flash");

const app = express();

// Logging middleware
if (process.env.NODE_ENV !== "production") {
  const morgan = require("morgan");
  app.use(morgan("dev"));
}

// Express middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const origin =
  process.env.NODE_ENV === "production"
    ? process.env.FRONTEND_PROD_URL
    : process.env.FRONTEND_LOCAL_URL;

// Setting up cors
app.use(
  cors({
    origin: origin,
    preflightContinue: true,
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials: true,
  })
);

// Adding database to project
require("./middleware/mongoose")(mongoose);

// Passing passport instance to passport.js
require("./middleware/passport")(passport);

// Express session middlewares
// NOTE: Must be before passport.session()
const sessionConfig = {
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new MongoStore({
    mongooseConnection: mongoose.connection,
    ttl: 2 * 24 * 60 * 60, // 2 days
  }),
  cookie: {
    sameSite: "none",
  },
};

if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1); // trust first proxy
  sessionConfig.cookie.secure = true; // serve secure cookies
}

app.use(session(sessionConfig));

// Passport middlewares

// Runs on every request, to ensure the session contains a `req.user` object
app.use(passport.initialize());

// Is a passport strategy which alters `req.user` from session id to entire deserialized user object
// if it finds a corresponding serialized user (invokes deserializeUser)
app.use(passport.session());

// Allows us to store a message inside `req.flash()` and access it anywhere
app.use(flash());

// req.session.passport.user (session data) is same as the user id in user model from database

// app.use((req, res, next) => {
// 	console.log(req.session);
// 	console.log("=================");
// 	console.log(req.user);
// 	next();
// });

// Routes
const auth = require("./routes/auth");
app.use("/auth", auth);

const profile = require("./routes/profile");
app.use("/profile", profile);

// All routes go here
app.get("/", (req, res) => res.send("Sunshine is bright"));

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
