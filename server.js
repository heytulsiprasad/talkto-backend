require("dotenv").config();

const express = require("express");
const morgan = require("morgan");
const mongoose = require("mongoose");
const passport = require("passport");
const session = require("express-session");
const MongoStore = require("connect-mongo")(session);
const flash = require("connect-flash");

const app = express();

// Connecting to database
mongoose
	.connect(process.env.MONGO_LOCAL_URI, {
		useNewUrlParser: true,
		useUnifiedTopology: true,
		useCreateIndex: true,
	})
	.then(() => console.log(`Database connected!`))
	.catch((e) => console.log(e));

// Passing passport instance to middleware
require("./middleware/passport")(passport);

// Express session middlewares
// NOTE: Must be before passport.session()
app.use(
	session({
		secret: "my-secret",
		resave: false,
		saveUninitialized: true,
		store: new MongoStore({ mongooseConnection: mongoose.connection }),
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

// Setup server logging
app.use(morgan("dev"));

// Routes
const auth = require("./routes/api/auth");
app.use("/api/auth", auth);

// All routes go here
app.get("/", (req, res) => {
	res.send("Sunshine is bright");
});

const PORT = 5000 || process.env.PORT;

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
