const express = require("express");
const bcrypt = require("bcrypt");
const passport = require("passport");

const router = express.Router();

// Import validator
const authValidate = require("./../../validation/authValidate");

// @route POST api/auth/signup
// @desc Register new users to database
// @access Public

router.post("/signup", (req, res, next) => {
	// Return validator results
	const { errors, isValid } = authValidate(req.body);

	// Check validation
	if (!isValid) return res.status(400).json(errors);

	passport.authenticate("local-signup", (err, user, info) => {
		if (err) {
			errors.error = err;
			return res.status(400).json(errors);
		}

		// If user object is empty means, same email is already in our database
		if (!user) {
			errors.email = req.flash("message")[0];
			return res.status(400).json(errors);
		}

		// Finally register if everything is okay
		req.logIn(user, (err) => {
			return res.json({ user });
		});
	})(req, res, next);
});

// @route POST api/auth/login
// @desc Login users
// @access Public

router.post("/login", (req, res, next) => {
	// Return validator results
	const { errors, isValid } = authValidate(req.body);

	// Check validation
	if (!isValid) return res.status(400).json(errors);

	passport.authenticate("local-login", (err, user, info) => {
		if (err) {
			errors.error = err;
			return res.status(400).json(errors);
		}

		// If user doesn't exist in database
		if (!user) {
			errors.email = req.flash("message")[0];
			return res.status(400).json(errors);
		}

		// Finally login if everything is sure
		req.logIn(user, (err) => {
			return res.json({ user });
		});
	})(req, res, next);
});

// @route POST api/auth/logout
// @desc Logout users
// @access Public

router.post("/logout", (req, res, next) => {
	if (req.isAuthenticated()) {
		req.logout();
		return res.json({ message: "Logout successful!" });
	} else {
		return res.status(400).json({ message: "Not logged in yet!" });
	}
});

module.exports = router;
