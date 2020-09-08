const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

const User = require("../models/Users");

// Refer http://toon.io/understanding-passportjs-authentication-flow/
// for understanding the flow of these functions behind the scenes

module.exports = (passport) => {
	// This determines what data from user object is stored in sessions
	// The result is attached at `req.session.passport.user` and `req.user`
	// This is invoked only after returning from passport.use(new Strategy) middleware
	passport.serializeUser((user, done) => {
		done(null, user._id);
	});

	// This is called by `passport.session()` to attach the req.user value
	// fetched from database
	passport.deserializeUser((id, done) => {
		User.findById(id, (err, user) => {
			done(err, user);
		});
	});

	// This is only invoked by the route which calls passport.authenticate middleware
	passport.use(
		"local-signup",
		new LocalStrategy(
			{
				usernameField: "email",
				passwordField: "password",
				// Ability to use additional form fields inside callback
				// https://stackoverflow.com/a/11784742/11674552
				passReqToCallback: true,
			},
			(req, email, password, done) => {
				User.findOne({ email: email }, (err, user) => {
					// Check for database errors
					if (err) {
						return done(err);
					}

					// Check if user is found
					if (user) {
						return done(
							null,
							false,
							req.flash("message", "That email already exists!")
						);
					} else {
						let newUser = new User();

						newUser.email = email;
						newUser.password = password;

						// Hash password using bcrypt
						bcrypt.genSalt(10, (err, salt) => {
							if (err) console.log(err);
							else {
								bcrypt.hash(newUser.password, salt, (err, hash) => {
									if (err) console.log(err);
									else {
										// Updating new user object
										newUser.password = hash;

										// Save to database
										newUser.save((err) => {
											if (err) throw err;
											return done(null, newUser);
										});
									}
								});
							}
						});
					}
				});
			}
		)
	);

	passport.use(
		"local-login",
		new LocalStrategy(
			{
				usernameField: "email",
				passwordField: "password",
				// Ability to use additional form fields inside callback
				// https://stackoverflow.com/a/11784742/11674552
				passReqToCallback: true,
			},
			(req, email, password, done) => {
				User.findOne({ email: email }, (err, user) => {
					// Check for database errors
					if (err) {
						return done(err);
					}

					// If user exists
					if (user) {
						// Compare entered password with stored password
						bcrypt.compare(password, user.password, (err, result) => {
							if (result) return done(null, user);
							else
								done(
									null,
									false,
									req.flash("message", "Invalid Password. Try again!")
								);
						});
					}

					// If user don't exists
					else {
						return done(
							null,
							false,
							req.flash("message", "No user found with this email!")
						);
					}
				});
			}
		)
	);
};
