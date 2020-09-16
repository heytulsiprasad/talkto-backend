const LocalStrategy = require("passport-local").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const bcrypt = require("bcrypt");

const User = require("../models/Users");
const authConfig = require("../config/auth");

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

	//////////////////////////// Local Signup

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
				process.nextTick(() => {
					// Not logged in
					if (!req.user) {
						User.findOne({ "local.email": email }, (err, user) => {
							if (err) return done(err);

							// User found
							if (user) {
								return done(
									null,
									false,
									req.flash("message", "That email already exists!")
								);
							}

							// If no user found
							let newUser = new User();

							newUser.local.push({
								email: email,
								password: newUser.generateHash(password),
							});

							newUser.save(function (err) {
								if (err) throw err;
								return done(null, newUser);
							});
						});
					}

					// Logged in (connect)
					else {
						const user = req.user;

						if (user.local.length === 0) {
							user.local.push({
								email: email,
								password: user.generateHash(password),
							});

							user.save((err) => {
								if (err) throw err;
								return done(null, user);
							});
						} else {
							console.log("You're already authorized locally");
							console.log(req.user);

							return done(
								null,
								false,
								req.flash({ message: "User already locally authorized" })
							);
						}
					}
				});
			}
		)
	);

	//////////////////////////// Local Login

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
				process.nextTick(() => {
					User.findOne({ "local.email": email }, async (err, user) => {
						if (err) return done(err);

						// User not found
						if (!user) {
							return done(null, false, req.flash("message", "No user found"));
						}

						// Password not match
						if (!(await user.isValidPassword(password))) {
							return done(
								null,
								false,
								req.flash("message", "Invalid Password")
							);
						}

						if (await user.isValidPassword(password)) {
							return done(null, user);
						}
					});
				});
			}
		)
	);

	//////////////////////////// Facebook

	passport.use(
		// Things to include in facebook strategy
		// https://stackoverflow.com/a/32370813/11674552
		new FacebookStrategy(
			{
				clientID: authConfig.facebookAuth.clientID,
				clientSecret: authConfig.facebookAuth.clientSecret,
				callbackURL: authConfig.facebookAuth.callbackURL,
				profileFields: ["id", "email", "name"],

				// when passreqtocallback is true, add req to callback
				// https://github.com/jaredhanson/passport-facebook/issues/185#issuecomment-335530926
				passReqToCallback: true,
			},
			function (req, accessToken, refreshToken, profile, done) {
				process.nextTick(() => {
					// Not logged in
					if (!req.user) {
						User.findOne({ "facebook.id": profile.id }, function (err, user) {
							if (err) return done(err);

							// User found
							if (user) {
								// No token found
								if (!user.facebook.token) {
									user.facebook.push({
										token: accessToken,
										name: `${profile.name.givenName} ${profile.name.familyName}`,
										email: profile.emails[0].value,
									});

									user.save((err) => {
										if (err) throw err;
									});
								}

								return done(null, user);
							} else {
								const newUser = new User();

								newUser.facebook.push({
									id: profile.id,
									token: accessToken,
									name: `${profile.name.givenName} ${profile.name.familyName}`,
									email: profile.emails[0].value,
								});

								newUser.save(function (err) {
									if (err) throw err;
									return done(null, newUser);
								});
							}
						});
					}

					// Logged in
					else {
						let user = req.user;

						// No facebook auth
						if (user.facebook.length === 0) {
							user.facebook.push({
								id: profile.id,
								token: accessToken,
								name: `${profile.name.givenName} ${profile.name.familyName}`,
								email: profile.emails[0].value,
							});

							user.save((err) => {
								if (err) throw err;
								return done(null, user);
							});
						} else {
							console.log("You're already authorized");
							console.log(req.user);
							return done(
								null,
								false,
								req.flash({ message: "You're already authorized!" })
							);
						}
					}
				});
			}
		)
	);

	//////////////////////////// Google
	passport.use(
		new GoogleStrategy(
			{
				clientID: authConfig.googleAuth.clientID,
				clientSecret: authConfig.googleAuth.clientSecret,
				callbackURL: authConfig.googleAuth.callbackURL,
				passReqToCallback: true,
			},
			function (req, accessToken, refreshToken, profile, done) {
				process.nextTick(() => {
					// Not logged in
					if (!req.user) {
						User.findOne({ "google.id": profile.id }, function (err, user) {
							if (err) return done(err);

							// User found
							if (user) {
								// Token not found
								if (!user.google.token) {
									user.google.push({
										token: accessToken,
										name: profile.displayName,
										email: profile.emails[0].value,
									});

									user.save((err) => {
										if (err) throw err;
									});
								}

								return done(null, user);
							} else {
								// New User
								const newUser = new User();

								newUser.google.push({
									id: profile.id,
									token: accessToken,
									name: profile.displayName,
									email: profile.emails[0].value,
								});

								newUser.save(function (err) {
									if (err) throw err;
									return done(null, newUser);
								});
							}
						});

						// Logged in
					} else {
						let user = req.user;

						if (user.google.length === 0) {
							user.google.push({
								id: profile.id,
								token: accessToken,
								name: profile.displayName,
								email: profile.emails[0].value,
							});

							user.save((err) => {
								if (err) throw err;
								return done(null, user);
							});
						} else {
							console.log("You're already authorized");
							console.log(req.user);
							return done(
								null,
								false,
								req.flash({ message: "You're already authorized!" })
							);
						}
					}
				});
			}
		)
	);
};
