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
					User.findOne({ "local.email": email }, (err, user) => {
						// Check for database errors
						if (err) return done(err);

						// Check if user is found
						if (user) {
							return done(
								null,
								false,
								req.flash("message", "That email already exists!")
							);
						}

						// If the user isn't logged in
						if (!req.user) {
							let newUser = new User();

							newUser.local.email = email;
							newUser.local.password = newUser.generateHash(password);

							newUser.save(function (err) {
								if (err) throw err;
								return done(null, newUser);
							});
						}

						// Are logged in, but are trying to merge local account to some oauth acc
						else {
							let user = req.user;
							user.local.email = email;
							user.local.password = user.generateHash(password);

							user.save((err) => {
								if (err) throw err;
								return done(null, user);
							});
						}
					});
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
					User.findOne({ "local.email": email }, (err, user) => {
						// Check for database errors
						if (err) return done(err);
						if (!user)
							return done(null, false, req.flash("message", "No user found"));

						// replace with user method on user model
						if (!bcrypt.compareSync(password, user.local.password)) {
							return done(
								null,
								false,
								req.flash("message", "Invalid password")
							);
						}

						if (user.validPassword(password)) return done(null, user);
					});
				});
			}
		)
	);

	//////////////////////////// Facebook

	passport.use(
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
					// User is not logged in
					if (!req.user) {
						User.findOne({ "facebook.id": profile.id }, function (err, user) {
							if (err) return done(err);
							if (user) {
								// If user unlinked their facebook we'd have deleted the token
								if (!user.facebook.token) {
									user.facebook.token = accessToken;
									user.facebook.name = `${profile.name.givenName} ${profile.name.familyName}`;
									user.facebook.email = profile.emails[0].value;

									user.save((err) => {
										if (err) throw err;
									});
								}
								return done(null, user);
							} else {
								const newUser = new User();
								newUser.facebook.id = profile.id;
								newUser.facebook.token = accessToken;
								newUser.facebook.name = `${profile.name.givenName} ${profile.name.familyName}`;
								newUser.facebook.email = profile.emails[0].value;

								newUser.save(function (err) {
									if (err) throw err;
									return done(null, newUser);
								});
							}
						});
					}

					// User is logged in, and needs to be merged
					else {
						let user = req.user;
						user.facebook.id = profile.id;
						user.facebook.token = accessToken;
						user.facebook.name = `${profile.name.givenName} ${profile.emails[0].value}`;
						user.facebook.email = profile.emails[0].value;

						user.save((err) => {
							if (err) throw err;
							return done(null, user);
						});
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
					if (!req.user) {
						User.findOne({ "google.id": profile.id }, function (err, user) {
							if (err) return done(err);
							if (user) {
								if (!user.google.token) {
									user.google.token = accessToken;
									user.google.name = profile.displayName;
									user.google.email = profile.emails[0].value;

									user.save((err) => {
										if (err) throw err;
									});
								}
								return done(null, user);
							} else {
								const newUser = new User();
								newUser.google.id = profile.id;
								newUser.google.token = accessToken;
								newUser.google.name = profile.displayName;
								newUser.google.email = profile.emails[0].value;

								newUser.save(function (err) {
									if (err) throw err;
									return done(null, newUser);
								});
							}
						});
					} else {
						let user = req.user;
						user.google.id = profile.id;
						user.google.token = accessToken;
						user.google.name = profile.displayName;
						user.google.email = profile.emails[0].value;

						user.save((err) => {
							if (err) throw err;
							return done(null, user);
						});
					}
				});
			}
		)
	);
};
