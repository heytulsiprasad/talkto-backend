const express = require("express");
const passport = require("passport");

const router = express.Router();

// Import validator
const authValidate = require("../validation/authValidate");

// @route GET /auth/state
// @desc Is user logged in/not
// @access Public

router.get("/state", (req, res, next) => {
  let isLogged = req.isAuthenticated();
  return res.send(isLogged);
});

// @route POST /auth/signup
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

    // Finally register and login if everything is okay
    req.logIn(user, (err) => {
      return res.json({ user });
      // return res.redirect(302, "http://localhost:3000");
    });
  })(req, res, next);
});

// @route POST /auth/login
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
      errors.email = req.flash("emailMsg")[0];
      errors.password = req.flash("passwordMsg")[0];
      return res.status(400).json(errors);
    }

    // Finally login if everything is sure
    req.logIn(user, (err) => {
      console.log("Logging in", user);
      return res.json({ user });
      // return res.redirect(302, "http://localhost:3000");
    });
  })(req, res, next);
});

// @route POST /auth/logout
// @desc Logout users
// @access Public

router.get("/logout", (req, res, next) => {
  if (req.isAuthenticated()) {
    console.log("Logging out", req.user);
    req.logout();
    return res.json({ message: "Logout successful!" });
  } else {
    return res.status(400).json({ message: "Not logged in yet!" });
  }
});

// @route GET /auth/facebook
// @desc Redirect to facebook for user to login
// @access Public

router.get(
  "/facebook",
  passport.authenticate("facebook", { scope: ["email"] })
);

/*
 * @route GET /auth/facebook
 * @desc After successfull auth fb redirects to this
 * @access Public
 */

router.get(
  "/facebook/callback",
  passport.authenticate("facebook", {
    failureRedirect: "http://localhost:3000/login",
  }),
  function (req, res) {
    // Successful authentication, redirect home
    console.log(req.user);

    // Redirects user to dashboard route on frontend
    return res.redirect(302, "http://localhost:3000");
  }
);

// @route GET /auth/google
// @desc Redirect to google for user to login
// @access Public

// @dev https://console.developers.google.com/

router.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// @route GET /auth/google
// @desc After successfull auth fb redirects to this
// @access Public

router.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: "http://localhost:3000/login",
  }),
  function (req, res) {
    // Successful authentication, redirect home.
    console.log(req.user);

    // Redirects user to dashboard route on frontend
    return res.redirect(302, "http://localhost:3000");
  }
);

module.exports = router;
