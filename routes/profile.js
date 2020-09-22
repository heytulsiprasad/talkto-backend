const express = require("express");
const router = new express.Router();

const User = require("./../models/Users");
const profileValidate = require("./../validation/profileValidate");

// Acts as an middleware to check auth state and give access to private routes
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  // Redirect to login route
  return res.redirect(302, "http://localhost:3000/login");
}

// @route GET /profile
// @desc Get user profile
// @access Private

router.get("/", isLoggedIn, (req, res, next) => {
  res.json(req.user);
  return next();
});

// @route POST /profile/edit
// @desc Edit user profile
// @access Private

router.post("/edit", isLoggedIn, (req, res, next) => {
  // Validate input
  const { errors, isValid } = profileValidate(req.body);

  // Send errors
  if (!isValid) return res.status(400).json(errors);

  const authUser = req.user;

  User.findOne({ email: authUser.email }, (err, user) => {
    if (err) {
      errors.error = err;
      return res.status(400).json(errors);
    }

    const { name, phone, bio, image } = req.body;

    user.name = name || user.name;
    user.phone = phone || user.phone;
    user.bio = bio || user.bio;
    user.image = image || user.image;

    user.save((err) => {
      if (err) {
        errors.error = err;
        return res.status(500).json(errors);
      }

      return res.send();
    });
  });
});

module.exports = router;
