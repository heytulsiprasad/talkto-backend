const { response } = require("express");
const express = require("express");
const router = express.Router();

const User = require("./../models/Users");
const profileValidate = require("./../validation/profileValidate");

const frontendUrl =
  process.env.NODE_ENV === "production"
    ? process.env.FRONTEND_PROD_URL
    : process.env.FRONTEND_LOCAL_URL;

// Acts as an middleware to check auth state and give access to private routes
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  // Redirect to login route
  return res.redirect(`${frontendUrl}/login`);
}

// @route GET /profile
// @desc Get user profile
// @access Private

router.get("/", isLoggedIn, (req, res, next) => {
  return res.json(req.user);
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

// @route POST /profile/delete
// @desc Delete user profile
// @access Private

router.delete("/delete", isLoggedIn, (req, res) => {
  User.findByIdAndRemove({ _id: req.user._id }, (err, user) => {
    if (err) throw new Error(err);
    return res.send(true);
  });
});

module.exports = router;
