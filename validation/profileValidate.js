const Validator = require("validator");
const isEmpty = require("./isEmpty");

const validateProfileInput = (data) => {
  // Will append all errors to this object
  let errors = {};

  // validator package can check for emptyness only with a string
  data.name = isEmpty(data.name) ? "" : data.name;
  data.bio = isEmpty(data.bio) ? "" : data.bio;
  data.phone = isEmpty(data.phone) ? "" : data.phone.toString();

  // Validation of each data type
  if (
    !Validator.isEmpty(data.name) &&
    !Validator.isLength(data.name, { min: 1, max: 50 })
  ) {
    errors.name = "Your name should be between 1 to 50 characters";
  }

  if (
    !Validator.isEmpty(data.bio) &&
    !Validator.isLength(data.bio, { min: 1, max: 255 })
  ) {
    errors.bio = "Your bio should be between 1 to 255 characters";
  }

  if (!Validator.isEmpty(data.phone)) {
    if (!Validator.isInt(data.phone, { gt: 1 })) {
      errors.phone = "Your mobile number should be a positive integer.";
    }

    if (!Validator.isLength(data.phone, { min: 10, max: 10 })) {
      errors.phone = "Your mobile number should be exactly 10 characters.";
    }
  }

  return {
    errors,
    isValid: isEmpty(errors),
  };
};

module.exports = validateProfileInput;
