const Validator = require("validator");
const isEmpty = require("./isEmpty");

const validateAuthInput = (data) => {
	// Will append all errors to this object
	let errors = {};

	// validator package can check for emptyness only with a string
	data.email = isEmpty(data.email) ? "" : data.email;
	data.password = isEmpty(data.password) ? "" : data.password;

	// Validation using the package
	if (Validator.isEmpty(data.email)) {
		errors.email = "Email field is required";
	}

	// Checks emails format
	if (!Validator.isEmpty(data.email) && !Validator.isEmail(data.email)) {
		errors.email = "Email is invalid";
	}

	if (Validator.isEmpty(data.password)) {
		errors.password = "Password field is required";
	}

	// Runs if password exists but not in proper format
	if (
		!Validator.isEmpty(data.password) &&
		!Validator.isLength(data.password, { min: 3, max: 30 })
	) {
		errors.password = "Password must be at least 3 characters";
	}

	return {
		errors,
		isValid: isEmpty(errors),
	};
};

module.exports = validateAuthInput;
