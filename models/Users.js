const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const Schema = mongoose.Schema;

const UserSchema = new Schema({
	local: {
		email: String,
		password: String,
	},
	facebook: {
		id: String,
		token: String,
		name: String,
		email: String,
	},
	twitter: {
		id: String,
		token: String,
		displayName: String,
		username: String,
	},
	google: {
		id: String,
		token: String,
		email: String,
		name: String,
	},
});

// Methods

UserSchema.methods.generateHash = (password) => {
	return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
};

UserSchema.methods.validPassword = function (password) {
	return bcrypt.compareSync(password, this.local.password);
};

// Create Model
const User = mongoose.model("users", UserSchema);

module.exports = User;
