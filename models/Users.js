const mongoose = require("mongoose");

// Create Schema
const UserSchema = new mongoose.Schema({
	email: {
		type: String,
		required: true,
		unique: true,
	},
	password: {
		type: String,
		required: true,
	},
	date: {
		type: Date,
		default: Date.now,
	},
});

// Create Model
const User = mongoose.model("users", UserSchema);

module.exports = User;
