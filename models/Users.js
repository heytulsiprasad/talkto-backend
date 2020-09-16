const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const { Schema } = mongoose;

const FacebookSchema = new Schema(
	{
		id: String,
		token: String,
		name: String,
		email: String,
	},
	{
		timestamps: true,
	}
);

const GoogleSchema = new Schema(
	{
		id: String,
		token: String,
		name: String,
		email: String,
	},
	{
		timestamps: true,
	}
);

const LocalSchema = new Schema(
	{
		email: String,
		password: String,
	},
	{
		timestamps: true,
	}
);

const UserSchema = new Schema(
	{
		name: String,
		bio: String,
		phone: Number,
		date: {
			type: Date,
			default: Date.now,
		},
		local: [LocalSchema],
		google: [GoogleSchema],
		facebook: [FacebookSchema],
	},
	{
		timestamps: true,
	}
);

// Methods

UserSchema.methods.generateHash = (password) => {
	return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
};

UserSchema.methods.isValidPassword = async function (password) {
	try {
		// Check/Compare Password
		return await bcrypt.compareSync(password, this.local.password);
	} catch (err) {
		console.log(err);
		throw new Error(err);
	}
};

// Create Model
const User = mongoose.model("users", UserSchema);

module.exports = User;
