const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const { Schema } = mongoose;

const FacebookSchema = new Schema({
  id: String,
  token: String,
  name: String,
  email: String,
});

const GoogleSchema = new Schema({
  id: String,
  token: String,
  name: String,
  email: String,
});

const LocalSchema = new Schema({
  email: String,
  password: String,
});

const UserSchema = new Schema(
  {
    name: String,
    bio: String,
    phone: Number,
    email: {
      type: String,
      required: true,
    },
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

// https://stackoverflow.com/a/50552763/11674552
LocalSchema.set("toJSON", {
  transform: function (doc, ret, opt) {
    delete ret._id;
    delete ret.password;
    return ret;
  },
});

GoogleSchema.set("toJSON", {
  transform: function (doc, ret, opt) {
    delete ret._id;
    delete ret.id;
    delete ret.token;
    return ret;
  },
});

FacebookSchema.set("toJSON", {
  transform: function (doc, ret, opt) {
    delete ret._id;
    delete ret.id;
    delete ret.token;
    return ret;
  },
});

// Methods

UserSchema.methods.generateHash = (password) => {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(10));
};

// Create Model
const User = mongoose.model("users", UserSchema);

module.exports = User;
