module.exports = (mongoose) => {
  // Connecting to database
  mongoose
    .connect(process.env.MONGO_CONNECT_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useCreateIndex: true,
    })
    .then(() => console.log(`Database connected!`))
    .catch((e) => console.log(e));
};
