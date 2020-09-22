module.exports = (mongoose) => {
  const db =
    process.env.NODE_ENV === "production"
      ? process.env.MONGO_PROD_URI
      : process.env.MONGO_LOCAL_URI;

  // Connecting to database
  mongoose
    .connect(db, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useCreateIndex: true,
    })
    .then(() => console.log(`Database connected!`))
    .catch((e) => console.log(e));
};
