const express = require("express");
const mongoose = require("mongoose");
require("dotenv").config();
const userRouter = require("./api/controllers/user/router");
const app = express();
const PORT = process.env.PORT || 2000;
mongoose.connect(process.env.MONGO_URL, {
  useCreateIndex: true,
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.once("open", () => console.log("Database connected"));

app.use(express.json());
app.use("/user", userRouter);

app.use((error, req, res, next) => {
  res.send({ message: error.message });
});

app.listen(PORT, () => console.log("Listening on http://localhost" + PORT));
