const User = require("../../../models/user");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const signupUser = async (req, res) => {
  const { nom, prenom, email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({
        message: "User already exists",
      });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      nom,
      prenom,
      email,
      password: hashedPassword,
    });
    await newUser.save();
    res.status(201).json({
      message: "Successfully created",
      data: newUser,
    });
  } catch (error) {
    console.log("Error signupUser =>", error);
    res.status(500).json({
      message: "Server error",
    });
  }
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        message: "user not found",
      });
    }
    const compare = await bcrypt.compare(password, user.password);
    if (compare == false) {
      return res.status(400).json({
        message: "wrong credentials",
      });
    }
    const token = jwt.sign({ email: user.email }, process.env.PRIVATE_KEY);
    if (!token) {
      return res.status(500).json({
        message: "Server error",
      });
    }
    return res.status(200).json({
      message: "login successful",
      data: {
        access_token: token,
      },
    });
  } catch (error) {
    console.log("Error loginUser =>", error);
    res.status(500).json({
      message: "Server error",
    });
  }
};

const getInfoUser = async (req, res) => {
  try {
    const data = req.data;
    const user = await User.findOne({ email: data.email }, "-_id -password");
    if (!user) {
      return res.status(400).json({
        message: "User not found",
      });
    }

    res.status(200).json({
      message: "Fetched successfully",
      data: user,
    });
  } catch (error) {
    let message = "Server error";
    console.log("Error loginUser =>", error);
    if (error.toString().includes("JsonWebTokenError")) {
      message = "Error in token";
    }
    res.status(500).json({
      message,
    });
  }
};

module.exports = {
  signupUser,
  loginUser,
  getInfoUser,
};
