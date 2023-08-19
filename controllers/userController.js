const bcrypt = require("bcrypt");
const userModel = require("../models/userModel");

//authHelper
const hashPassword = async (password) => {
  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
  } catch (error) {
    console.log(error);
  }
};

const comparePassword = async (password, hashedPassword) => {
  return bcrypt.compare(password, hashedPassword);
};

// login callback
const loginController = async (req, res) => {
  try {
    const { email, password } = req.body;
    //validation
    if (!email || !password) {
      return res.status(200).send({
        success: false,
        message: "Invalid email or password",
      });
    }
    //check user
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(200).send({
        success: false,
        message: "Email is not registerd",
      });
    }
    const match = await comparePassword(password, user.password);
    if (!match) {
      return res.status(200).send({
        success: false,
        message: "Invalid Password",
      });
    }
    res.status(200).json({
      success: true,
      message: "loggedin successfully",
      user,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Error in login",
      error,
    });
  }
};

//Register Callback
const registerController = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    //validations
    if (!name) {
      return res.status(200).send({ 
        success: "false",
        message: "Name is Required" });
    }
    if (!email) {
      return res.status(200).send({ 
        success: "false",
        message: "Email is Required" });
    }
    if (!password) {
      return res.status(200).send({ 
        success: "false",
        message: "Password is Required" });
    }
   
    //check user
    const exisitingUser = await userModel.findOne({ email });
    //exisiting user
    if (exisitingUser) {
      return res.status(200).send({
        success: false,
        message: "Already Registered please login",
      });
    }
    //register user
    const hashedPassword = await hashPassword(password);
    //save
    const user = await new userModel({
      name,
      email,
      password: hashedPassword,
    }).save();

    res.status(201).send({
      success: true,
      message: "User Registered Successfully",
      user,
    });
  
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Error in Registration", 
      error,
    });
  }
};

module.exports = { loginController, registerController };
