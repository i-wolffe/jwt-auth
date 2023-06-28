require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const cors = require('cors')
const User = require("./model/user");
const app = express();

app.use(express.json());

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  next();
});

app.options('/register', cors())
app.post("/register", async (req, res) => {
  try {
    // Get user input
    const { role, email, password } = req.body;

    // Validate user input
    if (!(role && password && email )) {
      res.status(400).send("All inputs are required");
    }
    // check if user already exist
    // Validate if user exist in our database
    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(409).send("Registration denied. User " + oldUser.email + " already exists.");
    }

    //Encrypt user password
    encryptedPassword = await bcrypt.hash(password, 10);

    // Create user in our database
    const user = await User.create({
      role,
      email: email.toLowerCase(), // sanitize: convert email to lowercase
      password: encryptedPassword,
    });

    // Create token
    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY,
      {
        expiresIn: "8h"}
    );
    // save user token
    user.token = token;

    // return new user
    res.status(201).json(user);
  } catch (err) {
    console.log(err);
  }
});

// Login
app.options('/register', cors())
app.post("/login", async (req, res) => {
  res.set('Access-Control-Allow-Origin', 'http://localhost:3000');
   // Our login logic starts here
   console.error(req.body)
   try {
    // Get user input
    const { email, password } = req.body;
    // Validate user input
    if (!(email && password)) {
      console.log(email,password)
      res.status(400).send(`All inputs are required -> email: ${email}; pass: ${password}`);
    }
    // Validate if user exist in our database
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: "8h",
        }
      );

      // save user token
      user.token = token;

      // user
      res.status(200).json(user);
    }
    res.status(400).send("Invalid Credentials" + req);
  } catch (err) {
    console.log(err);
  }
  // Our register logic ends here
});
 
module.exports = app;