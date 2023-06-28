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
app.post("/register",cors(), async (req, res) => {
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
app.options('/login', cors())
app.post("/login", cors(), async (req, res) => {
   // Our login logic starts here
  //  console.log("BODY",req.body)
  //  console.log("PARAMS",req.params)
  //  console.log("QUERY",req.query)
   // console.log("REK",req)
   try {
    // Get user input
    const { role ,email, password } = req.body;
    // Validate user input
    if (!(email && password)) {
      res.status(400).send(`All inputs are required -> email: ${email}; pass: ${password}`);
      return {error: `Invalid User`, stauts: 400}
    }
    // Validate if user exist in our database
    const user = await User.findOne({ email });
    // console.log('USER:',user, 'ROLES:', role, user.role)
    if (user && role === user.role && (await bcrypt.compare(password, user.password))) {
      // Create token
      console.log('Creating Token...')
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: "8h",
        }
      );
      // save user token
      user.token = token;
      user.status = 200
      // console.log('NewUser:',user)
      // user
      console.log('TOKEN generated successfully')
      // console.log('TOKEN generated ->',token)
      res.status(200).json(user)
      // return user
    } else {
      console.log(401,'Validation error',{})
      res.status(401).send("Invalid Credentials");
      // return {error: "Invalid Credentials", stauts: 401}
      
    }
  } catch (err) {
    console.log(err);
    console.log(403,'Invalid Credentials',{})
    res.status(403).send("Invalid Credentials");
    // return  {error: "Invalid Credentials", stauts: 403}
  }
  // Our register logic ends here
});
 
module.exports = app;