//jshint esversion:6
require('dotenv').config()
const express = require ("express");
const bodyParser = require("body-parser");
const ejs= require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
// const passportLocal = require("passport-local"); has to be installed, but doesn't need to be required

const app=express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended:true
}));

// Set up express-session
app.use(
    session({
      secret: "Secret.",
      resave: false,
      saveUninitialized: false
    })
  );
  // Set up passport
app.use(passport.initialize());
app.use(passport.session());

// Connecting mongoose to a database
mongoose.connect(process.env.ATLAS_URL, { useNewUrlParser: true}, {useUnifiedTopology: true}, mongoose.set('strictQuery', false));

const userSchema =  new mongoose.Schema({
    email: String,
    password: String,
    googleId: String, //! To store the ID that is receieved from Google
    secret: String //! To store the secret posted by user
});

 
userSchema.plugin(passportLocalMongoose);
const User= new mongoose.model("User", userSchema);

passport.use(User.createStrategy());


passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, name: user.name });
  });
  });
  passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" 
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOne({ googleId: profile.id }).then((foundUser) => {
        if (foundUser) {
          return foundUser;
        } else {
          const newUser = new User({
            googleId: profile.id
          });
          return newUser.save();
        }
      }).then((user) => {
        return cb(null, user);
      }).catch((err) => {
        return cb(err);
      });
  }
));


app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));
 
app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
  });
 
app.get("/", function(req,res){
    res.render("home");
})

app.get("/login", function (req, res) {
    res.render("login");
})
 
app.get("/register", function(req,res){
    res.render("register");
})

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else{
    res.render("login");
  }
  });


app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){ //! {$ne: null} means not null
    if(err){
      console.log(err);
    } else {
      if(foundUsers) {
        console.log(foundUsers);
        res.render("secrets", {SecretUsers: foundUsers});
      } else {
        console.log("No secret has been posted yet, check back later or post your secret.");
      }
    }
  });
  });
  

app.get("/logout", function(req, res){
    req.logout(function (err) {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
    
});


app.post("/login", function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  //! Below code is from passport.js > concepts > authentication > log in
  req.login(user, function(err){
    if(err){
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("secrets");
        console.log("Current logged in user: " + req.user.username); 
      })
    } 
  });
  });

app.post("/register", function(req,res){
    User.register({username: req.body.username}, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
    })
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  const loggedInUserID = req.user.id;  //! Fetching the logged in user ID from the session that we receive through cookie(session)
  
  User.findById(loggedInUserID, function(err, foundUser){
    if(err){
      console.log(err);
    } else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("secrets");
        })
      }
    };
  });
  });


app.listen(3000, function(){
    console.log("Server started on port 3000.")
})