//jshint esversion:6
const express = require("express");
const bodyParser = require("body-parser");
require('ejs');
const path = require('path');
const mongoose = require('mongoose');
const _ = require('lodash');
// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const TwitterStrategy = require('passport-twitter');
const findOrCreate = require('mongoose-findorcreate');
const keys = require('./keys');

const app = express();

app.use(express.static(path.join(__dirname, "public")));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));

// Passport related stuff - Add session
app.use(session({
  secret: 'SOMETEXT',
  resave: true,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());


// Using MongoDB Atlas
const dbUrl = 'mongodb://127.0.0.1:27017/userDB';
// const dbUrl = `mongodb+srv://admin:${process.env.MONGO_PWD}@cluster0-iws9g.mongodb.net/userDB`;

mongoose.connect(dbUrl, {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  twitterId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// To use encryption, add before defining model
// const secret = process.env.SOME_LONG_UNGUESSABLE_STRING;
// console.log(`Secret is ${secret}`);
// userSchema.plugin(encrypt, { secret: secret, encryptedFields: ['password'] });
// Ends

const User = mongoose.model('user', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || keys.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || keys.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(`Got from Google - ${JSON.stringify(profile)}`);
  
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

passport.use(new TwitterStrategy({
  consumerKey: keys.TWITTER_API_KEY,
  consumerSecret: keys.TWITTER_API_SECRET,
  callbackURL: "http://localhost:3000/auth/twitter/secrets"
},
function(token, tokenSecret, profile, cb) {
  User.findOrCreate({ twitterId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.get("/", function (req, res) {
  res.render('home');
});

app.get("/login", function (req, res) {
    res.render('login');
});

app.get("/register", function (req, res) {
  res.render('register');
});

app.get('/secrets', function (req, res) {
  if(req.isAuthenticated()) {
    User.find({"secret": {$ne: null}}, function(err, users) {
      if(err) {
        throw err;
      }
      if(users) {
        res.render('secrets', {usersWithSecrets: users});
      }
    });
  } else {
    res.render('login');
  }
});

app.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    console.log('Success');
    
    res.redirect('/secrets');
});

app.get('/auth/twitter',
  passport.authenticate('twitter'));

app.get('/auth/twitter/secrets', 
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/submit', function(req, res) {
  if (req.isAuthenticated()){
    res.render('submit');
  } else {
    res.redirect('/login');
  }
});

app.post('/register', function(req, res) {
  const username = req.body.username;
  const password = req.body.password;

  User.register({username}, password, function(err, user) {
    if(err) {
      res.redirect('/register');
    } else {
      passport.authenticate('local')(req, res, function () {
        res.redirect('/secrets');
      });
    }
  });
});

app.post('/login', function(req, res) {
  const username = req.body.username;
  const password = req.body.password;

  const tempUser = new User({
    username,
    password
  });

  req.login(tempUser, function(err) {
    if(err) {
      console.error(err);
    }
    passport.authenticate('local')(req, res, function () {
      res.redirect('secrets');
    });
  });
  
});

app.post('/submit', function(req, res) {
  const secretText = req.body.secret;
  console.log(req.user.id);
  User.findById(req.user.id, function(err, userObj) {
    if(err) {
      throw err;
    }
    if(userObj) {
      userObj.secret = secretText;
      userObj.save(function() {
        res.redirect('/secrets');
      });
    }
  });
});

app.listen(port, function () {
  console.log("Server Started");
});
