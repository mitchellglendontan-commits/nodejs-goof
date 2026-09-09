var mongoose = require('mongoose');
var cfenv = require("cfenv");
var Schema = mongoose.Schema;

var Todo = new Schema({
  content: Buffer,
  updated_at: Date,
});

mongoose.model('Todo', Todo);

var User = new Schema({
  username: String,
  password: String,
});

mongoose.model('User', User);

// CloudFoundry env vars
var mongoCFUri = cfenv.getAppEnv().getServiceURL('goof-mongo');
console.log(JSON.stringify(cfenv.getAppEnv()));

// MongoDB credentials from environment variables
const MONGODB_USERNAME = process.env.MONGODB_USERNAME || 'goof_user';
const MONGODB_PASSWORD = process.env.MONGODB_PASSWORD || 'goof_password_change_in_production';
const MONGODB_DATABASE = process.env.MONGODB_DATABASE || 'express-todo';

// Build authenticated MongoDB URI
const DOCKER = process.env.DOCKER
var mongoUri;
if (DOCKER === '1') {
  // Docker environment with authentication
  mongoUri = `mongodb://${MONGODB_USERNAME}:${MONGODB_PASSWORD}@goof-mongo:27017/${MONGODB_DATABASE}?authSource=admin`;
} else {
  // Local environment with authentication
  mongoUri = `mongodb://${MONGODB_USERNAME}:${MONGODB_PASSWORD}@localhost:27017/${MONGODB_DATABASE}?authSource=admin`;
}

// CloudFoundry Mongo URI (should already include authentication)
if (mongoCFUri) {
  mongoUri = mongoCFUri;
} else if (process.env.MONGOLAB_URI) {
  // Generic (plus Heroku) env var support (should already include authentication)
  mongoUri = process.env.MONGOLAB_URI;
} else if (process.env.MONGODB_URI) {
  // Generic (plus Heroku) env var support (should already include authentication)
  mongoUri = process.env.MONGODB_URI;
}

console.log("Using Mongo URI " + mongoUri.replace(/\/\/([^:]+):([^@]+)@/, '//***:***@'));

mongoose.connect(mongoUri);

User = mongoose.model('User');
User.find({ username: 'admin@snyk.io' }).exec(function (err, users) {
  console.log(users);
  if (users.length === 0) {
    console.log('no admin');
    new User({ username: 'admin@snyk.io', password: 'SuperSecretPassword' }).save(function (err, user, count) {
      if (err) {
        console.log('error saving admin user');
      }
    });
  }
});