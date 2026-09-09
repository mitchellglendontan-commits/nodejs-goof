var mongoose = require('mongoose');
var cfenv = require("cfenv");
var bcrypt = require('bcryptjs');
var crypto = require('crypto');
var Schema = mongoose.Schema;

var Todo = new Schema({
  content: Buffer,
  updated_at: Date,
});

mongoose.model('Todo', Todo);

var User = new Schema({
  username: String,
  password: String,
  requirePasswordChange: { type: Boolean, default: false },
});

mongoose.model('User', User);

// CloudFoundry env vars
var mongoCFUri = cfenv.getAppEnv().getServiceURL('goof-mongo');
console.log(JSON.stringify(cfenv.getAppEnv()));

// Default Mongo URI is local
const DOCKER = process.env.DOCKER
if (DOCKER === '1') {
  var mongoUri = 'mongodb://goof-mongo/express-todo';
} else {
  var mongoUri = 'mongodb://localhost/express-todo';
}


// CloudFoundry Mongo URI
if (mongoCFUri) {
  mongoUri = mongoCFUri;
} else if (process.env.MONGOLAB_URI) {
  // Generic (plus Heroku) env var support
  mongoUri = process.env.MONGOLAB_URI;
} else if (process.env.MONGODB_URI) {
  // Generic (plus Heroku) env var support
  mongoUri = process.env.MONGODB_URI;
}

console.log("Using Mongo URI " + mongoUri);

mongoose.connect(mongoUri);

// Only auto-provision admin in development mode with explicit environment variable
// Production deployments must manually create admin users with secure credentials
const AUTO_PROVISION_ADMIN = process.env.AUTO_PROVISION_ADMIN === 'true';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (AUTO_PROVISION_ADMIN && process.env.NODE_ENV !== 'production') {
  User = mongoose.model('User');
  
  // Validate that credentials are provided via environment variables
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    console.error('ERROR: AUTO_PROVISION_ADMIN is enabled but ADMIN_USERNAME or ADMIN_PASSWORD environment variables are not set.');
    console.error('Admin user will not be provisioned. Please set these environment variables or manually create an admin user.');
  } else {
    User.find({ username: ADMIN_USERNAME }).exec(function (err, users) {
      if (err) {
        console.error('Error checking for admin user:', err);
        return;
      }
      
      if (users.length === 0) {
        console.log('Auto-provisioning admin user (development mode only)');
        
        // Hash the password before storing
        bcrypt.hash(ADMIN_PASSWORD, 10, function(err, hashedPassword) {
          if (err) {
            console.error('Error hashing admin password:', err);
            return;
          }
          
          new User({ 
            username: ADMIN_USERNAME, 
            password: hashedPassword,
            requirePasswordChange: true 
          }).save(function (err, user, count) {
            if (err) {
              console.error('Error saving admin user:', err);
            } else {
              console.log('Admin user provisioned. Password change required on first login.');
            }
          });
        });
      }
    });
  }
} else if (AUTO_PROVISION_ADMIN && process.env.NODE_ENV === 'production') {
  console.warn('WARNING: AUTO_PROVISION_ADMIN is not allowed in production mode. Admin users must be created manually with secure credentials.');
} else {
  console.log('Admin auto-provisioning disabled. Admin users must be created manually.');
}