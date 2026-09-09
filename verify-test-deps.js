// Verification script to check if test dependencies load correctly
try {
  const tap = require('tap');
  console.log('✓ tap module loaded successfully');
  
  const routes = require('./routes/index.js');
  console.log('✓ routes module loaded successfully');
  
  // Check if required exports exist
  if (typeof routes.isLoggedIn === 'function') {
    console.log('✓ routes.isLoggedIn is a function');
  } else {
    console.log('✗ routes.isLoggedIn is not a function');
  }
  
  if (typeof routes.import === 'function') {
    console.log('✓ routes.import is a function');
  } else {
    console.log('✗ routes.import is not a function');
  }
  
  const moment = require('moment');
  console.log('✓ moment module loaded successfully');
  console.log('  moment version:', moment.version);
  
  console.log('\n✓ All dependencies loaded successfully');
  console.log('✓ Test file should be executable');
  
  process.exit(0);
} catch (error) {
  console.error('✗ Error loading dependencies:', error.message);
  process.exit(1);
}
