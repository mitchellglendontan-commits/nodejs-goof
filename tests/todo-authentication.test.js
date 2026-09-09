const tap = require('tap');
const path = require('path');

// Mock mongoose before any requires
const mockTodoFind = tap.mock('../routes/index.js', {
  mongoose: {
    model: function(name) {
      if (name === 'Todo') {
        return {
          find: function() {
            return {
              sort: function() {
                return {
                  exec: function(callback) {
                    callback(null, []);
                  }
                };
              }
            };
          },
          findById: function(id, callback) {
            const mockDoc = {
              _id: id,
              content: Buffer.from('test todo'),
              updated_at: new Date(),
              remove: function(cb) {
                cb(null, this);
              },
              save: function(cb) {
                cb(null, this);
              }
            };
            callback(null, mockDoc);
          }
        };
      }
      if (name === 'User') {
        return {
          find: function(query, callback) {
            callback(null, []);
          }
        };
      }
    }
  }
});

const routes = require('../routes');

// Helper function to create test app with routes
function createTestApp() {
  const app = express();
  
  app.use(session({
    secret: 'test-secret',
    name: 'test.sid',
    cookie: { path: '/' },
    resave: false,
    saveUninitialized: true
  }));
  
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(fileUpload());
  
  // Set up view engine (minimal setup for testing)
  app.set('view engine', 'ejs');
  app.set('views', __dirname + '/../views');
  
  // Apply routes exactly as in app.js (after fix)
  app.use(routes.current_user);
  app.get('/login', routes.login);
  app.post('/login', routes.loginHandler);
  app.get('/logout', routes.logout);
  app.get('/admin', routes.isLoggedIn, routes.admin);
  app.get('/account_details', routes.isLoggedIn, routes.get_account_details);
  app.post('/account_details', routes.isLoggedIn, routes.save_account_details);
  app.get('/', routes.isLoggedIn, routes.index);
  app.post('/create', routes.isLoggedIn, routes.create);
  app.get('/destroy/:id', routes.isLoggedIn, routes.destroy);
  app.get('/edit/:id', routes.isLoggedIn, routes.edit);
  app.post('/update/:id', routes.isLoggedIn, routes.update);
  app.post('/import', routes.isLoggedIn, routes.import);
  
  return app;
}

// Helper to make requests
function makeRequest(app, method, path, options = {}) {
  return new Promise((resolve, reject) => {
    const req = {
      method: method,
      url: path,
      headers: options.headers || {},
      session: options.session || {},
      body: options.body || {},
      params: options.params || {},
      files: options.files || null,
      query: options.query || {}
    };
    
    const res = {
      statusCode: 200,
      headers: {},
      body: '',
      status: function(code) {
        this.statusCode = code;
        return this;
      },
      send: function(data) {
        this.body = data;
        resolve(this);
        return this;
      },
      json: function(data) {
        this.body = JSON.stringify(data);
        resolve(this);
        return this;
      },
      redirect: function(location) {
        this.statusCode = 302;
        this.headers['Location'] = location;
        this.body = location;
        resolve(this);
        return this;
      },
      setHeader: function(name, value) {
        this.headers[name] = value;
        return this;
      },
      render: function(view, data) {
        this.body = JSON.stringify({ view, data });
        resolve(this);
        return this;
      }
    };
    
    // Find matching route and execute
    const stack = app._router.stack;
    let matched = false;
    
    for (let layer of stack) {
      if (layer.route && layer.route.path === path && layer.route.methods[method.toLowerCase()]) {
        matched = true;
        const handlers = layer.route.stack.map(l => l.handle);
        
        let index = 0;
        const next = (err) => {
          if (err) {
            res.statusCode = 500;
            res.body = err.message;
            resolve(res);
            return;
          }
          
          if (index < handlers.length) {
            const handler = handlers[index++];
            try {
              handler(req, res, next);
            } catch (e) {
              res.statusCode = 500;
              res.body = e.message;
              resolve(res);
            }
          }
        };
        
        next();
        break;
      }
    }
    
    if (!matched) {
      res.statusCode = 404;
      res.body = 'Not Found';
      resolve(res);
    }
  });
}

tap.test('Todo Authentication Security Tests', (t) => {
  
  t.test('unauthenticated access to index (/) should redirect to login', async (t) => {
    const app = createTestApp();
    const res = await makeRequest(app, 'GET', '/', {
      session: { loggedIn: 0 }
    });
    
    t.equal(res.statusCode, 302, 'should return 302 redirect');
    t.equal(res.headers['Location'], '/login', 'should redirect to /login');
    t.end();
  });
  
  t.test('unauthenticated POST to /create should redirect to login', async (t) => {
    const app = createTestApp();
    const res = await makeRequest(app, 'POST', '/create', {
      session: { loggedIn: 0 },
      body: { content: 'malicious todo' }
    });
    
    t.equal(res.statusCode, 302, 'should return 302 redirect');
    t.equal(res.headers['Location'], '/login', 'should redirect to /login');
    t.end();
  });
  
  t.test('unauthenticated GET to /destroy/:id should redirect to login', async (t) => {
    const app = createTestApp();
    const testId = '507f1f77bcf86cd799439011';
    const res = await makeRequest(app, 'GET', `/destroy/${testId}`, {
      session: { loggedIn: 0 }
    });
    
    t.equal(res.statusCode, 302, 'should return 302 redirect');
    t.equal(res.headers['Location'], '/login', 'should redirect to /login and prevent deletion');
    t.end();
  });
  
  t.test('unauthenticated GET to /edit/:id should redirect to login', async (t) => {
    const app = createTestApp();
    const testId = '507f1f77bcf86cd799439011';
    const res = await makeRequest(app, 'GET', `/edit/${testId}`, {
      session: { loggedIn: 0 }
    });
    
    t.equal(res.statusCode, 302, 'should return 302 redirect');
    t.equal(res.headers['Location'], '/login', 'should redirect to /login');
    t.end();
  });
  
  t.test('unauthenticated POST to /update/:id should redirect to login', async (t) => {
    const app = createTestApp();
    const testId = '507f1f77bcf86cd799439011';
    const res = await makeRequest(app, 'POST', `/update/${testId}`, {
      session: { loggedIn: 0 },
      body: { content: 'malicious update' }
    });
    
    t.equal(res.statusCode, 302, 'should return 302 redirect');
    t.equal(res.headers['Location'], '/login', 'should redirect to /login and prevent update');
    t.end();
  });
  
  t.test('unauthenticated POST to /import should redirect to login', async (t) => {
    const app = createTestApp();
    const res = await makeRequest(app, 'POST', '/import', {
      session: { loggedIn: 0 },
      files: {
        importFile: {
          data: Buffer.from('test todo\n'),
          name: 'test.txt'
        }
      }
    });
    
    t.equal(res.statusCode, 302, 'should return 302 redirect');
    t.equal(res.headers['Location'], '/login', 'should redirect to /login and prevent import');
    t.end();
  });
  
  t.test('authenticated access to index (/) should succeed', async (t) => {
    const app = createTestApp();
    const res = await makeRequest(app, 'GET', '/', {
      session: { loggedIn: 1 }
    });
    
    t.equal(res.statusCode, 200, 'should return 200 OK');
    t.notEqual(res.headers['Location'], '/login', 'should not redirect to login');
    t.end();
  });
  
  t.test('authenticated POST to /create should succeed', async (t) => {
    const app = createTestApp();
    
    // Override Todo save to track if it was called
    let saveCalled = false;
    const originalModel = mongoose.model;
    mongoose.model = function(name) {
      if (name === 'Todo') {
        return function(data) {
          this.content = data.content;
          this.updated_at = data.updated_at;
          this.save = function(callback) {
            saveCalled = true;
            callback(null, this, 1);
          };
          return this;
        };
      }
      return originalModel(name);
    };
    
    const res = await makeRequest(app, 'POST', '/create', {
      session: { loggedIn: 1 },
      body: { content: 'legitimate todo' }
    });
    
    // Restore original
    mongoose.model = originalModel;
    
    t.notEqual(res.statusCode, 302, 'should not redirect to login');
    t.notEqual(res.headers['Location'], '/login', 'should not redirect to login page');
    t.end();
  });
  
  t.test('isLoggedIn middleware should reject when session.loggedIn is not 1', (t) => {
    const testCases = [
      { loggedIn: 0, desc: 'loggedIn = 0' },
      { loggedIn: undefined, desc: 'loggedIn = undefined' },
      { loggedIn: null, desc: 'loggedIn = null' },
      { loggedIn: 2, desc: 'loggedIn = 2' },
      { loggedIn: '1', desc: 'loggedIn = "1" (string)' },
      { loggedIn: true, desc: 'loggedIn = true (boolean)' }
    ];
    
    testCases.forEach(testCase => {
      t.test(`should reject when ${testCase.desc}`, (t) => {
        const req = { session: { loggedIn: testCase.loggedIn } };
        const res = {
          redirect: function(location) {
            t.equal(location, '/login', 'should redirect to /login');
            t.end();
          }
        };
        const next = () => {
          t.fail('next() should not be called for unauthenticated request');
          t.end();
        };
        
        routes.isLoggedIn(req, res, next);
      });
    });
    
    t.end();
  });
  
  t.test('isLoggedIn middleware should allow when session.loggedIn is exactly 1', (t) => {
    const req = { session: { loggedIn: 1 } };
    const res = {
      redirect: function(location) {
        t.fail('redirect() should not be called for authenticated request');
        t.end();
      }
    };
    const next = () => {
      t.pass('next() should be called for authenticated request');
      t.end();
    };
    
    routes.isLoggedIn(req, res, next);
  });
  
  t.test('all Todo CRUD routes should have authentication middleware', (t) => {
    const app = createTestApp();
    const protectedRoutes = [
      { method: 'get', path: '/' },
      { method: 'post', path: '/create' },
      { method: 'get', path: '/destroy/:id' },
      { method: 'get', path: '/edit/:id' },
      { method: 'post', path: '/update/:id' },
      { method: 'post', path: '/import' }
    ];
    
    protectedRoutes.forEach(route => {
      const layer = app._router.stack.find(l => 
        l.route && 
        l.route.path === route.path && 
        l.route.methods[route.method]
      );
      
      t.ok(layer, `route ${route.method.toUpperCase()} ${route.path} should exist`);
      
      if (layer) {
        const handlers = layer.route.stack.map(l => l.handle);
        const hasAuthMiddleware = handlers.some(h => h === routes.isLoggedIn);
        t.ok(hasAuthMiddleware, `route ${route.method.toUpperCase()} ${route.path} should have isLoggedIn middleware`);
      }
    });
    
    t.end();
  });
  
  t.test('public routes should not require authentication', (t) => {
    const app = createTestApp();
    const publicRoutes = [
      { method: 'get', path: '/login' },
      { method: 'post', path: '/login' }
    ];
    
    publicRoutes.forEach(route => {
      const layer = app._router.stack.find(l => 
        l.route && 
        l.route.path === route.path && 
        l.route.methods[route.method]
      );
      
      t.ok(layer, `route ${route.method.toUpperCase()} ${route.path} should exist`);
      
      if (layer) {
        const handlers = layer.route.stack.map(l => l.handle);
        const hasAuthMiddleware = handlers.some(h => h === routes.isLoggedIn);
        t.notOk(hasAuthMiddleware, `route ${route.method.toUpperCase()} ${route.path} should NOT have isLoggedIn middleware`);
      }
    });
    
    t.end();
  });
  
  t.end();
});

tap.test('Pentest Reproduction Scenarios - Mitigated', (t) => {
  
  t.test('Step 2: Anonymous enumeration of all Todos should be blocked', async (t) => {
    const app = createTestApp();
    
    // Attempt to access index without authentication
    const res = await makeRequest(app, 'GET', '/', {
      session: {} // No loggedIn property
    });
    
    t.equal(res.statusCode, 302, 'should redirect instead of showing todos');
    t.equal(res.headers['Location'], '/login', 'should redirect to login page');
    t.notMatch(res.body, /todos/, 'response should not contain todo data');
    t.end();
  });
  
  t.test('Step 4: Anonymous deletion via GET /destroy/:id should be blocked', async (t) => {
    const app = createTestApp();
    const targetId = '507f1f77bcf86cd799439011';
    
    // Track if remove was called
    let removeCalled = false;
    const originalFindById = mockTodo.findById;
    mockTodo.findById = function(id, callback) {
      const mockDoc = {
        _id: id,
        content: 'target todo',
        remove: function(cb) {
          removeCalled = true;
          cb(null, this);
        }
      };
      callback(null, mockDoc);
    };
    
    const res = await makeRequest(app, 'GET', `/destroy/${targetId}`, {
      session: {} // No authentication
    });
    
    // Restore original
    mockTodo.findById = originalFindById;
    
    t.equal(res.statusCode, 302, 'should redirect');
    t.equal(res.headers['Location'], '/login', 'should redirect to login');
    t.notOk(removeCalled, 'Todo.remove() should NOT be called without authentication');
    t.end();
  });
  
  t.test('Step 5: Anonymous update via POST /update/:id should be blocked', async (t) => {
    const app = createTestApp();
    const targetId = '507f1f77bcf86cd799439011';
    
    // Track if save was called
    let saveCalled = false;
    const originalFindById = mockTodo.findById;
    mockTodo.findById = function(id, callback) {
      const mockDoc = {
        _id: id,
        content: 'original content',
        updated_at: new Date(),
        save: function(cb) {
          saveCalled = true;
          cb(null, this, 1);
        }
      };
      callback(null, mockDoc);
    };
    
    const res = await makeRequest(app, 'POST', `/update/${targetId}`, {
      session: {}, // No authentication
      body: { content: 'attacker controlled content' }
    });
    
    // Restore original
    mockTodo.findById = originalFindById;
    
    t.equal(res.statusCode, 302, 'should redirect');
    t.equal(res.headers['Location'], '/login', 'should redirect to login');
    t.notOk(saveCalled, 'Todo.save() should NOT be called without authentication');
    t.end();
  });
  
  t.test('Step 6: Anonymous import should be blocked', async (t) => {
    const app = createTestApp();
    
    // Track if save was called
    let saveCallCount = 0;
    const TodoConstructor = function(data) {
      this.content = data.content;
      this.updated_at = data.updated_at;
      this.save = function(callback) {
        saveCallCount++;
        callback(null, this, 1);
      };
      return this;
    };
    
    const originalModel = mongoose.model;
    mongoose.model = function(name) {
      if (name === 'Todo') return TodoConstructor;
      return originalModel(name);
    };
    
    const res = await makeRequest(app, 'POST', '/import', {
      session: {}, // No authentication
      files: {
        importFile: {
          data: Buffer.from('malicious todo 1\nmalicious todo 2\nmalicious todo 3\n'),
          name: 'malicious.txt'
        }
      }
    });
    
    // Restore original
    mongoose.model = originalModel;
    
    t.equal(res.statusCode, 302, 'should redirect');
    t.equal(res.headers['Location'], '/login', 'should redirect to login');
    t.equal(saveCallCount, 0, 'No todos should be saved without authentication');
    t.end();
  });
  
  t.test('Anonymous creation via POST /create should be blocked', async (t) => {
    const app = createTestApp();
    
    // Track if save was called
    let saveCalled = false;
    const TodoConstructor = function(data) {
      this.content = data.content;
      this.updated_at = data.updated_at;
      this.save = function(callback) {
        saveCalled = true;
        callback(null, this, 1);
      };
      return this;
    };
    
    const originalModel = mongoose.model;
    mongoose.model = function(name) {
      if (name === 'Todo') return TodoConstructor;
      return originalModel(name);
    };
    
    const res = await makeRequest(app, 'POST', '/create', {
      session: {}, // No authentication
      body: { content: 'attacker todo' }
    });
    
    // Restore original
    mongoose.model = originalModel;
    
    t.equal(res.statusCode, 302, 'should redirect');
    t.equal(res.headers['Location'], '/login', 'should redirect to login');
    t.notOk(saveCalled, 'Todo should NOT be created without authentication');
    t.end();
  });
  
  t.end();
});
