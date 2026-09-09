var typeorm = require("typeorm");
var EntitySchema = typeorm.EntitySchema;

const Users = require("./entity/Users")

// Use environment variables for database credentials
// Never use hardcoded credentials in production
const dbConfig = {
  name: "mysql",
  type: "mysql",
  host: process.env.MYSQL_HOST || "localhost",
  port: parseInt(process.env.MYSQL_PORT || "3306", 10),
  username: process.env.MYSQL_USER || "acme_app",
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE || "acme",
  synchronize: true,
  "logging": true,
  entities: [
    new EntitySchema(Users)
  ]
};

// Validate that password is provided
if (!dbConfig.password) {
  console.error('CRITICAL: MYSQL_PASSWORD environment variable is not set');
  console.error('Database connection cannot be established without credentials');
  process.exit(1);
}

typeorm.createConnection(dbConfig).then(() => {

  const dbConnection = typeorm.getConnection('mysql')

  const repo = dbConnection.getRepository("Users")
  return repo
}).then((repo) => {


  console.log('Seeding 2 users to MySQL users table: Liran (role: user), Simon (role: admin')
  const inserts = [
    repo.insert({
      name: "Liran",
      address: "IL",
      role: "user"
    }),
    repo.insert({
      name: "Simon",
      address: "UK",
      role: "admin"
    })
  ];

  return Promise.all(inserts)
}).catch((err) => {
  console.error('failed connecting and seeding users to the MySQL database')
  console.error(err)
})