#!/bin/bash
# MySQL initialization script
# This script runs automatically when the MySQL container is first created
# It creates a least-privilege application user with only necessary permissions

set -e

echo "Creating application user with limited privileges..."

# The MYSQL_USER and MYSQL_PASSWORD are automatically created by the MySQL image
# We just need to grant appropriate permissions to the application database

mysql -u root -p"${MYSQL_ROOT_PASSWORD}" <<-EOSQL
    -- Grant only necessary privileges to the application user
    -- The user ${MYSQL_USER} is already created by the MySQL image
    GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, ALTER, DROP, REFERENCES 
    ON ${MYSQL_DATABASE}.* 
    TO '${MYSQL_USER}'@'%';
    
    -- Explicitly deny dangerous privileges
    -- The application user should NOT have:
    -- - SUPER, PROCESS, FILE (server administration)
    -- - GRANT OPTION (privilege escalation)
    -- - RELOAD, SHUTDOWN (server control)
    -- - CREATE USER, SHOW DATABASES (security)
    
    FLUSH PRIVILEGES;
    
    SELECT CONCAT('Application user "', '${MYSQL_USER}', '" configured with limited privileges on database "', '${MYSQL_DATABASE}', '"') AS Status;
EOSQL

echo "Database initialization complete."
