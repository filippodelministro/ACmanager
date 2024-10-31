'use strict';

/* Data Access Object (DAO) module for accessing users data */

const db = require('./db');
const crypto = require('crypto');

// This function returns user's information given its id.
exports.getUserById = (id) => {
  return new Promise((resolve, reject) => {
    const sql = 'SELECT * FROM users WHERE id=?';
    db.get(sql, [id], (err, row) => {
      if (err)
        reject(err);
      else if (row === undefined)
        resolve({ error: 'User not found.' });
      else {
        // By default, the local strategy looks for "username": 
        // for simplicity, instead of using "email", we create an object with that property.
        const user = { id: row.id, username: row.email, name: row.name }
        resolve(user);
      }
    });
  });
};

// This function is used at log-in time to verify username and password.
exports.getUser = (email, password) => {
  return new Promise((resolve, reject) => {
    const sql = 'SELECT * FROM users WHERE email=?';
    db.get(sql, [email], (err, row) => {
      if (err) {
        reject(err);
      } else if (row === undefined) {
        resolve(false);
      }
      else {
        const user = { id: row.id, username: row.email, name: row.name };

        // Check the hashes with an async call, this operation may be CPU-intensive (and we don't want to block the server)
        crypto.scrypt(password, row.salt, 32, function (err, hashedPassword) { // WARN: it is 64 and not 32 (as in the week example) in the DB
          if (err) reject(err);
          if (!crypto.timingSafeEqual(Buffer.from(row.hash, 'hex'), hashedPassword)) // WARN: it is hash and not password (as in the week example) in the DB
            resolve(false);
          else
            resolve(user);
        });
      }
    });
  });
};


exports.createUser = (credentials) => {
  return new Promise((resolve, reject) => {
    const sqlCheck = 'SELECT * FROM users WHERE name=?';
    const sqlInsert = 'INSERT INTO users (email, name, hash, salt) VALUES (?, ?, ?, ?)';
  
    console.log("[daousers.js]> Check if user exists:", credentials);

    const username = credentials.username;
    const password = credentials.password;

    // console.log("[daousers.js]> usernmae:", username);
    // console.log("[daousers.js]> passowrd:", password);

    db.get(sqlCheck, [username], (err, row) => {
      if (err) {
        console.error("Error querying database for user:", err);
        return reject(err);
      } else if (row) {
        console.log("User already exists:", username);
        return resolve(false); // User already exists
      }

      // User doesn't exist, so we can insert a new user
      db.run(sqlInsert, [username, username, password, password], function(err) {
        if (err) {
          console.error("Error inserting new user:", err);
          return reject(err);
        }
        
        console.log("New user created with ID:", this.lastID);
        return resolve(true); // User created successfully
      });
    });
  });
};