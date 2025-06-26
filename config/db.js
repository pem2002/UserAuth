const pgpInit = require('pg-promise');
require('dotenv').config();

const pgp = pgpInit();

// Set SSL to true if on production (e.g., Render), otherwise false
const isProduction = 'production';

const db = pgp({
  host: process.env.DB_HOST,
  port: 5432,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  ssl: isProduction ? { rejectUnauthorized: false } : false, // ✅ handles both local + Render
});

module.exports = db;
