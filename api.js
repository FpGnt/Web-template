const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());

// MySQL Connection Pool
const pool = mysql.createPool({
    host: "server42.areait.lv",
    user: "kkbopro_automation",
    password: "+FnQDPmAg7$D",
    database: "kkbopro_map"
});

// Promisify bcrypt and jwt functions
const hashAsync = promisify(bcrypt.hash);
const compareAsync = promisify(bcrypt.compare);
const signAsync = promisify(jwt.sign);
const verifyAsync = promisify(jwt.verify);

// User model
const userSchema = `
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    password VARCHAR(255)
  );
`;
pool.execute(userSchema);

// Registration endpoint
app.post('/register', async (req, res) => {
  try {
    // Get user credentials from request body
    
    const { email, password } = req.body;

    console.log(req)

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user to database
    const [result] = await pool.execute(
      'INSERT INTO users (email, password) VALUES (?, ?)',
      [email, hashedPassword]
    );

    // Return success message with user ID
    res.status(201).json({ message: 'User created', id: result.insertId });
  } catch (error) {
    // Handle errors
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ error: 'Email already in use' });
    } else {
      console.error(error);
      res.status(500).send({ message: 'Internal server error' });
    }
  }
});



// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    if (rows.length === 0) {
      throw new Error('Invalid credentials');
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new Error('Invalid credentials');
    }

    const token = await signAsync({ email }, 'secret', { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});


// Authentication middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = await verifyAsync(token, 'secret');
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE email = ?',
      [decoded.email]
    );
    if (rows.length === 0) {
      throw new Error('Unauthorized');
    }
    req.user = rows[0];
    next();
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
};

// Protected endpoint
app.get('/profile', authenticate, (req, res) => {
  res.json({ email: req.user.email });
});

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
