const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const ejs = require('ejs');
const cookieParser = require('cookie-parser'); // Import cookie-parser

const { promisify } = require('util');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors({
  origin: 'http://127.0.0.1:5500',
  credentials: true
}));

app.options('*', cors({
  origin: 'http://127.0.0.1:5500',
  credentials: true
}));
app.use(cookieParser()); // Use cookie-parser middleware

// MySQL Connection Pool
const pool = mysql.createPool({
    host: "",
    user: "",
    password: "",
    database: ""
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

const productPageTemplate = `
  <html>
    <head>
      <title><%= product.name %></title>
    </head>
    <body>
      <h1><%= product.name %></h1>
      <img src="<%= product.image_url %>" alt="<%= product.name %>">
      <p><%= product.description %></p>
      <p><%= product.price %></p>
    </body>
  </html>
`;

pool.execute(userSchema);


app.get('/page/:id', async (req, res) => {
  const productId = req.params.id;
  console.log('Received request for product page ID:', productId);

  try {
    const [results] = await pool.query('SELECT * FROM products WHERE id = ?', [productId]);
    if (results.length === 0) {
      res.sendStatus(404);
      return;
    }
    const product = results[0];
    const html = ejs.render(productPageTemplate, { product });
    res.set('Content-Type', 'text/html');
    res.send(html);
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});




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

    const token = jwt.sign({ id: user.id }, 'secret', { expiresIn: '1h' });

    // Save token in cookie
    res.cookie('token', token, { expires: 0 });




    res.json({ message: 'Login successful' });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

app.post('/logout', (req, res) => {
  // Clear token cookie
  res.clearCookie('token');

  res.json({ message: 'Logout successful' });
});

// Authentication middleware
const authenticate = async (req, res, next) => {
  const token = req.cookies.token; // Get token from cookie

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = await verifyAsync(token, 'secret');
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE id = ?',
      [decoded.id]
    );
    if (rows.length === 0) {
      throw new Error('Unauthorized');
    }
    req.user = rows[0];
    next();
  } catch (err) {
    // Clear token cookie if verification fails
    res.clearCookie('token');
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
