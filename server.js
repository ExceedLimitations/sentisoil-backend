const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bcrypt = require('bcrypt');
const mysql = require('mysql');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// 1️⃣ CORRECT CORS middleware — must come BEFORE session
app.use(cors({
  origin: ['https://sentisoil.erides.site/'],
  credentials: true
}));

// 2️⃣ Parse incoming JSON
app.use(express.json());

app.use(session({
  name: 'connect.sid',
  secret: process.env.SESSION_SECRET || 'fallback-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',  // false for local development (use true for HTTPS)
    sameSite: 'none',  // helps with cross-origin requests
  }
}));

app.get('/', (req, res) => {
  res.send('✅ Sentisoil server is running.');
});

// Create DB connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, // or your actual MySQL password
  database: process.env.DB_NAME // replace with your actual DB name
});

// Connect to DB
db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err.message);
  } else {
    console.log('Connected to MySQL database.');
  }
});

app.get('/check-session', (req, res) => {
  if (req.session.user) {
    res.status(200).json({ loggedIn: true, user: req.session.user });
  } else {
    res.status(401).json({ loggedIn: false });
  }
});

app.get('/user-info', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  res.json(req.session.user);
});


// Add session to your login route
app.post('/login', (req, res) => {
  console.log('Received login request:', req.body); // 🔍 Add this line
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Username and password are required.");
  }

  const sql = 'SELECT * FROM users WHERE username = ?';

  db.query(sql, [username], (err, result) => {
    if (err) {
      console.error("Database query error:", err); 
      return res.status(500).send("Error logging in.");
    }

    if (result.length === 0) {
      return res.status(400).send("User not found.");
    }

    const user = result[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error("Bcrypt error:", err); 
        return res.status(500).send("Error checking password.");
      }

      if (!isMatch) {
        console.error("Incorrect password for user:", username); 
        return res.status(400).send("Incorrect password.");
      }

      req.session.user = {
        id: user.id,
        name: user.first_name + ' ' + user.last_name,  // Combine names if needed
        username: user.username,
        email: user.email,
        phone: user.contact,
        position: user.user_position,
        farm_address: user.farm_address,
        farm_owner: user.farm_owner,
        organization: user.organization,
        farm_name: user.farm_name
      };
      console.log('Session user data:', req.session.user);
      // Create session for the user
      console.log("Login successful for user:", username); // Log success
      res.status(200).send("Login successful!");
    });
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.log('Logout error:', err);
      return res.status(500).send('Logout failed.');
    }
    res.clearCookie('connect.sid');
    console.log('User logged out successfully');
    res.send('Logged out successfully');
  });
});

app.post('/signup', (req, res) => {
  const { firstName, lastName, username, contact, email, password, confirmPassword, farmOwner, userPosition, orgName, farmName, farmAddress } = req.body;

  if (password !== confirmPassword) {
      return res.status(400).send("Passwords do not match");
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  const sql = `
      INSERT INTO users (first_name, last_name, username, contact, email, password, farm_owner, user_position, organization, farm_name, farm_address)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(sql, [firstName, lastName, username, contact, email, hashedPassword, farmOwner, userPosition, orgName, farmName, farmAddress], (err, result) => {
      if (err) {
          console.error(err);
          return res.status(500).send("Error registering user.");
      }
      res.status(200).send("Signup successful!");
  });
});

const GROQ_API_KEY = process.env.GROQ_API_KEY; // Replace with your actual key

app.post('/ai-suggestions', async (req, res) => {
  const { zinc, npk, moisture, temperature } = req.body;

  const prompt = `Given this simulated soil data:
- Zinc level: ${zinc}
- NPK level: ${npk}
- Moisture: ${moisture}%
- Temperature: ${temperature}°C

Suggest 2-3 best actions a farmer should take to improve soil health. Respond with just the suggestions as a list.`;

  try {
    const response = await axios.post(
      'https://api.groq.com/openai/v1/chat/completions',
      {
        model: 'llama3-8b-8192',
        messages: [
          { role: 'system', content: 'You are a helpful AI soil expert.' },
          { role: 'user', content: prompt }
        ],
        temperature: 0.7
      },
      {
        headers: {
          'Authorization': `Bearer ${GROQ_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const aiText = response.data.choices[0].message.content;
    const suggestions = aiText.split('\n').filter(line => line.trim().length > 0);

    res.json({ suggestions });
  } catch (error) {
    console.error('Error fetching Groq API:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to get AI suggestions.' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT} or on Render`);
});

