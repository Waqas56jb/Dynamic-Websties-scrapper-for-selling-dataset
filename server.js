const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer'); // For file uploads
const path = require('path');
const db = require('./db');

const app = express();
const port = 5000;

// Middleware
app.use(bodyParser.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // Serve uploaded files

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname); // Unique filename
  }
});
const upload = multer({ storage });

// Signup API with file upload
app.post('/api/signup', upload.single('profile_photo'), async (req, res) => {
  const { name, email, phone, password } = req.body;
  const profile_photo = req.file ? `/uploads/${req.file.filename}` : null; // File path
  const hashedPassword = await bcrypt.hash(password, 8);

  const sql = `INSERT INTO users (name, email, phone, password, profile_photo) VALUES (?, ?, ?, ?, ?)`;
  db.query(sql, [name, email, phone, hashedPassword, profile_photo], (err, result) => {
    if (err) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(201).json({ message: 'User registered successfully' });
  });
});

 
// Logout API
app.post('/api/logout', (req, res) => {
  const { userId } = req.body;

  const sql = `UPDATE users SET device_token = NULL WHERE id = ?`;
  db.query(sql, [userId], (err, result) => {
    if (err) throw err;
    res.status(200).json({ message: 'Logged out successfully' });
  });
});

// Fetch Profile API
app.get('/api/user/:id', (req, res) => {
  const userId = req.params.id;

  const sql = `SELECT * FROM users WHERE id = ?`;
  db.query(sql, [userId], (err, result) => {
    if (err) throw err;

    if (result.length > 0) {
      res.status(200).json({ user: result[0] });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  });
});

// Update Profile API with file upload
app.put('/api/user/:id', upload.single('profile_photo'), (req, res) => {
  const userId = req.params.id;
  const { name, bio } = req.body;
  const profile_photo = req.file ? `/uploads/${req.file.filename}` : null; // File path

  const sql = `UPDATE users SET name = ?, bio = ?, profile_photo = ? WHERE id = ?`;
  db.query(sql, [name, bio, profile_photo, userId], (err, result) => {
    if (err) throw err;
    res.status(200).json({ message: 'Profile updated successfully' });
  });
});

// Start server
app.listen(port, () => {
  console.log(`Backend API running on http://localhost:${port}`);
});