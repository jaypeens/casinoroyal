const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');  // changed here
const path = require('path');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session setup
app.use(session({
  secret: 'your_secret_key_here',
  resave: false,
  saveUninitialized: false,
}));

// Serve static files from public folder
app.use(express.static(path.join(__dirname, 'public')));

// Mock user database (replace with real DB in production)
const users = [
  { id: 1, username: 'owner', passwordHash: bcrypt.hashSync('ownerpass', 10), role: 'owner' },
  { id: 2, username: 'user1', passwordHash: bcrypt.hashSync('userpass', 10), role: 'user' },
];

// Middleware to require login
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login.html');
  next();
}

// Middleware to require owner role
function requireOwner(req, res, next) {
  const user = users.find(u => u.id === req.session.userId);
  if (!user || user.role !== 'owner') return res.status(403).send('Forbidden');
  next();
}

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).send('Invalid credentials');
  if (!bcrypt.compareSync(password, user.passwordHash)) return res.status(401).send('Invalid credentials');
  req.session.userId = user.id;
  res.redirect('/casino.html');
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

// Profile route
app.get('/profile', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public/profile.html'));
});

// Password change API
app.post('/change-password', requireLogin, (req, res) => {
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).send('Unauthorized');
  const { oldPassword, newPassword } = req.body;
  if (!bcrypt.compareSync(oldPassword, user.passwordHash)) return res.status(400).send('Old password incorrect');
  user.passwordHash = bcrypt.hashSync(newPassword, 10);
  res.send('Password updated');
});

// Owner-only: view users
app.get('/owner/users', requireOwner, (req, res) => {
  res.json(users.map(u => ({ id: u.id, username: u.username, role: u.role })));
});

// Root redirect to login
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

app.listen(process.env.PORT || 3000);