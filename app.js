require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 5000;

// Path to posts.json
const POSTS_FILE = path.join(__dirname, 'public', 'posts.json');
const JWT_SECRET = process.env.JWT_SECRET;
// Middleware
app.use((req, res, next) => {
  if (!path.extname(req.path)) {
    const filePath = path.join(__dirname, 'public', req.path + '.html');
    if (fs.existsSync(filePath)) {
      return res.sendFile(filePath);
    }
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());

// Serve index.html on root path
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

function checkAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Get all blog posts
app.get('/posts', (req, res) => {
  try {
    const data = fs.readFileSync(POSTS_FILE, 'utf-8');
    res.json(JSON.parse(data));
  } catch (err) {
    res.status(500).json({ error: 'Failed to read posts file.' });
  }
});

// Add a new blog post
app.post('/add-post', checkAuth, (req, res) => {
  try {
    const data = fs.readFileSync(POSTS_FILE, 'utf-8');
    const posts = JSON.parse(data);
    const slug = slugify(req.body.title);
    const newPost = {
      id: (parseInt(posts[posts.length - 1]?.id || '0') + 1).toString(), 
      date: new Date().toLocaleDateString('en-US', {
        year: 'numeric', month: 'long', day: 'numeric'
      }), 
      ...req.body,
      slug,
    };

    posts.push(newPost);
    fs.writeFileSync(POSTS_FILE, JSON.stringify(posts, null, 2));
    res.json({ status: 'success', id: newPost.id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save post.' });
  }
});

function slugify(text) {
  return text
    .toString()
    .toLowerCase()
    .trim() 
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-');
}

app.put('/api/blogs/:id', checkAuth, (req, res) => {
  try {
  const blogId = parseInt(req.params.id, 10);
  const updatedBlog = req.body;

  const data = fs.readFileSync(POSTS_FILE, 'utf-8');
    const posts = JSON.parse(data);
    const index = posts.findIndex(p => p.id == blogId);

    if (index === -1) return res.status(404).send('Blog not found');

    posts[index] = updatedBlog;

    fs.writeFileSync(POSTS_FILE, JSON.stringify(posts, null, 2));
    res.json({ status: 'success', id: updatedBlog.id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save post.' });
  }
});

app.delete('/api/blogs/:id', checkAuth, (req, res) => {
  try {
    const blogId = parseInt(req.params.id, 10);

    const data = fs.readFileSync(POSTS_FILE, 'utf-8');
    const posts = JSON.parse(data);

    const index = posts.findIndex(post => post.id == blogId);
    if (index === -1) {
      return res.status(404).json({ error: 'Blog not found' });
    }

    posts.splice(index, 1); // Remove the blog
    fs.writeFileSync(POSTS_FILE, JSON.stringify(posts, null, 2));

    res.json({ status: 'success', message: `Blog with ID ${blogId} deleted.` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete blog.' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  const ADMIN_USERNAME  = process.env.ADMIN_USERNAME;
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

  if (username !== ADMIN_USERNAME) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  bcrypt.compare(password, ADMIN_PASSWORD, (err, result) => {
    if (!result) return res.status(401).json({ error: 'Invalid credentials' });

    const JWT_EXPIRY = process.env.JWT_EXPIRY;

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
    res.json({ token });
  });
});

const tokenBlacklist = new Set();

app.post('/api/logout', checkAuth, (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'No token provided' });

  if(isTokenBlacklisted(token)) {
    return res.status(403).json({ message: 'Token is already blacklisted' });
  }

  tokenBlacklist.add(token);
  res.json({ message: 'Logged out successfully' });
});

// Middleware to check if token is blacklisted
function isTokenBlacklisted(token) {
  return tokenBlacklist.has(token);
}

app.get('/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'post-details.html'));
});

app.post('/api/add-script', checkAuth, async (req, res) => {
  const { script, pin, position } = req.body;
  const ADD_SCRIPT_KEY = process.env.ADD_SCRIPT_KEY;

  try {
    if (script.startsWith('<script>')) {
      return res.status(403).json({ error: 'Error: Script content should not start with <script> tag.' });
    }

    const isMatch = await bcrypt.compare(pin, ADD_SCRIPT_KEY);

    if (!isMatch) {
      return res.status(403).json({ error: 'Error: Incorrect pin' });
    }

    const indexPath = path.join(__dirname, 'public', 'index.html');
    let indexHtml = fs.readFileSync(indexPath, 'utf-8');

    const scriptWithTag = `\n<script>\n${script}\n</script>\n`;

    if (indexHtml.includes(scriptWithTag)) {
      return res.status(400).json({ error: 'Error: Script already present.' });
    }

    if (position == 'head') {
      indexHtml = indexHtml.replace('</head>', `${scriptWithTag}</head>`);
    } else if (position == 'body') {
      indexHtml = indexHtml.replace('</body>', `${scriptWithTag}<body>`);
    } else {
      return res.status(400).json({ error: 'Error: Invalid position specified.' });
    }

    fs.writeFileSync(indexPath, indexHtml, 'utf-8');

    return res.json({ status: 'success', message: 'Script added successfully.' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ status: 'error', message: 'Failed to update index.html' });
  }
});

app.get('/api/verify-token', checkAuth, (req, res) => {
  res.sendStatus(200);
});

app.listen(PORT, () => {
  console.log(`Server running on Port ${PORT}`);
});