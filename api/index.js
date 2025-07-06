require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const User = require('./models/User');
const Post = require('./models/Post');
const bcrypt = require('bcryptjs');
const app = express();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const uploadMiddleware = multer({ dest: 'uploads/' });
const fs = require('fs');

const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET || 'default_jwt_secret';

// CORS configuration
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'https://mern-blog-master-sooty.vercel.app';
const corsOptions = {
  origin: 'https://mern-blog-master-sooty.vercel.app',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));



app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(__dirname + '/uploads'));

// Connect to MongoDB
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/BLOG_DB';
mongoose.connect(MONGO_URI)
  .then(() => console.log('database connected..'))
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// Register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.json(userDoc);
  } catch (e) {
    console.log(e);
    res.status(400).json(e);
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.findOne({ username });
    if (!userDoc) {
      return res.status(400).json('wrong credentials');
    }
    const passOk = bcrypt.compareSync(password, userDoc.password);
    if (passOk) {
      jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
        if (err) {
          console.error(err);
          return res.status(500).json('internal error');
        }
        res.cookie('token', token, {
  httpOnly: true,
  sameSite: 'none',
  secure: true,
}).json({
  id: userDoc._id,
  username,
});

      });
    } else {
      res.status(400).json('wrong credentials');
    }
  } catch (e) {
    console.error(e);
    res.status(500).json('internal error');
  }
});

// Profile
app.get('/profile', (req, res) => {
  const { token } = req.cookies;
  if (!token) return res.status(401).json('missing token');
  jwt.verify(token, secret, {}, (err, info) => {
    if (err) return res.status(401).json('invalid or expired token');
    res.json(info);
  });
});

// Logout
app.post('/logout', (req, res) => {
 res.cookie('token', '', {
  httpOnly: true,
  sameSite: 'none',
  secure: true,
  expires: new Date(0),
}).json('ok');

});

// Create Post
app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
  let newPath = '';
  if (req.file) {
    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    newPath = path + '.' + ext;
    fs.renameSync(path, newPath);
  }
  const { token } = req.cookies;
  if (!token) return res.status(401).json('missing token');
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(401).json('invalid or expired token');
    try {
      const { title, summary, content } = req.body;
      const postDoc = await Post.create({
        title,
        summary,
        content,
        cover: newPath,
        author: info.id,
      });
      res.json(postDoc);
    } catch (e) {
      console.error(e);
      res.status(500).json('internal error');
    }
  });
});

// Update Post
app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
  let newPath = null;
  if (req.file) {
    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    newPath = path + '.' + ext;
    fs.renameSync(path, newPath);
  }
  const { token } = req.cookies;
  if (!token) return res.status(401).json('missing token');
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(401).json('invalid or expired token');
    try {
      const { id, title, summary, content } = req.body;
      const postDoc = await Post.findById(id);
      if (!postDoc) return res.status(404).json('post not found');
      const isAuthor = postDoc.author.toString() === info.id;
      if (!isAuthor) {
        return res.status(403).json('you are not the author');
      }
      postDoc.title = title;
      postDoc.summary = summary;
      postDoc.content = content;
      if (newPath) postDoc.cover = newPath;
      await postDoc.save();
      res.json(postDoc);
    } catch (e) {
      console.error(e);
      res.status(500).json('internal error');
    }
  });
});

// Get Posts
app.get('/post', async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('author', ['username'])
      .sort({ createdAt: -1 })
      .limit(20);
    res.json(posts);
  } catch (e) {
    console.error(e);
    res.status(500).json('internal error');
  }
});

// Get Single Post
app.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const postDoc = await Post.findById(id).populate('author', ['username']);
    if (!postDoc) return res.status(404).json('post not found');
    res.json(postDoc);
  } catch (e) {
    console.error(e);
    res.status(500).json('internal error');
  }
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`server running on port ${port}...`);
});
