const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const path = require('path');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => console.log('Database connected'));

// CORS configuration to allow frontend requests
const corsOptions = {
  origin: [
    'http://localhost:3000',  // Local frontend URL
    'http://46.101.252.244',  // Production frontend URL
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

// Middleware
app.use(express.json());
app.use(cors(corsOptions));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// User Schema and Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', userSchema);

// File Schema and Model
const fileSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  originalname: { type: String, required: true },
  tags: [String],
  views: { type: Number, default: 0 },
  sharedLink: { type: String, unique: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
});
const File = mongoose.model('File', fileSchema);

// File Upload Setup
const storage = multer.diskStorage({
  destination: './uploads',
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'video/mp4'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only images and videos are allowed.'));
    }
  },
});

// Routes
// Register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(403).json({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Upload File
app.post('/upload', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }

  try {
    const token = req.headers.authorization?.split(' ')[1];  // Get the token from Authorization header
    const decoded = jwt.verify(token, process.env.JWT_SECRET);  // Decode the token
    const userId = decoded.id;  // Get the user ID from the token

    const sharedLink = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;

    const file = new File({
      filename: req.file.filename,
      originalname: req.file.originalname,
      tags: req.body.tags ? req.body.tags.split(',') : [],
      sharedLink: sharedLink,
      user: userId,  // Save the user ID who uploaded the file
    });

    await file.save();
    res.json({ message: 'File uploaded successfully', file });
  } catch (err) {
    console.error('Error saving file:', err);
    res.status(500).json({ error: err.message });
  }
});
  
  

// Fetch Files
app.get('/files', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];  // Get the token from Authorization header
    const decoded = jwt.verify(token, process.env.JWT_SECRET);  // Decode the token
    const userId = decoded.id;  // Get the user ID from the token

    // Fetch files that belong to the logged-in user
    const files = await File.find({ user: userId });
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Share File
app.post('/share/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ message: 'File not found' });

    const link = `${req.protocol}://${req.get('host')}/uploads/${file.filename}`;
    file.sharedLink = link;
    await file.save();
    res.json({ message: 'File shared successfully', link });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Track Views
app.get('/view/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ message: 'File not found' });

    file.views += 1;
    await file.save();
    res.sendFile(path.resolve(__dirname, 'uploads', file.filename));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start Server
app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));