const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = 8001;

// Middleware
app.use(express.json());
app.use(cors({
  origin: '*',
  credentials: false,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// MongoDB Connection
const MONGO_URL = process.env.MONGO_URL;
const DB_NAME = process.env.DB_NAME;

mongoose.connect(`${MONGO_URL}/${DB_NAME}`, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// JWT Secret
const SECRET_KEY = process.env.SECRET_KEY || require('crypto').randomBytes(32).toString('hex');
const ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24; // 24 hours

// Models
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  hashed_password: { type: String, required: true },
  created_at: { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
  tracking_id: { type: String, required: true, unique: true },
  customer_name: { type: String, required: true },
  customer_email: { type: String, required: true },
  customer_state: { type: String, required: true },
  customer_address: { type: String, required: true },
  product_name: { type: String, required: true },
  quantity: { type: Number, required: true },
  company_name: { type: String, required: true },
  company_address: { type: String, required: true },
  current_status: { type: String, default: 'confirmed' },
  status_history: [{
    status: String,
    timestamp: Date,
    note: String
  }],
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', adminSchema);
const Order = mongoose.model('Order', orderSchema);

// Helper Functions
const hashPassword = async (password) => {
  return await bcrypt.hash(password, 10);
};

const verifyPassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

const createAccessToken = (email) => {
  return jwt.sign(
    { sub: email },
    SECRET_KEY,
    { expiresIn: `${ACCESS_TOKEN_EXPIRE_MINUTES}m` }
  );
};

const generateTrackingId = () => {
  return `FXS-${require('crypto').randomBytes(6).toString('hex').toUpperCase()}`;
};

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ detail: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const admin = await Admin.findOne({ email: decoded.sub }).select('-hashed_password');
    
    if (!admin) {
      return res.status(401).json({ detail: 'Admin not found' });
    }
    
    req.admin = admin;
    next();
  } catch (err) {
    return res.status(401).json({ detail: 'Invalid token' });
  }
};

// Routes

// Admin Registration
app.post('/api/admin/register', [
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('name').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ detail: 'Invalid input', errors: errors.array() });
  }

  try {
    const { email, password, name } = req.body;

    // Check if admin exists
    const existing = await Admin.findOne({ email });
    if (existing) {
      return res.status(400).json({ detail: 'Email already registered' });
    }

    // Create admin
    const hashedPassword = await hashPassword(password);
    const admin = new Admin({
      email,
      name,
      hashed_password: hashedPassword
    });

    await admin.save();

    // Create token
    const access_token = createAccessToken(email);

    res.json({
      access_token,
      token_type: 'bearer',
      admin: {
        email: admin.email,
        name: admin.name,
        created_at: admin.created_at
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Admin Login
app.post('/api/admin/login', [
  body('email').isEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ detail: 'Invalid input', errors: errors.array() });
  }

  try {
    const { email, password } = req.body;

    // Find admin
    const admin = await Admin.findOne({ email });
    if (!admin || !(await verifyPassword(password, admin.hashed_password))) {
      return res.status(401).json({ detail: 'Incorrect email or password' });
    }

    // Create token
    const access_token = createAccessToken(email);

    res.json({
      access_token,
      token_type: 'bearer',
      admin: {
        email: admin.email,
        name: admin.name,
        created_at: admin.created_at
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Get Admin Profile
app.get('/api/admin/me', authenticateToken, async (req, res) => {
  res.json({
    email: req.admin.email,
    name: req.admin.name,
    created_at: req.admin.created_at
  });
});

// Create Order
app.post('/api/orders', authenticateToken, [
  body('customer_name').notEmpty(),
  body('customer_email').isEmail(),
  body('customer_state').notEmpty(),
  body('customer_address').notEmpty(),
  body('product_name').notEmpty(),
  body('quantity').isInt({ min: 1 }),
  body('company_name').notEmpty(),
  body('company_address').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ detail: 'Invalid input', errors: errors.array() });
  }

  try {
    const tracking_id = generateTrackingId();
    const now = new Date();

    const order = new Order({
      tracking_id,
      ...req.body,
      current_status: 'confirmed',
      status_history: [{
        status: 'confirmed',
        timestamp: now,
        note: 'Order created'
      }],
      created_at: now,
      updated_at: now
    });

    await order.save();
    res.json(order);
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Get All Orders (Admin only)
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find().sort({ created_at: -1 }).limit(1000);
    res.json(orders);
  } catch (err) {
    console.error('Get orders error:', err);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Get Order by Tracking ID (Public)
app.get('/api/orders/:tracking_id', async (req, res) => {
  try {
    const order = await Order.findOne({ tracking_id: req.params.tracking_id });
    if (!order) {
      return res.status(404).json({ detail: 'Order not found' });
    }
    res.json(order);
  } catch (err) {
    console.error('Get order error:', err);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Update Order Status
app.patch('/api/orders/:tracking_id', authenticateToken, [
  body('status').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ detail: 'Invalid input', errors: errors.array() });
  }

  try {
    const { status, note } = req.body;
    const order = await Order.findOne({ tracking_id: req.params.tracking_id });

    if (!order) {
      return res.status(404).json({ detail: 'Order not found' });
    }

    const now = new Date();
    const newStatus = {
      status,
      timestamp: now,
      note: note || `Status updated to ${status}`
    };

    order.current_status = status;
    order.updated_at = now;
    order.status_history.push(newStatus);

    await order.save();
    res.json(order);
  } catch (err) {
    console.error('Update order error:', err);
    res.status(500).json({ detail: 'Internal server error' });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Graceful Shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  mongoose.connection.close();
  process.exit(0);
});
