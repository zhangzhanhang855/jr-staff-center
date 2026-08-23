require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://buenosairesampy563_db_user:congcong2012@cluster0.aaks5du.mongodb.net/?appName=Cluster0';
const JWT_SECRET = process.env.JWT_SECRET || 'CORP_TASK_SECURE_AUTH_KEY_2026_SECRET';

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Database Connection
mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB Connected Successfully to Corporate Cluster'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// ==========================================
// SCHEMAS (Service-Specific Namespaces)
// ==========================================

// Dedicated schema for this application to avoid collision with other apps
const CorporateEmployeeAccountSchema = new mongoose.Schema({
  staff_id: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  full_name: { type: String, required: true },
  department: { type: String, required: true },
  role: { type: String, default: 'employee' },
  created_at: { type: Date, default: Date.now }
}, { collection: 'corp_app_employee_accounts' });

const CorporateApplicationRequestSchema = new mongoose.Schema({
  applicant_username: { type: String, required: true },
  applicant_name: { type: String, required: true },
  department: { type: String, required: true },
  request_title: { type: String, required: true },
  request_body: { type: String, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  submitted_at: { type: Date, default: Date.now }
}, { collection: 'corp_app_staff_requests' });

const CorporateTaskSchema = new mongoose.Schema({
  task_title: { type: String, required: true },
  task_description: { type: String, required: true },
  assigned_to_username: { type: String, required: true }, // Targeted user
  priority: { type: String, enum: ['Low', 'Normal', 'High', 'Urgent'], default: 'Normal' },
  status: { type: String, enum: ['Assigned', 'Claimed', 'In Progress', 'Completed'], default: 'Assigned' },
  claimed_at: { type: Date, default: null },
  created_at: { type: Date, default: Date.now }
}, { collection: 'corp_app_tasks' });

const EmployeeAccount = mongoose.model('CorporateEmployeeAccount', CorporateEmployeeAccountSchema);
const EmployeeRequest = mongoose.model('CorporateApplicationRequest', CorporateApplicationRequestSchema);
const TaskItem = mongoose.model('CorporateTask', CorporateTaskSchema);

// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================
const authenticateEmployeeToken = (req, res, next) => {
  const token = req.cookies.corp_auth_token;
  if (!token) {
    return res.status(401).json({ success: false, message: 'Authentication required. No session found.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Session expired or invalid.' });
    }
    req.user = decodedUser;
    next();
  });
};

// ==========================================
// API ROUTES
// ==========================================

// 1. Authentication Route (Login Only - No Public Register)
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  try {
    const employee = await EmployeeAccount.findOne({ username: username.trim() });
    if (!employee) {
      return res.status(401).json({ success: false, message: 'Invalid credentials. Account not found.' });
    }

    const isMatch = await bcrypt.compare(password, employee.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials. Incorrect password.' });
    }

    const payload = {
      staff_id: employee.staff_id,
      username: employee.username,
      full_name: employee.full_name,
      department: employee.department
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

    // Store JWT securely into Cookie
    res.cookie('corp_auth_token', token, {
      httpOnly: false, // Accessible by script for display handling if required, or pure HTTP header
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 8 * 60 * 60 * 1000 // 8 Hours
    });

    res.json({
      success: true,
      message: 'Login successful',
      user: payload
    });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ success: false, message: 'Internal server error during authentication.' });
  }
});

// 2. Session Check
app.get('/api/auth/session', authenticateEmployeeToken, (req, res) => {
  res.json({ success: true, user: req.user });
});

// 3. Logout Route
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('corp_auth_token');
  res.json({ success: true, message: 'Logged out successfully.' });
});

// 4. Submit Employee Application Request
app.post('/api/requests/submit', authenticateEmployeeToken, async (req, res) => {
  const { title, body } = req.body;
  if (!title || !body) {
    return res.status(400).json({ success: false, message: 'Title and content are required.' });
  }

  try {
    const newRequest = new EmployeeRequest({
      applicant_username: req.user.username,
      applicant_name: req.user.full_name,
      department: req.user.department,
      request_title: title.trim(),
      request_body: body.trim()
    });

    await newRequest.save();
    res.json({ success: true, message: 'Request submitted successfully to database.', data: newRequest });
  } catch (error) {
    console.error('Request Submission Error:', error);
    res.status(500).json({ success: false, message: 'Failed to record application to MongoDB.' });
  }
});

// 5. Get User History Requests
app.get('/api/requests/mine', authenticateEmployeeToken, async (req, res) => {
  try {
    const list = await EmployeeRequest.find({ applicant_username: req.user.username }).sort({ submitted_at: -1 });
    res.json({ success: true, data: list });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch requests.' });
  }
});

// 6. Get User Tasks
app.get('/api/tasks/list', authenticateEmployeeToken, async (req, res) => {
  try {
    const tasks = await TaskItem.find({ assigned_to_username: req.user.username }).sort({ created_at: -1 });
    res.json({ success: true, data: tasks });
  } catch (error) {
    console.error('Fetch Task Error:', error);
    res.status(500).json({ success: false, message: 'Failed to retrieve tasks from database.' });
  }
});

// 7. Claim Task (Sync status and timestamp to MongoDB)
app.post('/api/tasks/claim/:id', authenticateEmployeeToken, async (req, res) => {
  const taskId = req.params.id;

  try {
    const task = await TaskItem.findOne({ _id: taskId, assigned_to_username: req.user.username });
    if (!task) {
      return res.status(404).json({ success: false, message: 'Task not found or access denied.' });
    }

    if (task.status !== 'Assigned') {
      return res.status(400).json({ success: false, message: 'This task is already claimed or resolved.' });
    }

    task.status = 'Claimed';
    task.claimed_at = new Date();
    await task.save();

    res.json({ success: true, message: 'Task claimed successfully!', data: task });
  } catch (error) {
    console.error('Claim Task Error:', error);
    res.status(500).json({ success: false, message: 'Internal server error while claiming task.' });
  }
});

// Fallback to Serve Index
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Seed an initial demo account if empty
async function initSeed() {
  const count = await EmployeeAccount.countDocuments();
  if (count === 0) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash('Employee@2026', salt);
    await EmployeeAccount.create({
      staff_id: 'EMP-9081',
      username: 'corp_employee',
      password_hash: hash,
      full_name: 'Alex Vance',
      department: 'Infrastructure Operations',
      role: 'employee'
    });
    console.log('Seed account created: username: "corp_employee" / password: "Employee@2026"');
  }
}
mongoose.connection.once('open', initSeed);

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
