require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://aleafs%40aliyun.com:Xl32cVfKQ6SJ@120.55.50.18:27017/CorporateDB?authSource=admin';
const JWT_SECRET = process.env.JWT_SECRET || 'CORP_TASK_SECURE_AUTH_KEY_2026_SECRET';

// Render Environment Variable for Admin Site Access Gate
const SITE_GATE_PASSWORD = process.env.SITE_GATE_PASSWORD || 'congcong2012';
const GATE_SECRET = process.env.GATE_SECRET || 'CORP_ADMIN_GATE_AUTH_SIGNING_KEY_2026';

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Configure Multer: max 25MB per file, max 5 files
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: {
    fileSize: 25 * 1024 * 1024,
    files: 5
  }
});

// Database Connection
mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB Connected Successfully to Corporate Cluster'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// ==========================================
// SCHEMAS
// ==========================================
const CorporateEmployeeAccountSchema = new mongoose.Schema({
  staff_id: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  full_name: { type: String, required: true },
  department: { type: String, required: true },
  account_balance: { type: Number, default: 0.00 },
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

const FileAttachmentSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  data: { type: Buffer, required: true },
  uploaded_at: { type: Date, default: Date.now }
});

const CorporateTaskSchema = new mongoose.Schema({
  task_title: { type: String, required: true },
  task_description: { type: String, required: true },
  assigned_to_username: { type: String, required: true },
  priority: { type: String, enum: ['Low', 'Normal', 'High', 'Urgent'], default: 'Normal' },
  reward_amount: { type: Number, default: 0.00 },
  requires_submission: { type: Boolean, default: false },
  submission_deadline: { type: Date, default: null },
  status: { type: String, enum: ['Assigned', 'Claimed', 'Submitted', 'Completed'], default: 'Assigned' },
  reward_distributed: { type: Boolean, default: false },
  attachments: [FileAttachmentSchema],
  submissions: [FileAttachmentSchema],
  submission_notes: { type: String, default: '' },
  claimed_at: { type: Date, default: null },
  submitted_at: { type: Date, default: null },
  completed_at: { type: Date, default: null },
  created_at: { type: Date, default: Date.now }
}, { collection: 'corp_app_tasks' });

const EmployeeAccount = mongoose.model('CorporateEmployeeAccount', CorporateEmployeeAccountSchema);
const EmployeeRequest = mongoose.model('CorporateApplicationRequest', CorporateApplicationRequestSchema);
const TaskItem = mongoose.model('CorporateTask', CorporateTaskSchema);

// ==========================================
// ADMIN GATE VERIFICATION & GUARD
// ==========================================
app.post('/api/gate/verify', (req, res) => {
  const { password } = req.body;
  if (!password || password !== SITE_GATE_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Invalid gate passcode.' });
  }

  const token = jwt.sign({ adminGatePassed: true }, GATE_SECRET, { expiresIn: '8h' });
  res.cookie('corp_site_gate_pass', token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000
  });

  res.json({ success: true, message: 'Gate unlocked.' });
});

const checkGateAccess = (req, res, next) => {
  const gateToken = req.cookies.corp_site_gate_pass;
  if (!gateToken) {
    return res.status(403).json({ success: false, gateLocked: true, message: 'Admin gate code required.' });
  }
  jwt.verify(gateToken, GATE_SECRET, (err) => {
    if (err) {
      return res.status(403).json({ success: false, gateLocked: true, message: 'Gate session expired.' });
    }
    next();
  });
};

// ==========================================
// AUTHENTICATION MIDDLEWARES
// ==========================================
const authenticateEmployeeToken = (req, res, next) => {
  const token = req.cookies.corp_auth_token;
  if (!token) {
    return res.status(401).json({ success: false, message: 'Authentication required.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Session expired.' });
    }
    req.user = decodedUser;
    next();
  });
};

const authenticateAdminToken = (req, res, next) => {
  const token = req.cookies.corp_admin_auth_token;
  if (!token) {
    return res.status(401).json({ success: false, message: 'Admin authentication required.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err || decodedUser.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Access denied: Admin role required.' });
    }
    req.admin = decodedUser;
    next();
  });
};

// ==========================================================================
// 1. EMPLOYEE APIS
// ==========================================================================

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password required.' });
  }

  try {
    const employee = await EmployeeAccount.findOne({ username: username.trim(), role: 'employee' });
    if (!employee) {
      return res.status(401).json({ success: false, message: 'Account not found.' });
    }

    const isMatch = await bcrypt.compare(password, employee.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Incorrect credentials.' });
    }

    const payload = {
      staff_id: employee.staff_id,
      username: employee.username,
      full_name: employee.full_name,
      department: employee.department,
      role: 'employee'
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

    res.cookie('corp_auth_token', token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 8 * 60 * 60 * 1000
    });

    res.json({ success: true, message: 'Login successful', user: payload });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Authentication error.' });
  }
});

app.get('/api/auth/session', authenticateEmployeeToken, async (req, res) => {
  try {
    const employee = await EmployeeAccount.findOne({ username: req.user.username });
    if (!employee) return res.status(404).json({ success: false, message: 'User not found.' });

    res.json({
      success: true,
      user: {
        staff_id: employee.staff_id,
        username: employee.username,
        full_name: employee.full_name,
        department: employee.department,
        account_balance: employee.account_balance || 0
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error retrieving user data.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('corp_auth_token');
  res.json({ success: true, message: 'Logged out.' });
});

app.post('/api/requests/submit', authenticateEmployeeToken, async (req, res) => {
  const { title, body } = req.body;
  if (!title || !body) {
    return res.status(400).json({ success: false, message: 'Title and description required.' });
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
    res.json({ success: true, message: 'Request submitted.', data: newRequest });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to record request.' });
  }
});

app.get('/api/requests/mine', authenticateEmployeeToken, async (req, res) => {
  try {
    const list = await EmployeeRequest.find({ applicant_username: req.user.username }).sort({ submitted_at: -1 });
    res.json({ success: true, data: list });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch requests.' });
  }
});

app.get('/api/tasks/list', authenticateEmployeeToken, async (req, res) => {
  try {
    const tasks = await TaskItem.find(
      { assigned_to_username: req.user.username },
      { 'attachments.data': 0, 'submissions.data': 0 }
    ).sort({ created_at: -1 });

    res.json({ success: true, data: tasks });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch tasks.' });
  }
});

app.get('/api/tasks/:taskId/attachment/:fileId', authenticateEmployeeToken, async (req, res) => {
  try {
    const task = await TaskItem.findOne({
      _id: req.params.taskId,
      assigned_to_username: req.user.username
    });

    if (!task) return res.status(404).json({ success: false, message: 'Task not found.' });

    const attachment = task.attachments.id(req.params.fileId);
    if (!attachment) return res.status(404).json({ success: false, message: 'Attachment not found.' });

    res.setHeader('Content-Type', attachment.mimetype);
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(attachment.filename)}`);
    res.send(attachment.data);
  } catch (error) {
    res.status(500).json({ success: false, message: 'Download error.' });
  }
});

app.get('/api/tasks/:taskId/submission/:fileId', authenticateEmployeeToken, async (req, res) => {
  try {
    const task = await TaskItem.findOne({
      _id: req.params.taskId,
      assigned_to_username: req.user.username
    });

    if (!task) return res.status(404).json({ success: false, message: 'Task not found.' });

    const sub = task.submissions.id(req.params.fileId);
    if (!sub) return res.status(404).json({ success: false, message: 'File not found.' });

    res.setHeader('Content-Type', sub.mimetype);
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(sub.filename)}`);
    res.send(sub.data);
  } catch (error) {
    res.status(500).json({ success: false, message: 'Download error.' });
  }
});

app.post('/api/tasks/claim/:id', authenticateEmployeeToken, async (req, res) => {
  try {
    const task = await TaskItem.findOne({ _id: req.params.id, assigned_to_username: req.user.username });
    if (!task) return res.status(404).json({ success: false, message: 'Task not found.' });
    if (task.status !== 'Assigned') return res.status(400).json({ success: false, message: 'Task already claimed or finished.' });

    task.status = 'Claimed';
    task.claimed_at = new Date();
    await task.save();

    res.json({ success: true, message: 'Task claimed successfully!', data: task });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Claim processing failed.' });
  }
});

app.post('/api/tasks/submit-deliverables/:id', authenticateEmployeeToken, upload.array('deliverables', 5), async (req, res) => {
  try {
    const task = await TaskItem.findOne({ _id: req.params.id, assigned_to_username: req.user.username });
    if (!task) return res.status(404).json({ success: false, message: 'Task not found.' });

    if (!['Claimed', 'Submitted'].includes(task.status)) {
      return res.status(400).json({ success: false, message: 'Please claim the task first or task already completed.' });
    }

    if (task.submission_deadline && new Date() > new Date(task.submission_deadline)) {
      return res.status(400).json({ success: false, message: 'Submission deadline has passed.' });
    }

    const { notes } = req.body;
    const uploadedFiles = (req.files || []).map(f => ({
      filename: Buffer.from(f.originalname, 'latin1').toString('utf8'),
      mimetype: f.mimetype,
      size: f.size,
      data: f.buffer
    }));

    if (task.requires_submission && uploadedFiles.length === 0 && (!task.submissions || task.submissions.length === 0)) {
      return res.status(400).json({ success: false, message: 'Deliverable file submission is required for this task.' });
    }

    if (uploadedFiles.length > 0) {
      task.submissions = uploadedFiles;
    }

    task.submission_notes = (notes || '').trim();
    task.status = 'Submitted';
    task.submitted_at = new Date();
    await task.save();

    res.json({ success: true, message: 'Deliverables uploaded successfully!', data: task });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Submission failed.' });
  }
});

// ==========================================================================
// 2. ADMIN APIS
// ==========================================================================

app.post('/api/admin/auth/login', checkGateAccess, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: 'Username and password required.' });

  try {
    const adminUser = await EmployeeAccount.findOne({ username: username.trim(), role: 'admin' });
    if (!adminUser) return res.status(401).json({ success: false, message: 'Admin account not found.' });

    const isMatch = await bcrypt.compare(password, adminUser.password_hash);
    if (!isMatch) return res.status(401).json({ success: false, message: 'Incorrect password.' });

    const payload = {
      staff_id: adminUser.staff_id,
      username: adminUser.username,
      full_name: adminUser.full_name,
      department: adminUser.department,
      role: 'admin'
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

    res.cookie('corp_admin_auth_token', token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 8 * 60 * 60 * 1000
    });

    res.json({ success: true, message: 'Admin session created', user: payload });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Authentication failure.' });
  }
});

app.get('/api/admin/auth/session', checkGateAccess, authenticateAdminToken, (req, res) => {
  res.json({ success: true, user: req.admin });
});

app.post('/api/admin/auth/logout', (req, res) => {
  res.clearCookie('corp_admin_auth_token');
  res.json({ success: true, message: 'Admin logged out.' });
});

app.get('/api/admin/employees/list', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const list = await EmployeeAccount.find({ role: 'employee' }).sort({ created_at: -1 });
    res.json({ success: true, data: list });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to retrieve accounts.' });
  }
});

app.post('/api/admin/employees/create', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const { staff_id, username, password, full_name, department, initial_balance } = req.body;
  if (!staff_id || !username || !password || !full_name || !department) {
    return res.status(400).json({ success: false, message: 'All profile fields are required.' });
  }

  try {
    const existing = await EmployeeAccount.findOne({
      $or: [{ username: username.trim() }, { staff_id: staff_id.trim() }]
    });
    if (existing) return res.status(409).json({ success: false, message: 'Staff ID or username already exists.' });

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const newStaff = new EmployeeAccount({
      staff_id: staff_id.trim(),
      username: username.trim(),
      password_hash,
      full_name: full_name.trim(),
      department: department.trim(),
      account_balance: parseFloat(initial_balance) || 0.00,
      role: 'employee'
    });

    await newStaff.save();
    res.json({ success: true, message: 'Employee account created successfully.' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to save account.' });
  }
});

app.patch('/api/admin/employees/balance/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const { balance } = req.body;
  if (balance === undefined || isNaN(parseFloat(balance))) {
    return res.status(400).json({ success: false, message: 'Valid balance numeric value required.' });
  }

  try {
    const emp = await EmployeeAccount.findByIdAndUpdate(
      req.params.id,
      { account_balance: parseFloat(balance) },
      { new: true }
    );
    res.json({ success: true, message: 'Balance updated successfully!', data: emp });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to modify balance.' });
  }
});

app.delete('/api/admin/employees/delete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const target = await EmployeeAccount.findByIdAndDelete(req.params.id);
    if (!target) return res.status(404).json({ success: false, message: 'Account not found.' });
    res.json({ success: true, message: 'Employee account deregistered.' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to delete account.' });
  }
});

app.get('/api/admin/tasks/all', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const tasks = await TaskItem.find({}, { 'attachments.data': 0, 'submissions.data': 0 }).sort({ created_at: -1 });
    res.json({ success: true, data: tasks });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch tasks.' });
  }
});

// Admin: Bulk Dispatch Tasks to Multiple Users
app.post('/api/admin/tasks/create-bulk', checkGateAccess, authenticateAdminToken, upload.array('attachments', 5), async (req, res) => {
  const { title, description, assignees, priority, reward_amount, requires_submission, submission_deadline } = req.body;
  
  if (!title || !description || !assignees) {
    return res.status(400).json({ success: false, message: 'Title, description, and assignees are required.' });
  }

  let assigneeList = [];
  try {
    assigneeList = typeof assignees === 'string' ? JSON.parse(assignees) : assignees;
  } catch (e) {
    assigneeList = [assignees];
  }

  if (!Array.isArray(assigneeList) || assigneeList.length === 0) {
    return res.status(400).json({ success: false, message: 'At least one target assignee must be selected.' });
  }

  try {
    const fileAttachments = (req.files || []).map(f => ({
      filename: Buffer.from(f.originalname, 'latin1').toString('utf8'),
      mimetype: f.mimetype,
      size: f.size,
      data: f.buffer
    }));

    const taskDocuments = assigneeList.map(username => ({
      task_title: title.trim(),
      task_description: description.trim(),
      assigned_to_username: String(username).trim(),
      priority: priority || 'Normal',
      reward_amount: parseFloat(reward_amount) || 0.00,
      requires_submission: requires_submission === 'true' || requires_submission === true,
      submission_deadline: submission_deadline ? new Date(submission_deadline) : null,
      status: 'Assigned',
      attachments: fileAttachments
    }));

    await TaskItem.insertMany(taskDocuments);
    res.json({
      success: true,
      message: `Successfully dispatched tasks to ${assigneeList.length} employee(s)!`,
      count: assigneeList.length
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Bulk task dispatch failed.' });
  }
});

app.post('/api/admin/tasks/complete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const task = await TaskItem.findById(req.params.id);
    if (!task) return res.status(404).json({ success: false, message: 'Task not found.' });
    if (task.status === 'Completed') return res.status(400).json({ success: false, message: 'Task already completed.' });

    task.status = 'Completed';
    task.completed_at = new Date();

    if (!task.reward_distributed && task.reward_amount > 0) {
      await EmployeeAccount.findOneAndUpdate(
        { username: task.assigned_to_username },
        { $inc: { account_balance: task.reward_amount } }
      );
      task.reward_distributed = true;
    }

    await task.save();
    res.json({
      success: true,
      message: `Task completed! Reward of ¥${task.reward_amount.toFixed(2)} credited to ${task.assigned_to_username}.`,
      data: task
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Completion processing failed.' });
  }
});

app.delete('/api/admin/tasks/delete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const result = await TaskItem.findByIdAndDelete(req.params.id);
    if (!result) return res.status(404).json({ success: false, message: 'Task not found.' });
    res.json({ success: true, message: 'Task deleted successfully.' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Deletion failed.' });
  }
});

app.get('/api/admin/requests/all', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const requests = await EmployeeRequest.find().sort({ submitted_at: -1 });
    res.json({ success: true, data: requests });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch requests.' });
  }
});

app.patch('/api/admin/requests/status/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected', 'pending'].includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid status value.' });
  }

  try {
    const updated = await EmployeeRequest.findByIdAndUpdate(req.params.id, { status }, { new: true });
    res.json({ success: true, message: 'Status updated.', data: updated });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update status.' });
  }
});

app.delete('/api/admin/requests/delete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    await EmployeeRequest.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Request purged.' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to delete.' });
  }
});

// Seed Initial Accounts
async function initSeed() {
  const salt = await bcrypt.genSalt(10);
  const empCount = await EmployeeAccount.countDocuments({ role: 'employee' });
  if (empCount === 0) {
    const empHash = await bcrypt.hash('Employee@2026', salt);
    await EmployeeAccount.create({
      staff_id: 'EMP-9081',
      username: 'corp_employee',
      password_hash: empHash,
      full_name: 'Alex Vance',
      department: 'Infrastructure Operations',
      account_balance: 150.00,
      role: 'employee'
    });
  }

  const adminCount = await EmployeeAccount.countDocuments({ role: 'admin' });
  if (adminCount === 0) {
    const adminHash = await bcrypt.hash('Admin@2026', salt);
    await EmployeeAccount.create({
      staff_id: 'ADM-0001',
      username: 'corp_admin',
      password_hash: adminHash,
      full_name: 'Lead Operations Executive',
      department: 'Headquarters System Control',
      role: 'admin'
    });
  }
}
mongoose.connection.once('open', initSeed);

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
