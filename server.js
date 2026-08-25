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

const SITE_GATE_PASSWORD = process.env.SITE_GATE_PASSWORD || 'congcong2012';
const GATE_SECRET = process.env.GATE_SECRET || 'CORP_ADMIN_GATE_AUTH_SIGNING_KEY_2026';

// 放大 Express Payload 限制
app.use(express.json({ limit: '150mb' }));
app.use(express.urlencoded({ limit: '150mb', extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Multer 配置：单个文件上限 30MB，支持 5 个附件
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 30 * 1024 * 1024, // 30MB
    files: 5
  }
});

// 连接数据库
mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB Connected Successfully!'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// ==========================================
// SCHEMAS (独立文件集合，规避 16MB 限制)
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

// 独立文件存储 Schema
const StoredFileSchema = new mongoose.Schema({
  task_id: { type: mongoose.Schema.Types.ObjectId, ref: 'CorporateTask', required: true },
  file_type: { type: String, enum: ['admin_attachment', 'user_submission'], required: true },
  filename: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  data: { type: Buffer, required: true },
  uploader: { type: String, required: true },
  created_at: { type: Date, default: Date.now }
}, { collection: 'corp_app_files' });

const FileMetadataSchema = new mongoose.Schema({
  file_id: { type: mongoose.Schema.Types.ObjectId, required: true },
  filename: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true }
}, { _id: false });

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
  attachments: [FileMetadataSchema], // 管理员附件元数据
  submissions: [FileMetadataSchema], // 员工提交成果元数据
  submission_notes: { type: String, default: '' },
  claimed_at: { type: Date, default: null },
  submitted_at: { type: Date, default: null },
  completed_at: { type: Date, default: null },
  created_at: { type: Date, default: Date.now }
}, { collection: 'corp_app_tasks' });

const EmployeeAccount = mongoose.model('CorporateEmployeeAccount', CorporateEmployeeAccountSchema);
const EmployeeRequest = mongoose.model('CorporateApplicationRequest', CorporateApplicationRequestSchema);
const StoredFile = mongoose.model('StoredFile', StoredFileSchema);
const TaskItem = mongoose.model('CorporateTask', CorporateTaskSchema);

// ==========================================
// MIDDLEWARES
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
  if (!gateToken) return res.status(403).json({ success: false, gateLocked: true, message: 'Gate passcode required.' });
  jwt.verify(gateToken, GATE_SECRET, (err) => {
    if (err) return res.status(403).json({ success: false, gateLocked: true, message: 'Gate passcode expired.' });
    next();
  });
};

const authenticateEmployeeToken = (req, res, next) => {
  const token = req.cookies.corp_auth_token;
  if (!token) return res.status(401).json({ success: false, message: 'Authentication required.' });
  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) return res.status(403).json({ success: false, message: 'Session expired.' });
    req.user = decodedUser;
    next();
  });
};

const authenticateAdminToken = (req, res, next) => {
  const token = req.cookies.corp_admin_auth_token;
  if (!token) return res.status(401).json({ success: false, message: 'Admin authentication required.' });
  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err || decodedUser.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin role required.' });
    req.admin = decodedUser;
    next();
  });
};

// ==========================================
// EMPLOYEE APIS
// ==========================================
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: 'Username and password required.' });

  const employee = await EmployeeAccount.findOne({ username: username.trim(), role: 'employee' });
  if (!employee) return res.status(401).json({ success: false, message: 'Account not found.' });

  const isMatch = await bcrypt.compare(password, employee.password_hash);
  if (!isMatch) return res.status(401).json({ success: false, message: 'Incorrect credentials.' });

  const payload = { staff_id: employee.staff_id, username: employee.username, full_name: employee.full_name, department: employee.department, role: 'employee' };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

  res.cookie('corp_auth_token', token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000
  });

  res.json({ success: true, message: 'Login successful', user: payload });
});

app.get('/api/auth/session', authenticateEmployeeToken, async (req, res) => {
  const employee = await EmployeeAccount.findOne({ username: req.user.username });
  if (!employee) return res.status(404).json({ success: false, message: 'User not found.' });
  res.json({
    success: true,
    user: { staff_id: employee.staff_id, username: employee.username, full_name: employee.full_name, department: employee.department, account_balance: employee.account_balance || 0 }
  });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('corp_auth_token');
  res.json({ success: true, message: 'Logged out.' });
});

app.get('/api/tasks/list', authenticateEmployeeToken, async (req, res) => {
  try {
    const tasks = await TaskItem.find({ assigned_to_username: req.user.username }).sort({ created_at: -1 });
    res.json({ success: true, data: tasks });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch tasks.' });
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
    res.status(500).json({ success: false, message: 'Claim failed.' });
  }
});

// 员工上传交付成果（单文件可达 25MB+）
app.post('/api/tasks/submit-deliverables/:id', authenticateEmployeeToken, upload.array('deliverables', 5), async (req, res) => {
  try {
    const task = await TaskItem.findOne({ _id: req.params.id, assigned_to_username: req.user.username });
    if (!task) return res.status(404).json({ success: false, message: 'Task not found.' });

    if (task.submission_deadline && new Date() > new Date(task.submission_deadline)) {
      return res.status(400).json({ success: false, message: 'Submission deadline has passed.' });
    }

    const uploadedFiles = req.files || [];
    if (task.requires_submission && uploadedFiles.length === 0 && (!task.submissions || task.submissions.length === 0)) {
      return res.status(400).json({ success: false, message: 'Deliverable files are required.' });
    }

    const savedMetadata = [];
    for (const f of uploadedFiles) {
      const stored = new StoredFile({
        task_id: task._id,
        file_type: 'user_submission',
        filename: Buffer.from(f.originalname, 'latin1').toString('utf8'),
        mimetype: f.mimetype,
        size: f.size,
        data: f.buffer,
        uploader: req.user.username
      });
      await stored.save();
      savedMetadata.push({
        file_id: stored._id,
        filename: stored.filename,
        mimetype: stored.mimetype,
        size: stored.size
      });
    }

    if (savedMetadata.length > 0) {
      task.submissions = savedMetadata;
    }
    task.submission_notes = (req.body.notes || '').trim();
    task.status = 'Submitted';
    task.submitted_at = new Date();
    await task.save();

    res.json({ success: true, message: 'Files uploaded successfully!', data: task });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'File upload failed.' });
  }
});

// 通用文件下载通道（员工与管理员共享权限，解决无法下载问题）
app.get('/api/files/download/:fileId', async (req, res) => {
  try {
    const empToken = req.cookies.corp_auth_token;
    const adminToken = req.cookies.corp_admin_auth_token;

    let isAuthorized = false;
    let authUser = null;

    if (adminToken) {
      try {
        const decoded = jwt.verify(adminToken, JWT_SECRET);
        if (decoded.role === 'admin') isAuthorized = true;
      } catch (e) {}
    }

    if (!isAuthorized && empToken) {
      try {
        authUser = jwt.verify(empToken, JWT_SECRET);
      } catch (e) {}
    }

    const file = await StoredFile.findById(req.params.fileId);
    if (!file) return res.status(404).json({ success: false, message: 'File not found.' });

    // 如果不是管理员，验证是否属于该员工
    if (!isAuthorized) {
      if (!authUser) return res.status(401).json({ success: false, message: 'Unauthorized.' });
      const task = await TaskItem.findById(file.task_id);
      if (!task || task.assigned_to_username !== authUser.username) {
        return res.status(403).json({ success: false, message: 'Access denied.' });
      }
    }

    res.setHeader('Content-Type', file.mimetype);
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(file.filename)}`);
    res.send(file.data);
  } catch (error) {
    res.status(500).json({ success: false, message: 'Download error.' });
  }
});

// ==========================================
// ADMIN APIS
// ==========================================
app.post('/api/admin/auth/login', checkGateAccess, async (req, res) => {
  const { username, password } = req.body;
  const adminUser = await EmployeeAccount.findOne({ username: username.trim(), role: 'admin' });
  if (!adminUser) return res.status(401).json({ success: false, message: 'Admin account not found.' });

  const isMatch = await bcrypt.compare(password, adminUser.password_hash);
  if (!isMatch) return res.status(401).json({ success: false, message: 'Incorrect password.' });

  const payload = { staff_id: adminUser.staff_id, username: adminUser.username, full_name: adminUser.full_name, department: adminUser.department, role: 'admin' };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

  res.cookie('corp_admin_auth_token', token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000
  });

  res.json({ success: true, message: 'Admin session created', user: payload });
});

app.get('/api/admin/auth/session', checkGateAccess, authenticateAdminToken, (req, res) => {
  res.json({ success: true, user: req.admin });
});

app.post('/api/admin/auth/logout', (req, res) => {
  res.clearCookie('corp_admin_auth_token');
  res.json({ success: true, message: 'Admin logged out.' });
});

app.get('/api/admin/tasks/all', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const tasks = await TaskItem.find().sort({ created_at: -1 });
    res.json({ success: true, data: tasks });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch tasks.' });
  }
});

// 管理员批量布置任务并存入独立附件
app.post('/api/admin/tasks/create-bulk', checkGateAccess, authenticateAdminToken, upload.array('attachments', 5), async (req, res) => {
  const { title, description, assignees, priority, reward_amount, requires_submission, submission_deadline } = req.body;
  
  let assigneeList = [];
  try {
    assigneeList = typeof assignees === 'string' ? JSON.parse(assignees) : assignees;
  } catch (e) {
    assigneeList = [assignees];
  }

  if (!Array.isArray(assigneeList) || assigneeList.length === 0) {
    return res.status(400).json({ success: false, message: 'No assignee selected.' });
  }

  try {
    const rawFiles = req.files || [];

    for (const username of assigneeList) {
      const newTask = new TaskItem({
        task_title: title.trim(),
        task_description: description.trim(),
        assigned_to_username: String(username).trim(),
        priority: priority || 'Normal',
        reward_amount: parseFloat(reward_amount) || 0.00,
        requires_submission: requires_submission === 'true' || requires_submission === true,
        submission_deadline: submission_deadline ? new Date(submission_deadline) : null,
        status: 'Assigned',
        attachments: []
      });

      await newTask.save();

      // 单独存附件并挂载元数据
      const fileMetas = [];
      for (const f of rawFiles) {
        const stored = new StoredFile({
          task_id: newTask._id,
          file_type: 'admin_attachment',
          filename: Buffer.from(f.originalname, 'latin1').toString('utf8'),
          mimetype: f.mimetype,
          size: f.size,
          data: f.buffer,
          uploader: 'admin'
        });
        await stored.save();
        fileMetas.push({
          file_id: stored._id,
          filename: stored.filename,
          mimetype: stored.mimetype,
          size: stored.size
        });
      }

      newTask.attachments = fileMetas;
      await newTask.save();
    }

    res.json({ success: true, message: `Dispatched to ${assigneeList.length} employee(s)!` });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Bulk dispatch error.' });
  }
});

// 管理员点击完成：自动发放报酬
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
    res.json({ success: true, message: `Task completed! ¥${task.reward_amount.toFixed(2)} credited.` });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Completion failed.' });
  }
});

app.delete('/api/admin/tasks/delete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    await StoredFile.deleteMany({ task_id: req.params.id });
    await TaskItem.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Task & files deleted.' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Delete failed.' });
  }
});

// 员工账号管理
app.get('/api/admin/employees/list', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const list = await EmployeeAccount.find({ role: 'employee' }).sort({ created_at: -1 });
  res.json({ success: true, data: list });
});

app.post('/api/admin/employees/create', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const { staff_id, username, password, full_name, department, initial_balance } = req.body;
  const salt = await bcrypt.genSalt(10);
  const password_hash = await bcrypt.hash(password, salt);
  await EmployeeAccount.create({
    staff_id: staff_id.trim(),
    username: username.trim(),
    password_hash,
    full_name: full_name.trim(),
    department: department.trim(),
    account_balance: parseFloat(initial_balance) || 0.00,
    role: 'employee'
  });
  res.json({ success: true, message: 'Employee created!' });
});

app.patch('/api/admin/employees/balance/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const emp = await EmployeeAccount.findByIdAndUpdate(req.params.id, { account_balance: parseFloat(req.body.balance) }, { new: true });
  res.json({ success: true, message: 'Balance updated!', data: emp });
});

app.delete('/api/admin/employees/delete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  await EmployeeAccount.findByIdAndDelete(req.params.id);
  res.json({ success: true, message: 'Employee deleted.' });
});

// 员工申请管理
app.get('/api/admin/requests/all', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const requests = await EmployeeRequest.find().sort({ submitted_at: -1 });
  res.json({ success: true, data: requests });
});

app.patch('/api/admin/requests/status/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const updated = await EmployeeRequest.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
  res.json({ success: true, message: 'Status updated.', data: updated });
});

app.delete('/api/admin/requests/delete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  await EmployeeRequest.findByIdAndDelete(req.params.id);
  res.json({ success: true, message: 'Request purged.' });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
