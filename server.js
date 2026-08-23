require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://user:password@cluster.mongodb.net/CorporateDB?retryWrites=true&w=majority';
const JWT_SECRET = process.env.JWT_SECRET || 'CORP_TASK_SECURE_AUTH_KEY_2026_SECRET';

// Render Environment Variable for Admin Site Access Gate
const SITE_GATE_PASSWORD = process.env.SITE_GATE_PASSWORD || 'congcong2012';
const GATE_SECRET = process.env.GATE_SECRET || 'CORP_ADMIN_GATE_AUTH_SIGNING_KEY_2026';

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Database Connection
mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB Connected Successfully to Corporate Cluster'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// ==========================================
// SCHEMAS (Dedicated Service-Specific Namespaces)
// ==========================================
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
  assigned_to_username: { type: String, required: true },
  priority: { type: String, enum: ['Low', 'Normal', 'High', 'Urgent'], default: 'Normal' },
  status: { type: String, enum: ['Assigned', 'Claimed', 'In Progress', 'Completed'], default: 'Assigned' },
  claimed_at: { type: Date, default: null },
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
    return res.status(401).json({ success: false, message: '管理通行密码错误，拒绝访问。' });
  }

  // Generate temporary gate session token for Admin console
  const token = jwt.sign({ adminGatePassed: true }, GATE_SECRET, { expiresIn: '8h' });
  res.cookie('corp_site_gate_pass', token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000
  });

  res.json({ success: true, message: '环境通行密码验证成功。' });
});

// Guard Middleware for Admin Gate Access (Used ONLY for Admin routes)
const checkGateAccess = (req, res, next) => {
  const gateToken = req.cookies.corp_site_gate_pass;
  if (!gateToken) {
    return res.status(403).json({ success: false, gateLocked: true, message: '需要先输入管理员通行密码。' });
  }
  jwt.verify(gateToken, GATE_SECRET, (err) => {
    if (err) {
      return res.status(403).json({ success: false, gateLocked: true, message: '通行密码凭据已失效，请重新输入。' });
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
    return res.status(401).json({ success: false, message: '未检测到登录状态，请先登录。' });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err) {
      return res.status(403).json({ success: false, message: '登录状态已失效，请重新登录。' });
    }
    req.user = decodedUser;
    next();
  });
};

const authenticateAdminToken = (req, res, next) => {
  const token = req.cookies.corp_admin_auth_token;
  if (!token) {
    return res.status(401).json({ success: false, message: '未检测到管理员登录状态。' });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err || decodedUser.role !== 'admin') {
      return res.status(403).json({ success: false, message: '权限不足，拒绝访问管理终端。' });
    }
    req.admin = decodedUser;
    next();
  });
};

// ==========================================================================
// 1. EMPLOYEE CLIENT APIS (No Gate Password Required - Direct Staff Login)
// ==========================================================================

// Employee Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: '工号/用户名与密码为必填项。' });
  }

  try {
    const employee = await EmployeeAccount.findOne({ username: username.trim(), role: 'employee' });
    if (!employee) {
      return res.status(401).json({ success: false, message: '员工账号不存在。' });
    }

    const isMatch = await bcrypt.compare(password, employee.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: '账号或密码错误。' });
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

    res.json({ success: true, message: '登录成功', user: payload });
  } catch (error) {
    res.status(500).json({ success: false, message: '登录处理失败。' });
  }
});

// Employee Session Check
app.get('/api/auth/session', authenticateEmployeeToken, (req, res) => {
  res.json({ success: true, user: req.user });
});

// Employee Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('corp_auth_token');
  res.json({ success: true, message: '已安全登出。' });
});

// Employee Submit Application Request
app.post('/api/requests/submit', authenticateEmployeeToken, async (req, res) => {
  const { title, body } = req.body;
  if (!title || !body) {
    return res.status(400).json({ success: false, message: '申请标题与正文不可为空。' });
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
    res.json({ success: true, message: '申请已成功提交至 MongoDB。', data: newRequest });
  } catch (error) {
    res.status(500).json({ success: false, message: '提交申请失败。' });
  }
});

// Employee View Submitted Requests
app.get('/api/requests/mine', authenticateEmployeeToken, async (req, res) => {
  try {
    const list = await EmployeeRequest.find({ applicant_username: req.user.username }).sort({ submitted_at: -1 });
    res.json({ success: true, data: list });
  } catch (error) {
    res.status(500).json({ success: false, message: '获取申请记录失败。' });
  }
});

// Employee View Assigned Tasks
app.get('/api/tasks/list', authenticateEmployeeToken, async (req, res) => {
  try {
    const tasks = await TaskItem.find({ assigned_to_username: req.user.username }).sort({ created_at: -1 });
    res.json({ success: true, data: tasks });
  } catch (error) {
    res.status(500).json({ success: false, message: '获取任务失败。' });
  }
});

// Employee Claim Task (Sync status and timestamp to MongoDB)
app.post('/api/tasks/claim/:id', authenticateEmployeeToken, async (req, res) => {
  try {
    const task = await TaskItem.findOne({ _id: req.params.id, assigned_to_username: req.user.username });
    if (!task) {
      return res.status(404).json({ success: false, message: '任务不存在或无权领取。' });
    }

    if (task.status !== 'Assigned') {
      return res.status(400).json({ success: false, message: '该任务已被领取或已完成。' });
    }

    task.status = 'Claimed';
    task.claimed_at = new Date();
    await task.save();

    res.json({ success: true, message: '任务领取成功，状态已同步！', data: task });
  } catch (error) {
    res.status(500).json({ success: false, message: '领取任务处理失败。' });
  }
});

// ==========================================================================
// 2. ADMIN APIS (Strictly Protected by checkGateAccess & Admin Auth)
// ==========================================

// Admin Login (Requires Gate Password Check First)
app.post('/api/admin/auth/login', checkGateAccess, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: '请输入管理员账号及密码。' });
  }

  try {
    const adminUser = await EmployeeAccount.findOne({ username: username.trim(), role: 'admin' });
    if (!adminUser) {
      return res.status(401).json({ success: false, message: '管理员账号不存在。' });
    }

    const isMatch = await bcrypt.compare(password, adminUser.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: '管理员密码错误。' });
    }

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

    res.json({ success: true, message: '管理员认证通过', user: payload });
  } catch (error) {
    res.status(500).json({ success: false, message: '服务器验证异常。' });
  }
});

// Admin Session Check
app.get('/api/admin/auth/session', checkGateAccess, authenticateAdminToken, (req, res) => {
  res.json({ success: true, user: req.admin });
});

// Admin Logout
app.post('/api/admin/auth/logout', (req, res) => {
  res.clearCookie('corp_admin_auth_token');
  res.json({ success: true, message: '管理员已安全退出。' });
});

// Admin: List All Employee Accounts
app.get('/api/admin/employees/list', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const list = await EmployeeAccount.find({ role: 'employee' }).sort({ created_at: -1 });
    res.json({ success: true, data: list });
  } catch (error) {
    res.status(500).json({ success: false, message: '读取员工账号列表失败。' });
  }
});

// Admin: Register a New Employee Account
app.post('/api/admin/employees/create', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const { staff_id, username, password, full_name, department } = req.body;
  if (!staff_id || !username || !password || !full_name || !department) {
    return res.status(400).json({ success: false, message: '请完整填写所有员工字段。' });
  }

  try {
    const existing = await EmployeeAccount.findOne({
      $or: [{ username: username.trim() }, { staff_id: staff_id.trim() }]
    });
    if (existing) {
      return res.status(409).json({ success: false, message: '工号或用户名已存在。' });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const newStaff = new EmployeeAccount({
      staff_id: staff_id.trim(),
      username: username.trim(),
      password_hash,
      full_name: full_name.trim(),
      department: department.trim(),
      role: 'employee'
    });

    await newStaff.save();
    res.json({ success: true, message: '新员工账号注册成功并已写入 MongoDB。' });
  } catch (error) {
    res.status(500).json({ success: false, message: '注册员工失败。' });
  }
});

// Admin: Delete / Deregister an Employee Account
app.delete('/api/admin/employees/delete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const target = await EmployeeAccount.findByIdAndDelete(req.params.id);
    if (!target) {
      return res.status(404).json({ success: false, message: '未找到指定员工账号。' });
    }
    res.json({ success: true, message: '员工账号已成功注销并从 MongoDB 物理删除。' });
  } catch (error) {
    res.status(500).json({ success: false, message: '注销员工失败。' });
  }
});

// Admin: View All Tasks
app.get('/api/admin/tasks/all', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const tasks = await TaskItem.find().sort({ created_at: -1 });
    res.json({ success: true, data: tasks });
  } catch (error) {
    res.status(500).json({ success: false, message: '获取任务汇总失败。' });
  }
});

// Admin: Create & Dispatch Task
app.post('/api/admin/tasks/create', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const { title, description, assigned_to_username, priority } = req.body;
  if (!title || !description || !assigned_to_username) {
    return res.status(400).json({ success: false, message: '任务标题、描述与执行人必填。' });
  }

  try {
    const newTask = new TaskItem({
      task_title: title.trim(),
      task_description: description.trim(),
      assigned_to_username: assigned_to_username.trim(),
      priority: priority || 'Normal',
      status: 'Assigned'
    });
    await newTask.save();
    res.json({ success: true, message: '任务已成功派发并存储至数据库。', data: newTask });
  } catch (error) {
    res.status(500).json({ success: false, message: '派发任务失败。' });
  }
});

// Admin: Revoke and Delete Task from MongoDB
app.delete('/api/admin/tasks/delete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const result = await TaskItem.findByIdAndDelete(req.params.id);
    if (!result) {
      return res.status(404).json({ success: false, message: '任务不存在或已删除。' });
    }
    res.json({ success: true, message: '任务已撤销并从 MongoDB 彻底删除。' });
  } catch (error) {
    res.status(500).json({ success: false, message: '撤销任务失败。' });
  }
});

// Admin: View All Requests
app.get('/api/admin/requests/all', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const requests = await EmployeeRequest.find().sort({ submitted_at: -1 });
    res.json({ success: true, data: requests });
  } catch (error) {
    res.status(500).json({ success: false, message: '获取申请列表失败。' });
  }
});

// Admin: Update Request Status (Approve / Reject)
app.patch('/api/admin/requests/status/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected', 'pending'].includes(status)) {
    return res.status(400).json({ success: false, message: '非法的审批状态。' });
  }

  try {
    const updated = await EmployeeRequest.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    res.json({ success: true, message: '申请状态已同步更新。', data: updated });
  } catch (error) {
    res.status(500).json({ success: false, message: '更新审批状态失败。' });
  }
});

// Admin: Delete Request Record from MongoDB
app.delete('/api/admin/requests/delete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    await EmployeeRequest.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: '申请记录已从 MongoDB 彻底清除。' });
  } catch (error) {
    res.status(500).json({ success: false, message: '删除申请失败。' });
  }
});

// ==========================================
// SEED INITIAL DEMO ACCOUNTS
// ==========================================
async function initSeed() {
  const salt = await bcrypt.genSalt(10);

  // 1. Default Employee Account
  const empCount = await EmployeeAccount.countDocuments({ role: 'employee' });
  if (empCount === 0) {
    const empHash = await bcrypt.hash('Employee@2026', salt);
    await EmployeeAccount.create({
      staff_id: 'EMP-9081',
      username: 'corp_employee',
      password_hash: empHash,
      full_name: 'Alex Vance',
      department: 'Infrastructure Operations',
      role: 'employee'
    });
    console.log('Default employee created: corp_employee / Employee@2026');
  }

  // 2. Default Admin Account
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
    console.log('Default admin created: corp_admin / Admin@2026');
  }
}
mongoose.connection.once('open', initSeed);

// Fallback Route for Single Page Apps
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
