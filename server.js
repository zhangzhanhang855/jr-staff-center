/**
 * ============================================================================
 * CORPORATE TASK & RESOURCE MANAGEMENT PLATFORM - BACKEND ENGINE
 * ============================================================================
 * Architecture: Node.js / Express.js / MongoDB Mongoose / Cloudflare R2
 * Deployment Target: Render Web Service & Alibaba Cloud ECS VPS
 * 
 * Core Features:
 *  - Cloudflare R2 Integration for Task Deliverables
 *  - MongoDB High-Volume Binary Storage for Admin Attachments
 *  - Dual Token-Based Authentication Engine (RBAC: Employee / Administrator)
 *  - Environment Gate Password Protection Layer
 *  - Automated Balance & Financial Ledger Credit Engine
 *  - Multi-Assignee Bulk Task Dispatch Pipeline
 *  - Robust Case-Insensitive Auth with Automatic Stale Cookie Invalidation
 * ============================================================================
 */

'use strict';

require('dotenv').config();

const path = require('path');
const http = require('http');
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');

// Cloudflare R2 (S3 Compatible SDK)
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, DeleteObjectsCommand } = require('@aws-sdk/client-s3');

// ============================================================================
// 1. GLOBAL CONSTANTS & RUNTIME CONFIGURATION
// ============================================================================

const PORT = parseInt(process.env.PORT, 10) || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';

// Database Connection URI
const MONGODB_URI = process.env.MONGODB_URI || 
  'mongodb://aleafs%40aliyun.com:Xl32cVfKQ6SJ@120.55.50.18:27017/CorporateDB?authSource=admin';

// Security Signing Secrets
const JWT_SECRET = process.env.JWT_SECRET || 
  'CORP_TASK_SECURE_AUTH_KEY_2026_PRODUCTION_SECRET_KEY';
const GATE_SECRET = process.env.GATE_SECRET || 
  'CORP_ADMIN_GATE_AUTH_SIGNING_KEY_2026_MASTER_SECRET';

// Site Gate Unlock Code
const SITE_GATE_PASSWORD = process.env.SITE_GATE_PASSWORD || 'congcong2012';

// Cloudflare R2 Credentials
const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID || '';
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || '';
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || '';
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME || 'corp-task-deliverables';

// Cookie Lifespan Constants (8 Hours standard corporate session)
const SESSION_EXPIRATION_MS = 8 * 60 * 60 * 1000;
const SESSION_EXPIRATION_STR = '8h';

// File Upload Constraints
const MAX_SINGLE_FILE_SIZE_BYTES = 30 * 1024 * 1024; // 30 Megabytes
const MAX_CONCURRENT_ATTACHMENTS = 5;

// ============================================================================
// 2. LOGGING & AUDIT UTILITIES
// ============================================================================

const Logger = {
  info(message, context = 'SERVER') {
    const timestamp = new Date().toISOString();
    console.log(`\x1b[32m[${timestamp}] [INFO] [${context}]\x1b[0m ${message}`);
  },
  warn(message, context = 'SECURITY') {
    const timestamp = new Date().toISOString();
    console.warn(`\x1b[33m[${timestamp}] [WARN] [${context}]\x1b[0m ${message}`);
  },
  error(message, errorObject = null, context = 'SYSTEM') {
    const timestamp = new Date().toISOString();
    console.error(`\x1b[31m[${timestamp}] [ERROR] [${context}]\x1b[0m ${message}`);
    if (errorObject && errorObject.stack) {
      console.error(`\x1b[31m${errorObject.stack}\x1b[0m`);
    }
  }
};

// ============================================================================
// 2.1 CLOUDFLARE R2 S3 CLIENT INITIALIZATION
// ============================================================================

const r2Client = new S3Client({
  region: 'auto',
  endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: R2_ACCESS_KEY_ID,
    secretAccessKey: R2_SECRET_ACCESS_KEY
  }
});

// ============================================================================
// 3. EXPRESS APPLICATION INITIALIZATION & MIDDLEWARES
// ============================================================================

const app = express();

// High Payload Allowance for Multi-part Buffer Streams
app.use(express.json({ limit: '150mb' }));
app.use(express.urlencoded({ limit: '150mb', extended: true }));
app.use(cookieParser());

// Static File Delivery
app.use(express.static(path.join(__dirname, 'public')));

// Multer In-Memory Storage Buffer Configuration
const uploadMemoryStorage = multer.memoryStorage();
const uploadHandler = multer({
  storage: uploadMemoryStorage,
  limits: {
    fileSize: MAX_SINGLE_FILE_SIZE_BYTES,
    files: MAX_CONCURRENT_ATTACHMENTS
  },
  fileFilter: (req, file, callback) => {
    callback(null, true);
  }
});

// ============================================================================
// 4. DATABASE CONNECTION & LIFECYCLE MANAGEMENT
// ============================================================================

const mongooseOptions = {
  autoIndex: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  family: 4
};

mongoose.connect(MONGODB_URI, mongooseOptions)
  .then(() => {
    Logger.info('Successfully established connection to MongoDB Corporate Cluster.', 'DATABASE');
    initializeDatabaseIndexes();
    bootstrapSeedAccounts();
  })
  .catch((err) => {
    Logger.error('Critical failure connecting to MongoDB instance.', err, 'DATABASE');
  });

mongoose.connection.on('disconnected', () => {
  Logger.warn('MongoDB connection lost. Attempting auto-reconnection...', 'DATABASE');
});

mongoose.connection.on('error', (err) => {
  Logger.error('Mongoose internal driver error observed.', err, 'DATABASE');
});

// ============================================================================
// 5. MONGOOSE DATA SCHEMAS & MODELS
// ============================================================================

/**
 * Corporate Employee Account Schema
 */
const CorporateEmployeeAccountSchema = new mongoose.Schema({
  staff_id: {
    type: String,
    required: [true, 'Staff ID is required.'],
    unique: true,
    trim: true,
    index: true
  },
  username: {
    type: String,
    required: [true, 'Username is required.'],
    unique: true,
    trim: true,
    index: true
  },
  password_hash: {
    type: String,
    required: [true, 'Password hash is required.']
  },
  full_name: {
    type: String,
    required: [true, 'Full name is required.'],
    trim: true
  },
  department: {
    type: String,
    required: [true, 'Department is required.'],
    trim: true
  },
  account_balance: {
    type: Number,
    default: 0.00,
    min: [0, 'Balance cannot be negative.']
  },
  role: {
    type: String,
    enum: ['employee', 'admin'],
    default: 'employee',
    index: true
  },
  created_at: {
    type: Date,
    default: Date.now
  }
}, { collection: 'corp_app_employee_accounts' });

/**
 * Corporate Staff Application / Administrative Request Schema
 */
const CorporateApplicationRequestSchema = new mongoose.Schema({
  applicant_username: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  applicant_name: {
    type: String,
    required: true,
    trim: true
  },
  department: {
    type: String,
    required: true,
    trim: true
  },
  request_title: {
    type: String,
    required: true,
    trim: true
  },
  request_body: {
    type: String,
    required: true,
    trim: true
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending',
    index: true
  },
  submitted_at: {
    type: Date,
    default: Date.now,
    index: true
  }
}, { collection: 'corp_app_staff_requests' });

/**
 * Stored Binary File Schema (Used for Admin Attachments in MongoDB)
 */
const StoredFileSchema = new mongoose.Schema({
  task_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'CorporateTask',
    required: true,
    index: true
  },
  file_type: {
    type: String,
    enum: ['admin_attachment', 'user_submission'],
    required: true,
    index: true
  },
  filename: {
    type: String,
    required: true,
    trim: true
  },
  mimetype: {
    type: String,
    required: true,
    default: 'application/octet-stream'
  },
  size: {
    type: Number,
    required: true
  },
  data: {
    type: Buffer,
    required: true
  },
  uploader: {
    type: String,
    required: true,
    index: true
  },
  created_at: {
    type: Date,
    default: Date.now
  }
}, { collection: 'corp_app_files' });

/**
 * Lightweight File Metadata Embedding Schema
 */
const FileMetadataSchema = new mongoose.Schema({
  file_id: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
  filename: {
    type: String,
    required: true
  },
  mimetype: {
    type: String,
    required: true
  },
  size: {
    type: Number,
    required: true
  },
  storage_type: {
    type: String,
    enum: ['mongodb', 'r2'],
    default: 'mongodb'
  },
  r2_key: {
    type: String,
    default: null
  }
}, { _id: false });

/**
 * Corporate Task Orchestration Schema
 */
const CorporateTaskSchema = new mongoose.Schema({
  task_title: {
    type: String,
    required: [true, 'Task title is required.'],
    trim: true
  },
  task_description: {
    type: String,
    required: [true, 'Task description is required.'],
    trim: true
  },
  assigned_to_username: {
    type: String,
    required: [true, 'Assignee username is required.'],
    trim: true,
    index: true
  },
  priority: {
    type: String,
    enum: ['Low', 'Normal', 'High', 'Urgent'],
    default: 'Normal'
  },
  reward_amount: {
    type: Number,
    default: 0.00,
    min: 0.00
  },
  requires_submission: {
    type: Boolean,
    default: false
  },
  submission_deadline: {
    type: Date,
    default: null
  },
  status: {
    type: String,
    enum: ['Assigned', 'Claimed', 'Submitted', 'Completed'],
    default: 'Assigned',
    index: true
  },
  reward_distributed: {
    type: Boolean,
    default: false
  },
  attachments: [FileMetadataSchema],
  submissions: [FileMetadataSchema],
  submission_notes: {
    type: String,
    default: '',
    trim: true
  },
  claimed_at: {
    type: Date,
    default: null
  },
  submitted_at: {
    type: Date,
    default: null
  },
  completed_at: {
    type: Date,
    default: null
  },
  created_at: {
    type: Date,
    default: Date.now,
    index: true
  }
}, { collection: 'corp_app_tasks' });

// Instantiate Compiled Models
const EmployeeAccount = mongoose.model('CorporateEmployeeAccount', CorporateEmployeeAccountSchema);
const EmployeeRequest = mongoose.model('CorporateApplicationRequest', CorporateApplicationRequestSchema);
const StoredFile = mongoose.model('StoredFile', StoredFileSchema);
const TaskItem = mongoose.model('CorporateTask', CorporateTaskSchema);

// ============================================================================
// 6. DATABASE MAINTENANCE & INITIALIZATION ROUTINES
// ============================================================================

async function initializeDatabaseIndexes() {
  try {
    await EmployeeAccount.syncIndexes();
    await EmployeeRequest.syncIndexes();
    await StoredFile.syncIndexes();
    await TaskItem.syncIndexes();
    Logger.info('All database schema collections and indexes synchronized.', 'DATABASE');
  } catch (err) {
    Logger.error('Failed to sync collection indexes.', err, 'DATABASE');
  }
}

async function bootstrapSeedAccounts() {
  try {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);

    // 1. Check Default Employee Account
    const defaultEmployeeCount = await EmployeeAccount.countDocuments({ role: 'employee' });
    if (defaultEmployeeCount === 0) {
      const defaultEmployeeHash = await bcrypt.hash('Employee@2026', salt);
      const seedEmployee = new EmployeeAccount({
        staff_id: 'EMP-9081',
        username: 'corp_employee',
        password_hash: defaultEmployeeHash,
        full_name: 'Alex Vance',
        department: 'Infrastructure Operations',
        account_balance: 150.00,
        role: 'employee'
      });
      await seedEmployee.save();
      Logger.info('Default seed employee account created: corp_employee / Employee@2026', 'SEED');
    }

    // 2. Check Default Administrator Account
    const defaultAdminCount = await EmployeeAccount.countDocuments({ role: 'admin' });
    if (defaultAdminCount === 0) {
      const defaultAdminHash = await bcrypt.hash('Admin@2026', salt);
      const seedAdmin = new EmployeeAccount({
        staff_id: 'ADM-0001',
        username: 'corp_admin',
        password_hash: defaultAdminHash,
        full_name: 'Lead Operations Executive',
        department: 'Headquarters System Control',
        account_balance: 0.00,
        role: 'admin'
      });
      await seedAdmin.save();
      Logger.info('Default seed administrator account created: corp_admin / Admin@2026', 'SEED');
    }
  } catch (err) {
    Logger.error('Error executing initial account bootstrap routines.', err, 'SEED');
  }
}

// ============================================================================
// 7. AUTHENTICATION & SECURITY MIDDLEWARES
// ============================================================================

/**
 * Gate Passcode Verification Middleware
 */
const checkGateAccess = (req, res, next) => {
  const gateToken = req.cookies.corp_site_gate_pass;
  
  if (!gateToken) {
    return res.status(403).json({
      success: false,
      gateLocked: true,
      message: 'Access gate locked. Administrator passcode validation required.'
    });
  }

  jwt.verify(gateToken, GATE_SECRET, (err, decoded) => {
    if (err || !decoded || !decoded.adminGatePassed) {
      return res.status(403).json({
        success: false,
        gateLocked: true,
        message: 'Security gate credentials expired. Please unlock the gate again.'
      });
    }
    next();
  });
};

/**
 * Employee Role JWT Verification Middleware (With Auto-Cookie Clearing on Expire)
 */
const authenticateEmployeeToken = (req, res, next) => {
  const token = req.cookies.corp_auth_token;
  
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Authentication session token not found. Please log in.'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err || !decodedUser) {
      res.clearCookie('corp_auth_token');
      return res.status(403).json({
        success: false,
        message: 'Your active session has expired or is invalid. Please log in again.'
      });
    }
    req.user = decodedUser;
    next();
  });
};

/**
 * Administrator Role JWT Verification Middleware
 */
const authenticateAdminToken = (req, res, next) => {
  const token = req.cookies.corp_admin_auth_token;
  
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Administrative privileges token missing. Authentication required.'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err || !decodedUser || decodedUser.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Access Denied: Insufficient authorization level.'
      });
    }
    req.admin = decodedUser;
    next();
  });
};

// ============================================================================
// 8. API ROUTE DEFINITIONS: GATE & PUBLIC AUTHENTICATION
// ============================================================================

/**
 * POST /api/gate/verify
 * Unlocks the admin environment gate using the shared environment secret.
 */
app.post('/api/gate/verify', (req, res) => {
  const { password } = req.body;
  
  if (!password || typeof password !== 'string') {
    return res.status(400).json({
      success: false,
      message: 'Passcode cannot be empty.'
    });
  }

  if (password.trim() !== SITE_GATE_PASSWORD) {
    Logger.warn(`Failed gate access attempt with code: ${password.trim()}`, 'SECURITY');
    return res.status(401).json({
      success: false,
      message: 'Invalid environment passcode. Access denied.'
    });
  }

  const gateToken = jwt.sign(
    { adminGatePassed: true, unlockedAt: new Date().toISOString() },
    GATE_SECRET,
    { expiresIn: SESSION_EXPIRATION_STR }
  );

  res.cookie('corp_site_gate_pass', gateToken, {
    httpOnly: false,
    secure: NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: SESSION_EXPIRATION_MS
  });

  Logger.info('Administrative security gate successfully unlocked.', 'SECURITY');
  return res.json({
    success: true,
    message: 'Gate unlocked successfully.'
  });
});

// ============================================================================
// 9. API ROUTE DEFINITIONS: EMPLOYEE WORKSPACE
// ============================================================================

/**
 * POST /api/auth/login
 * Employee Authentication Endpoint (Supports Case-Insensitive Matching)
 */
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Both username/staff ID and password are required.'
    });
  }

  try {
    const rawIdentifier = String(username).trim();
    const escapedIdentifier = rawIdentifier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    const employee = await EmployeeAccount.findOne({
      $or: [
        { username: new RegExp(`^${escapedIdentifier}$`, 'i') },
        { staff_id: new RegExp(`^${escapedIdentifier}$`, 'i') }
      ],
      role: 'employee'
    });

    if (!employee) {
      return res.status(401).json({
        success: false,
        message: 'Employee account credentials invalid or not found.'
      });
    }

    const isMatch = await bcrypt.compare(password, employee.password_hash);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect password supplied.'
      });
    }

    const sessionPayload = {
      staff_id: employee.staff_id,
      username: employee.username,
      full_name: employee.full_name,
      department: employee.department,
      role: 'employee'
    };

    const authToken = jwt.sign(sessionPayload, JWT_SECRET, { expiresIn: SESSION_EXPIRATION_STR });

    res.cookie('corp_auth_token', authToken, {
      httpOnly: false,
      secure: NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: SESSION_EXPIRATION_MS
    });

    Logger.info(`Employee logged in successfully: ${employee.username} (${employee.staff_id})`, 'AUTH');

    return res.json({
      success: true,
      message: 'Login successful.',
      user: sessionPayload
    });
  } catch (error) {
    Logger.error('Internal error during employee login.', error, 'AUTH');
    return res.status(500).json({
      success: false,
      message: 'Server error while processing authentication request.'
    });
  }
});

/**
 * GET /api/auth/session
 * Real-time Session Check & Profile/Balance Refresher
 */
app.get('/api/auth/session', authenticateEmployeeToken, async (req, res) => {
  try {
    const escapedUser = String(req.user.username).trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const employee = await EmployeeAccount.findOne({
      username: new RegExp(`^${escapedUser}$`, 'i')
    });
    
    if (!employee) {
      res.clearCookie('corp_auth_token');
      return res.status(404).json({
        success: false,
        message: 'Active profile data not found.'
      });
    }

    return res.json({
      success: true,
      user: {
        staff_id: employee.staff_id,
        username: employee.username,
        full_name: employee.full_name,
        department: employee.department,
        account_balance: employee.account_balance || 0.00
      }
    });
  } catch (error) {
    Logger.error('Failed to retrieve employee profile session state.', error, 'AUTH');
    return res.status(500).json({
      success: false,
      message: 'Database query failed.'
    });
  }
});

/**
 * POST /api/auth/logout
 * Destroys the Employee Session Cookie
 */
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('corp_auth_token');
  return res.json({
    success: true,
    message: 'Employee session cleared.'
  });
});

/**
 * GET /api/tasks/list
 * Retrieves all tasks dispatched to the logged-in employee
 */
app.get('/api/tasks/list', authenticateEmployeeToken, async (req, res) => {
  try {
    const escapedUser = String(req.user.username).trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const tasks = await TaskItem.find({
      assigned_to_username: new RegExp(`^${escapedUser}$`, 'i')
    })
      .sort({ created_at: -1 })
      .lean();

    return res.json({
      success: true,
      data: tasks
    });
  } catch (error) {
    Logger.error('Error fetching employee task stream.', error, 'TASKS');
    return res.status(500).json({
      success: false,
      message: 'Failed to fetch tasks from cluster.'
    });
  }
});

/**
 * POST /api/tasks/claim/:id
 * Claims an unassigned task
 */
app.post('/api/tasks/claim/:id', authenticateEmployeeToken, async (req, res) => {
  try {
    const taskId = req.params.id;
    const escapedUser = String(req.user.username).trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    
    const task = await TaskItem.findOne({
      _id: taskId,
      assigned_to_username: new RegExp(`^${escapedUser}$`, 'i')
    });

    if (!task) {
      return res.status(404).json({
        success: false,
        message: 'Task item not found or you lack claim permissions.'
      });
    }

    if (task.status !== 'Assigned') {
      return res.status(400).json({
        success: false,
        message: 'Task is already in progress, submitted, or marked completed.'
      });
    }

    task.status = 'Claimed';
    task.claimed_at = new Date();
    await task.save();

    Logger.info(`Task [${task.task_title}] claimed by user [${req.user.username}]`, 'TASKS');

    return res.json({
      success: true,
      message: 'Task claimed successfully!',
      data: task
    });
  } catch (error) {
    Logger.error('Failed to claim task item.', error, 'TASKS');
    return res.status(500).json({
      success: false,
      message: 'Internal error updating task claim status.'
    });
  }
});

/**
 * POST /api/tasks/submit-deliverables/:id
 * Uploads Deliverables to Cloudflare R2 (Supports up to 5 files <= 30MB each)
 */
app.post('/api/tasks/submit-deliverables/:id', 
  authenticateEmployeeToken, 
  uploadHandler.array('deliverables', MAX_CONCURRENT_ATTACHMENTS), 
  async (req, res) => {
    try {
      const taskId = req.params.id;
      const escapedUser = String(req.user.username).trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      const task = await TaskItem.findOne({
        _id: taskId,
        assigned_to_username: new RegExp(`^${escapedUser}$`, 'i')
      });

      if (!task) {
        return res.status(404).json({
          success: false,
          message: 'Task not found or access denied.'
        });
      }

      // Check Submission Deadline
      if (task.submission_deadline && new Date() > new Date(task.submission_deadline)) {
        return res.status(400).json({
          success: false,
          message: 'Task submission deadline has expired. Submissions are now locked.'
        });
      }

      const uploadedFiles = req.files || [];

      if (task.requires_submission && uploadedFiles.length === 0 && (!task.submissions || task.submissions.length === 0)) {
        return res.status(400).json({
          success: false,
          message: 'This task strictly mandates deliverable attachments.'
        });
      }

      // Purge prior user deliverable files from R2 & MongoDB if resubmitting
      if (uploadedFiles.length > 0 && task.submissions && task.submissions.length > 0) {
        const priorMongoIds = [];
        const priorR2Objects = [];

        for (const s of task.submissions) {
          if (s.storage_type === 'r2' && s.r2_key) {
            priorR2Objects.push({ Key: s.r2_key });
          } else if (s.file_id) {
            priorMongoIds.push(s.file_id);
          }
        }

        if (priorMongoIds.length > 0) {
          await StoredFile.deleteMany({ _id: { $in: priorMongoIds } });
        }

        if (priorR2Objects.length > 0 && R2_BUCKET_NAME) {
          try {
            await r2Client.send(new DeleteObjectsCommand({
              Bucket: R2_BUCKET_NAME,
              Delete: { Objects: priorR2Objects }
            }));
          } catch (r2DelErr) {
            Logger.warn(`Failed to cleanup previous R2 deliverables: ${r2DelErr.message}`, 'DELIVERABLES');
          }
        }
      }

      const metadataList = [];

      for (const file of uploadedFiles) {
        const decodedFilename = Buffer.from(file.originalname, 'latin1').toString('utf8');
        const generatedFileId = new mongoose.Types.ObjectId();
        const r2ObjectKey = `submissions/${task._id}/${generatedFileId}_${encodeURIComponent(decodedFilename)}`;

        // Upload directly to Cloudflare R2
        await r2Client.send(new PutObjectCommand({
          Bucket: R2_BUCKET_NAME,
          Key: r2ObjectKey,
          Body: file.buffer,
          ContentType: file.mimetype || 'application/octet-stream',
          Metadata: {
            task_id: String(task._id),
            uploader: req.user.username,
            original_filename: encodeURIComponent(decodedFilename)
          }
        }));

        metadataList.push({
          file_id: generatedFileId,
          filename: decodedFilename,
          mimetype: file.mimetype || 'application/octet-stream',
          size: file.size,
          storage_type: 'r2',
          r2_key: r2ObjectKey
        });
      }

      if (metadataList.length > 0) {
        task.submissions = metadataList;
      }

      task.submission_notes = (req.body.notes || '').trim();
      task.status = 'Submitted';
      task.submitted_at = new Date();
      await task.save();

      Logger.info(`Deliverables submitted to Cloudflare R2 for task [${task.task_title}] by [${req.user.username}]`, 'DELIVERABLES');

      return res.json({
        success: true,
        message: 'Deliverables and files uploaded successfully to Cloudflare R2!',
        data: task
      });
    } catch (error) {
      Logger.error('Failed to save deliverable file stream to Cloudflare R2.', error, 'DELIVERABLES');
      return res.status(500).json({
        success: false,
        message: 'Failed to process deliverable upload.'
      });
    }
  }
);

/**
 * POST /api/requests/submit
 * Submits an operational/administrative request
 */
app.post('/api/requests/submit', authenticateEmployeeToken, async (req, res) => {
  const { title, body } = req.body;

  if (!title || !body) {
    return res.status(400).json({
      success: false,
      message: 'Request title and detailed justification are required.'
    });
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
    Logger.info(`Staff request created: "${newRequest.request_title}" by [${req.user.username}]`, 'REQUESTS');

    return res.json({
      success: true,
      message: 'Application request submitted successfully.',
      data: newRequest
    });
  } catch (error) {
    Logger.error('Error recording employee request.', error, 'REQUESTS');
    return res.status(500).json({
      success: false,
      message: 'Failed to persist request.'
    });
  }
});

/**
 * GET /api/requests/mine
 * Fetches the user's historical requests
 */
app.get('/api/requests/mine', authenticateEmployeeToken, async (req, res) => {
  try {
    const list = await EmployeeRequest.find({ applicant_username: req.user.username })
      .sort({ submitted_at: -1 })
      .lean();

    return res.json({
      success: true,
      data: list
    });
  } catch (error) {
    Logger.error('Error retrieving staff request history.', error, 'REQUESTS');
    return res.status(500).json({
      success: false,
      message: 'Failed to read records.'
    });
  }
});

// ============================================================================
// 10. API ROUTE DEFINITIONS: UNIVERSAL FILE RETRIEVAL / DOWNLOAD ENGINE
// ============================================================================

/**
 * GET /api/files/download/:fileId
 * Universal secure streaming endpoint with RBAC inspection (R2 & MongoDB hybrid support)
 */
app.get('/api/files/download/:fileId', async (req, res) => {
  try {
    const fileId = req.params.fileId;
    if (!mongoose.Types.ObjectId.isValid(fileId)) {
      return res.status(400).json({ success: false, message: 'Invalid file ID format.' });
    }

    const empToken = req.cookies.corp_auth_token;
    const adminToken = req.cookies.corp_admin_auth_token;

    let isAuthorized = false;
    let authUser = null;

    // 1. Check Administrator Authorization
    if (adminToken) {
      try {
        const decodedAdmin = jwt.verify(adminToken, JWT_SECRET);
        if (decodedAdmin && decodedAdmin.role === 'admin') {
          isAuthorized = true;
        }
      } catch (e) {
        // Fallback to employee verification
      }
    }

    // 2. Check Employee Authorization
    if (!isAuthorized && empToken) {
      try {
        authUser = jwt.verify(empToken, JWT_SECRET);
      } catch (e) {
        // Token invalid
      }
    }

    // Attempt to locate file in Task submissions metadata (R2 Storage Route)
    const taskWithSubmission = await TaskItem.findOne({ 'submissions.file_id': fileId });

    if (taskWithSubmission) {
      const fileMeta = taskWithSubmission.submissions.find(s => s.file_id.toString() === fileId);

      // Ownership authorization check
      if (!isAuthorized) {
        if (!authUser) {
          return res.status(401).json({ success: false, message: 'Access denied: Please authenticate.' });
        }
        if (taskWithSubmission.assigned_to_username.toLowerCase() !== authUser.username.toLowerCase()) {
          return res.status(403).json({ success: false, message: 'Access forbidden: Task does not belong to you.' });
        }
      }

      // If stored in Cloudflare R2
      if (fileMeta && fileMeta.storage_type === 'r2' && fileMeta.r2_key) {
        try {
          const r2Response = await r2Client.send(new GetObjectCommand({
            Bucket: R2_BUCKET_NAME,
            Key: fileMeta.r2_key
          }));

          res.setHeader('Content-Type', fileMeta.mimetype || 'application/octet-stream');
          if (fileMeta.size) res.setHeader('Content-Length', fileMeta.size);
          res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileMeta.filename)}`);

          return r2Response.Body.pipe(res);
        } catch (r2FetchErr) {
          Logger.error('Failed to stream file directly from Cloudflare R2.', r2FetchErr, 'DOWNLOAD');
          return res.status(404).json({ success: false, message: 'Target file not found in R2 storage.' });
        }
      }
    }

    // Fallback: Check MongoDB Binary Storage (Admin attachments & legacy deliverables)
    const fileDoc = await StoredFile.findById(fileId);
    if (!fileDoc) {
      return res.status(404).json({ success: false, message: 'Target file binary not found.' });
    }

    if (!isAuthorized) {
      if (!authUser) {
        return res.status(401).json({ success: false, message: 'Access denied: Please authenticate.' });
      }

      const task = await TaskItem.findById(fileDoc.task_id);
      if (!task || task.assigned_to_username.toLowerCase() !== authUser.username.toLowerCase()) {
        return res.status(403).json({ success: false, message: 'Access forbidden: Task does not belong to you.' });
      }
    }

    res.setHeader('Content-Type', fileDoc.mimetype || 'application/octet-stream');
    res.setHeader('Content-Length', fileDoc.size);
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileDoc.filename)}`);
    
    return res.send(fileDoc.data);
  } catch (error) {
    Logger.error('Error during file stream dispatch.', error, 'DOWNLOAD');
    return res.status(500).json({ success: false, message: 'Stream generation failed.' });
  }
});

// ============================================================================
// 11. API ROUTE DEFINITIONS: ADMINISTRATOR CONSOLE
// ============================================================================

/**
 * POST /api/admin/auth/login
 * Administrator Credential Verification
 */
app.post('/api/admin/auth/login', checkGateAccess, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Administrator username and password required.'
    });
  }

  try {
    const escapedUser = String(username).trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const adminUser = await EmployeeAccount.findOne({
      username: new RegExp(`^${escapedUser}$`, 'i'),
      role: 'admin'
    });

    if (!adminUser) {
      return res.status(401).json({
        success: false,
        message: 'Administrator identity not registered.'
      });
    }

    const isMatch = await bcrypt.compare(password, adminUser.password_hash);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Administrator credentials mismatch.'
      });
    }

    const adminPayload = {
      staff_id: adminUser.staff_id,
      username: adminUser.username,
      full_name: adminUser.full_name,
      department: adminUser.department,
      role: 'admin'
    };

    const adminToken = jwt.sign(adminPayload, JWT_SECRET, { expiresIn: SESSION_EXPIRATION_STR });

    res.cookie('corp_admin_auth_token', adminToken, {
      httpOnly: false,
      secure: NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: SESSION_EXPIRATION_MS
    });

    Logger.info(`Administrator authenticated: ${adminUser.username}`, 'ADMIN_AUTH');

    return res.json({
      success: true,
      message: 'Administrator privileged session active.',
      user: adminPayload
    });
  } catch (error) {
    Logger.error('Administrator authentication error.', error, 'ADMIN_AUTH');
    return res.status(500).json({
      success: false,
      message: 'Server error validating administrator credentials.'
    });
  }
});

/**
 * GET /api/admin/auth/session
 * Confirms Admin Session
 */
app.get('/api/admin/auth/session', checkGateAccess, authenticateAdminToken, (req, res) => {
  return res.json({
    success: true,
    user: req.admin
  });
});

/**
 * POST /api/admin/auth/logout
 * Destroys Admin Cookie
 */
app.post('/api/admin/auth/logout', (req, res) => {
  res.clearCookie('corp_admin_auth_token');
  return res.json({
    success: true,
    message: 'Administrator session cleared.'
  });
});

/**
 * GET /api/admin/tasks/all
 * Retrieves All System Tasks
 */
app.get('/api/admin/tasks/all', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const tasks = await TaskItem.find().sort({ created_at: -1 }).lean();
    return res.json({
      success: true,
      data: tasks
    });
  } catch (error) {
    Logger.error('Failed to fetch full task ledger.', error, 'ADMIN_TASKS');
    return res.status(500).json({
      success: false,
      message: 'Failed to retrieve task data.'
    });
  }
});

/**
 * POST /api/admin/tasks/create-bulk
 * Dispatches Task and Attachments to Single or Multiple Assignees (Attachments Stored in MongoDB)
 */
app.post('/api/admin/tasks/create-bulk', 
  checkGateAccess, 
  authenticateAdminToken, 
  uploadHandler.array('attachments', MAX_CONCURRENT_ATTACHMENTS), 
  async (req, res) => {
    const { title, description, assignees, priority, reward_amount, requires_submission, submission_deadline } = req.body;

    if (!title || !description || !assignees) {
      return res.status(400).json({
        success: false,
        message: 'Task title, description, and target assignees are required.'
      });
    }

    let assigneeList = [];
    try {
      assigneeList = typeof assignees === 'string' ? JSON.parse(assignees) : assignees;
    } catch (e) {
      assigneeList = [assignees];
    }

    if (!Array.isArray(assigneeList) || assigneeList.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'At least one valid assignee must be selected.'
      });
    }

    try {
      const rawUploadedFiles = req.files || [];
      const createdTaskIds = [];

      for (const rawUsername of assigneeList) {
        const targetUsername = String(rawUsername).trim();

        const newTask = new TaskItem({
          task_title: title.trim(),
          task_description: description.trim(),
          assigned_to_username: targetUsername,
          priority: priority || 'Normal',
          reward_amount: parseFloat(reward_amount) || 0.00,
          requires_submission: requires_submission === 'true' || requires_submission === true,
          submission_deadline: submission_deadline ? new Date(submission_deadline) : null,
          status: 'Assigned',
          attachments: []
        });

        await newTask.save();
        createdTaskIds.push(newTask._id);

        const fileMetadataList = [];
        for (const f of rawUploadedFiles) {
          const decodedFilename = Buffer.from(f.originalname, 'latin1').toString('utf8');
          
          const newFileDoc = new StoredFile({
            task_id: newTask._id,
            file_type: 'admin_attachment',
            filename: decodedFilename,
            mimetype: f.mimetype,
            size: f.size,
            data: f.buffer,
            uploader: req.admin.username
          });

          await newFileDoc.save();

          fileMetadataList.push({
            file_id: newFileDoc._id,
            filename: newFileDoc.filename,
            mimetype: newFileDoc.mimetype,
            size: newFileDoc.size,
            storage_type: 'mongodb'
          });
        }

        newTask.attachments = fileMetadataList;
        await newTask.save();
      }

      Logger.info(`Bulk task "${title.trim()}" dispatched to ${assigneeList.length} employee(s).`, 'ADMIN_TASKS');

      return res.json({
        success: true,
        message: `Task successfully dispatched to ${assigneeList.length} employee account(s)!`,
        dispatchedCount: assigneeList.length
      });
    } catch (error) {
      Logger.error('Failed to create bulk task entries.', error, 'ADMIN_TASKS');
      return res.status(500).json({
        success: false,
        message: 'Failed to process bulk task dispatch.'
      });
    }
  }
);

/**
 * POST /api/admin/tasks/complete/:id
 * Completes Task & Automates Financial Balance Credit to Employee
 */
app.post('/api/admin/tasks/complete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const taskId = req.params.id;
    const task = await TaskItem.findById(taskId);

    if (!task) {
      return res.status(404).json({
        success: false,
        message: 'Target task not found.'
      });
    }

    if (task.status === 'Completed') {
      return res.status(400).json({
        success: false,
        message: 'Task has already been verified and closed.'
      });
    }

    task.status = 'Completed';
    task.completed_at = new Date();

    if (!task.reward_distributed && task.reward_amount > 0) {
      const escapedUser = String(task.assigned_to_username).trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      await EmployeeAccount.findOneAndUpdate(
        { username: new RegExp(`^${escapedUser}$`, 'i') },
        { $inc: { account_balance: task.reward_amount } }
      );
      task.reward_distributed = true;
      Logger.info(`Reward balance credited: ¥${task.reward_amount.toFixed(2)} to [${task.assigned_to_username}]`, 'FINANCE');
    }

    await task.save();

    return res.json({
      success: true,
      message: `Task marked as completed! Reward of ¥${task.reward_amount.toFixed(2)} has been credited to ${task.assigned_to_username}.`,
      data: task
    });
  } catch (error) {
    Logger.error('Failed to complete task and distribute rewards.', error, 'ADMIN_TASKS');
    return res.status(500).json({
      success: false,
      message: 'Failed to mark task as completed.'
    });
  }
});

/**
 * DELETE /api/admin/tasks/delete/:id
 * Purges Task and Associated Binary Files (MongoDB & R2)
 */
app.delete('/api/admin/tasks/delete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const taskId = req.params.id;
    
    // Check if task has R2 deliverable files to clean up
    const task = await TaskItem.findById(taskId);
    if (task && task.submissions && task.submissions.length > 0) {
      const r2Objects = task.submissions
        .filter(s => s.storage_type === 'r2' && s.r2_key)
        .map(s => ({ Key: s.r2_key }));

      if (r2Objects.length > 0 && R2_BUCKET_NAME) {
        try {
          await r2Client.send(new DeleteObjectsCommand({
            Bucket: R2_BUCKET_NAME,
            Delete: { Objects: r2Objects }
          }));
        } catch (r2Err) {
          Logger.warn(`Failed to clean up R2 deliverables on task delete: ${r2Err.message}`, 'ADMIN_TASKS');
        }
      }
    }

    await StoredFile.deleteMany({ task_id: taskId });
    const result = await TaskItem.findByIdAndDelete(taskId);

    if (!result) {
      return res.status(404).json({
        success: false,
        message: 'Task item not found.'
      });
    }

    Logger.info(`Task and associated binary attachments permanently purged: [${taskId}]`, 'ADMIN_TASKS');
    return res.json({
      success: true,
      message: 'Task and all related file artifacts permanently removed.'
    });
  } catch (error) {
    Logger.error('Failed to delete task.', error, 'ADMIN_TASKS');
    return res.status(500).json({
      success: false,
      message: 'Failed to delete task item.'
    });
  }
});

/**
 * GET /api/admin/employees/list
 * Lists All Staff Accounts
 */
app.get('/api/admin/employees/list', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const list = await EmployeeAccount.find({ role: 'employee' })
      .sort({ created_at: -1 })
      .lean();

    return res.json({
      success: true,
      data: list
    });
  } catch (error) {
    Logger.error('Failed to list staff accounts.', error, 'ADMIN_EMPLOYEES');
    return res.status(500).json({
      success: false,
      message: 'Failed to retrieve employee directory.'
    });
  }
});

/**
 * POST /api/admin/employees/create
 * Registers New Staff Account
 */
app.post('/api/admin/employees/create', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const { staff_id, username, password, full_name, department, initial_balance } = req.body;

  if (!staff_id || !username || !password || !full_name || !department) {
    return res.status(400).json({
      success: false,
      message: 'All employee profile fields must be provided.'
    });
  }

  try {
    const formattedUsername = String(username).trim();
    const formattedStaffId = String(staff_id).trim();

    const existingAccount = await EmployeeAccount.findOne({
      $or: [
        { username: new RegExp(`^${formattedUsername.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') },
        { staff_id: new RegExp(`^${formattedStaffId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') }
      ]
    });

    if (existingAccount) {
      return res.status(409).json({
        success: false,
        message: 'An employee with this Staff ID or username already exists.'
      });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const newStaffAccount = new EmployeeAccount({
      staff_id: formattedStaffId,
      username: formattedUsername,
      password_hash,
      full_name: String(full_name).trim(),
      department: String(department).trim(),
      account_balance: parseFloat(initial_balance) || 0.00,
      role: 'employee'
    });

    await newStaffAccount.save();
    Logger.info(`New staff profile created: ${newStaffAccount.username} (${newStaffAccount.staff_id})`, 'ADMIN_EMPLOYEES');

    return res.json({
      success: true,
      message: 'New employee account successfully registered.'
    });
  } catch (error) {
    Logger.error('Failed to register employee profile.', error, 'ADMIN_EMPLOYEES');
    return res.status(500).json({
      success: false,
      message: 'Server error creating employee record.'
    });
  }
});

/**
 * PATCH /api/admin/employees/balance/:id
 * Manual Balance Override / Adjustment
 */
app.patch('/api/admin/employees/balance/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const { balance } = req.body;

  if (balance === undefined || isNaN(parseFloat(balance)) || parseFloat(balance) < 0) {
    return res.status(400).json({
      success: false,
      message: 'Valid non-negative balance value is required.'
    });
  }

  try {
    const updatedEmployee = await EmployeeAccount.findByIdAndUpdate(
      req.params.id,
      { account_balance: parseFloat(balance) },
      { new: true }
    );

    if (!updatedEmployee) {
      return res.status(404).json({
        success: false,
        message: 'Target employee account not found.'
      });
    }

    Logger.info(`Manual balance override for [${updatedEmployee.username}]: ¥${updatedEmployee.account_balance.toFixed(2)}`, 'FINANCE');

    return res.json({
      success: true,
      message: 'Employee balance updated successfully.',
      data: updatedEmployee
    });
  } catch (error) {
    Logger.error('Failed to update balance.', error, 'ADMIN_EMPLOYEES');
    return res.status(500).json({
      success: false,
      message: 'Server error modifying balance.'
    });
  }
});

/**
 * DELETE /api/admin/employees/delete/:id
 * Deregisters Employee Profile
 */
app.delete('/api/admin/employees/delete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const target = await EmployeeAccount.findByIdAndDelete(req.params.id);
    if (!target) {
      return res.status(404).json({
        success: false,
        message: 'Account not found.'
      });
    }

    Logger.warn(`Employee account deregistered: ${target.username} (${target.staff_id})`, 'ADMIN_EMPLOYEES');
    return res.json({
      success: true,
      message: 'Employee account deregistered successfully.'
    });
  } catch (error) {
    Logger.error('Failed to delete staff profile.', error, 'ADMIN_EMPLOYEES');
    return res.status(500).json({
      success: false,
      message: 'Server error removing employee record.'
    });
  }
});

/**
 * GET /api/admin/requests/all
 * Lists All Staff Applications
 */
app.get('/api/admin/requests/all', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    const requests = await EmployeeRequest.find().sort({ submitted_at: -1 }).lean();
    return res.json({
      success: true,
      data: requests
    });
  } catch (error) {
    Logger.error('Failed to fetch requests.', error, 'ADMIN_REQUESTS');
    return res.status(500).json({
      success: false,
      message: 'Failed to read request records.'
    });
  }
});

/**
 * PATCH /api/admin/requests/status/:id
 * Updates Request Workflow Status
 */
app.patch('/api/admin/requests/status/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected', 'pending'].includes(status)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid workflow status.'
    });
  }

  try {
    const updated = await EmployeeRequest.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );

    return res.json({
      success: true,
      message: `Request status transitioned to "${status}".`,
      data: updated
    });
  } catch (error) {
    Logger.error('Failed to update request state.', error, 'ADMIN_REQUESTS');
    return res.status(500).json({
      success: false,
      message: 'Failed to update request.'
    });
  }
});

/**
 * DELETE /api/admin/requests/delete/:id
 * Purges Historical Request Record
 */
app.delete('/api/admin/requests/delete/:id', checkGateAccess, authenticateAdminToken, async (req, res) => {
  try {
    await EmployeeRequest.findByIdAndDelete(req.params.id);
    return res.json({
      success: true,
      message: 'Request record cleared from database.'
    });
  } catch (error) {
    Logger.error('Failed to purge request.', error, 'ADMIN_REQUESTS');
    return res.status(500).json({
      success: false,
      message: 'Server error during record deletion.'
    });
  }
});

// ============================================================================
// 12. FALLBACK ROUTE & SERVER LAUNCH
// ============================================================================

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const server = http.createServer(app);

server.listen(PORT, () => {
  Logger.info(`Corporate Platform Engine active on port ${PORT} [Env: ${NODE_ENV}]`, 'SERVER');
});

process.on('SIGTERM', () => {
  Logger.info('SIGTERM received. Shutting down gracefully...', 'SERVER');
  server.close(() => {
    mongoose.connection.close(false, () => {
      Logger.info('MongoDB connections closed. Process terminating.', 'SERVER');
      process.exit(0);
    });
  });
});
