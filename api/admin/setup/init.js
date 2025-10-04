// api/admin/setup/init.js
import { connectToDatabase } from '../../config/database.js';
import bcrypt from 'bcryptjs';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const db = await connectToDatabase();
    
    // Check if any admin users already exist
    const existingAdmin = await db.collection('moderators').findOne({ role: 'admin' });
    
    if (existingAdmin) {
      return res.status(400).json({ error: 'Admin account already exists' });
    }

    // Create default admin account
    const saltRounds = 12;
    const defaultPasswordHash = await bcrypt.hash('admin', saltRounds);

    const defaultAdmin = {
      email: 'admin@enclave-messenger.com',
      username: 'admin',
      name: 'Administrator',
      passwordHash: defaultPasswordHash,
      mustChangePassword: true,
      role: 'admin',
      permissions: [
        'manage_discussions',
        'manage_vulnerabilities', 
        'manage_users',
        'manage_settings',
        'view_analytics',
        'approve_submissions',
        'manage_rewards'
      ],
      status: 'active',
      createdAt: new Date(),
      lastLogin: null,
      lastLoginIP: null,
      passwordChangedAt: null,
      passwordHistory: []
    };

    // Insert default admin
    await db.collection('moderators').insertOne(defaultAdmin);

    // Initialize system settings
    await db.collection('settings').insertOne({
      type: 'system',
      bugBountyEnabled: true,
      forumEnabled: true,
      autoApproveDiscussions: false,
      emailNotifications: true,
      moderationQueue: true,
      rewardLimits: {
        critical: { min: 2500, max: 5000 },
        high: { min: 500, max: 2000 },
        medium: { min: 200, max: 500 },
        low: { min: 50, max: 200 }
      },
      createdAt: new Date()
    });

    // Log initialization
    await db.collection('admin_log').insertOne({
      type: 'system_initialized',
      userId: defaultAdmin._id,
      timestamp: new Date(),
      details: {
        adminAccountCreated: true,
        systemSettingsInitialized: true
      }
    });

    res.status(200).json({
      success: true,
      message: 'System initialized successfully',
      adminCredentials: {
        email: 'admin@enclave-messenger.com',
        username: 'admin',
        defaultPassword: 'admin',
        mustChangePassword: true
      },
      note: 'Please change the default password immediately after first login'
    });

  } catch (error) {
    console.error('System initialization error:', error);
    res.status(500).json({ error: 'Failed to initialize system' });
  }
}