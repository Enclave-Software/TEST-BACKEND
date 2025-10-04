// api/admin/auth/change-password.js
import { connectToDatabase } from '../../config/database.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { verifyToken } from '../../middleware/auth.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Verify authentication token
    const user = await verifyToken(req, res);
    if (!user) return; // verifyToken handles the response

    const { currentPassword, newPassword, confirmPassword } = req.body;

    // Validation
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'All password fields are required' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'New passwords do not match' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    // Password strength validation
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({ 
        error: 'Password must contain uppercase, lowercase, number and special character' 
      });
    }

    const db = await connectToDatabase();
    
    // Get current user from database
    const currentUser = await db.collection('moderators').findOne({ _id: user.userId });
    
    if (!currentUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password (unless it's a forced password change)
    if (!currentUser.mustChangePassword) {
      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, currentUser.passwordHash);
      if (!isCurrentPasswordValid) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
    }

    // Check if new password is different from current
    const isSamePassword = await bcrypt.compare(newPassword, currentUser.passwordHash);
    if (isSamePassword) {
      return res.status(400).json({ error: 'New password must be different from current password' });
    }

    // Hash new password
    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    // Update password in database
    await db.collection('moderators').updateOne(
      { _id: user.userId },
      { 
        $set: { 
          passwordHash: newPasswordHash,
          mustChangePassword: false,
          passwordChangedAt: new Date(),
          passwordHistory: {
            $push: {
              $each: [currentUser.passwordHash],
              $slice: -5 // Keep last 5 passwords to prevent reuse
            }
          }
        }
      }
    );

    // Log password change event
    await db.collection('admin_log').insertOne({
      type: 'password_changed',
      userId: user.userId,
      email: user.email,
      timestamp: new Date(),
      ipAddress: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      forced: currentUser.mustChangePassword || false
    });

    // Generate new token (optional - invalidates old sessions)
    const newToken = jwt.sign(
      { 
        userId: user.userId, 
        email: user.email, 
        role: user.role,
        mustChangePassword: false
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.status(200).json({
      success: true,
      message: 'Password changed successfully',
      token: newToken,
      mustChangePassword: false
    });

  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}