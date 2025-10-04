// api/admin/discussions/approve.js - Approve discussion topics
import { connectToDatabase } from '../../config/database.js';
import { verifyToken, requirePermission, auditLog } from '../../middleware/auth.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Verify authentication and permissions
    const user = await verifyToken(req, res);
    if (!user) return;

    const db = await connectToDatabase();
    const userData = await db.collection('moderators').findOne({ _id: user.userId });
    
    if (!userData.permissions.includes('approve_submissions') && userData.role !== 'admin') {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const { topicId, action, reason } = req.body;

    if (!topicId || !action) {
      return res.status(400).json({ error: 'Topic ID and action are required' });
    }

    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Action must be approve or reject' });
    }

    // Find the discussion
    const discussion = await db.collection('discussions').findOne({ trackingId: topicId });
    
    if (!discussion) {
      return res.status(404).json({ error: 'Discussion not found' });
    }

    if (discussion.status !== 'pending') {
      return res.status(400).json({ error: 'Discussion has already been moderated' });
    }

    // Update discussion status
    const updateData = {
      status: action === 'approve' ? 'approved' : 'rejected',
      moderatedBy: userData.email,
      moderatedAt: new Date(),
      moderationReason: reason || null,
      updatedAt: new Date()
    };

    await db.collection('discussions').updateOne(
      { trackingId: topicId },
      { $set: updateData }
    );

    // Send notification email to user
    try {
      await sendModerationNotification({
        to: discussion.authorEmail,
        action,
        topicTitle: discussion.title,
        trackingId: topicId,
        reason: reason
      });
    } catch (emailError) {
      console.error('Email notification failed:', emailError);
    }

    // Log moderation action
    await auditLog('discussion_moderated', user.userId, {
      topicId,
      action,
      reason,
      authorEmail: discussion.authorEmail,
      ipAddress: req.headers['x-forwarded-for'] || req.connection.remoteAddress
    });

    // Update moderation statistics
    await updateModerationStats(db, action);

    res.status(200).json({
      success: true,
      message: `Discussion ${action}d successfully`,
      topicId,
      status: updateData.status
    });

  } catch (error) {
    console.error('Discussion moderation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Helper function to send moderation notification
async function sendModerationNotification({ to, action, topicTitle, trackingId, reason }) {
  const nodemailer = require('nodemailer');
  
  const templates = {
    approve: {
      subject: `Discussion Approved - ${trackingId}`,
      html: `
        <h2>✅ Discussion Approved</h2>
        <p>Great news! Your discussion topic has been approved and is now live.</p>
        
        <div style="background: #f0f9ff; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #0ea5e9;">
          <p><strong>Topic:</strong> ${topicTitle}</p>
          <p><strong>Tracking ID:</strong> ${trackingId}</p>
          <p><strong>Status:</strong> Approved</p>
        </div>
        
        <p>Your topic is now visible to the community and others can reply and engage with your discussion.</p>
        <p><a href="https://community.enclave-messenger.com/discussions" style="background: #0ea5e9; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Discussion</a></p>
      `
    },
    reject: {
      subject: `Discussion Update - ${trackingId}`,
      html: `
        <h2>Discussion Review Update</h2>
        <p>Thank you for your submission. After review, we're unable to approve your discussion topic at this time.</p>
        
        <div style="background: #fef2f2; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #ef4444;">
          <p><strong>Topic:</strong> ${topicTitle}</p>
          <p><strong>Tracking ID:</strong> ${trackingId}</p>
          <p><strong>Status:</strong> Not Approved</p>
          ${reason ? `<p><strong>Reason:</strong> ${reason}</p>` : ''}
        </div>
        
        <p>Please review our community guidelines and feel free to submit a new topic that aligns with our standards.</p>
        <p><a href="https://community.enclave-messenger.com/guidelines">Review Guidelines</a></p>
      `
    }
  };

  const template = templates[action];
  if (!template) return;

  // Configure your email service here
  // await transporter.sendMail({ to, subject: template.subject, html: template.html });
}

// Helper function to update moderation statistics
async function updateModerationStats(db, action) {
  const today = new Date().toISOString().split('T')[0];
  
  await db.collection('moderation_stats').updateOne(
    { date: today, type: 'discussions' },
    { 
      $inc: { 
        [`actions.${action}`]: 1,
        'actions.total': 1
      }
    },
    { upsert: true }
  );
}