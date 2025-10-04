// api/discussions/submit.js
import { connectToDatabase } from '../config/database.js';
import { put } from '@vercel/blob';
import rateLimit from '../utils/rateLimiter.js';

export default async function handler(req, res) {
  // Rate limiting
  try {
    await rateLimit(req, res);
  } catch {
    return res.status(429).json({ error: 'Too many requests' });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const {
      userName,
      userEmail,
      topicCategory,
      topicPriority,
      topicTitle,
      topicDescription,
      topicTags,
      systemInfo,
      additionalContext,
      communityGuidelines,
      emailNotifications,
      publicProfile
    } = req.body;

    // Validation
    if (!userName || !userEmail || !topicCategory || !topicTitle || !topicDescription) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!communityGuidelines) {
      return res.status(400).json({ error: 'Must agree to community guidelines' });
    }

    // Connect to database
    const db = await connectToDatabase();
    
    // Generate tracking ID
    const trackingId = 'TOPIC-' + Date.now().toString(36).toUpperCase();

    // Create discussion document
    const discussion = {
      trackingId,
      author: publicProfile ? userName : 'Anonymous User',
      authorEmail: userEmail,
      category: topicCategory,
      priority: topicPriority || 'normal',
      title: topicTitle,
      description: topicDescription,
      tags: topicTags ? topicTags.split(',').map(tag => tag.trim()) : [],
      systemInfo: systemInfo || null,
      additionalContext: additionalContext || null,
      emailNotifications,
      publicProfile,
      status: 'pending', // pending, approved, rejected
      createdAt: new Date(),
      updatedAt: new Date(),
      replies: [],
      views: 0,
      likes: 0
    };

    // Insert into database
    await db.collection('discussions').insertOne(discussion);

    // Send notification email (if configured)
    try {
      await sendNotificationEmail({
        to: userEmail,
        type: 'discussion_submitted',
        data: { trackingId, title: topicTitle }
      });
      
      await sendModeratorNotification({
        type: 'new_discussion',
        data: discussion
      });
    } catch (emailError) {
      console.error('Email notification failed:', emailError);
      // Continue - don't fail the submission for email errors
    }

    // Log activity
    await db.collection('activity_log').insertOne({
      type: 'discussion_submitted',
      trackingId,
      userEmail,
      timestamp: new Date(),
      metadata: {
        category: topicCategory,
        title: topicTitle
      }
    });

    res.status(201).json({
      success: true,
      message: 'Discussion submitted successfully',
      trackingId,
      status: 'pending'
    });

  } catch (error) {
    console.error('Discussion submission error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Helper function to send notification emails
async function sendNotificationEmail({ to, type, data }) {
  const nodemailer = require('nodemailer');
  
  // Configure your email service (Gmail, SendGrid, etc.)
  const transporter = nodemailer.createTransporter({
    // Add your email configuration here
  });

  const templates = {
    discussion_submitted: {
      subject: `Discussion Submitted - ${data.trackingId}`,
      html: `
        <h2>Discussion Submitted Successfully</h2>
        <p>Thank you for submitting your discussion topic!</p>
        <p><strong>Tracking ID:</strong> ${data.trackingId}</p>
        <p><strong>Title:</strong> ${data.title}</p>
        <p>Your submission will be reviewed by our moderators and published once approved.</p>
      `
    }
  };

  const template = templates[type];
  if (!template) return;

  await transporter.sendMail({
    to,
    subject: template.subject,
    html: template.html
  });
}

// Helper function to notify moderators
async function sendModeratorNotification({ type, data }) {
  // Send notification to moderators about new submissions
  // This could be email, Slack, Discord, etc.
}