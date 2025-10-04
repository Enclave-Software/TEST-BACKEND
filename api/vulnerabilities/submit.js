// api/vulnerabilities/submit.js
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
      researcherName,
      researcherEmail,
      vulnerabilityTitle,
      vulnerabilityType,
      severity,
      affectedComponent,
      description,
      reproductionSteps,
      impactAssessment,
      proofOfConcept,
      suggestedFix,
      osEnvironment,
      appVersion,
      browserInfo,
      responsibleDisclosure,
      testingAuthorization,
      hallOfFameConsent
    } = req.body;

    // Validation
    if (!researcherName || !researcherEmail || !vulnerabilityTitle || 
        !vulnerabilityType || !severity || !affectedComponent || 
        !description || !reproductionSteps || !impactAssessment) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!responsibleDisclosure || !testingAuthorization) {
      return res.status(400).json({ error: 'Must agree to disclosure terms and testing authorization' });
    }

    // Connect to database
    const db = await connectToDatabase();
    
    // Generate tracking ID
    const trackingId = 'VUL-' + Date.now().toString(36).toUpperCase();

    // Calculate initial reward estimate based on severity
    const rewardEstimates = {
      low: { min: 50, max: 200 },
      medium: { min: 200, max: 500 },
      high: { min: 500, max: 2000 },
      critical: { min: 2500, max: 5000 }
    };

    // Create vulnerability document
    const vulnerability = {
      trackingId,
      researcher: researcherName,
      researcherEmail,
      title: vulnerabilityTitle,
      type: vulnerabilityType,
      severity,
      component: affectedComponent,
      description,
      reproductionSteps,
      impact: impactAssessment,
      proofOfConcept: proofOfConcept || null,
      suggestedFix: suggestedFix || null,
      environment: {
        os: osEnvironment || null,
        appVersion: appVersion || null,
        browser: browserInfo || null
      },
      consent: {
        responsibleDisclosure,
        testingAuthorization,
        hallOfFame: hallOfFameConsent || false
      },
      status: 'submitted', // submitted, triaging, confirmed, fixed, rejected, duplicate
      priority: severity === 'critical' ? 'urgent' : severity === 'high' ? 'high' : 'normal',
      rewardEstimate: rewardEstimates[severity] || rewardEstimates.low,
      actualReward: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      timeline: [{
        action: 'submitted',
        timestamp: new Date(),
        note: 'Initial vulnerability submission received'
      }],
      assignedTo: null,
      internalNotes: [],
      publicNotes: []
    };

    // Insert into database
    await db.collection('vulnerabilities').insertOne(vulnerability);

    // Send notification emails
    try {
      await sendNotificationEmail({
        to: researcherEmail,
        type: 'vulnerability_submitted',
        data: { 
          trackingId, 
          title: vulnerabilityTitle,
          severity,
          rewardEstimate: rewardEstimates[severity]
        }
      });
      
      await sendSecurityTeamAlert({
        type: 'new_vulnerability',
        data: vulnerability
      });
    } catch (emailError) {
      console.error('Email notification failed:', emailError);
    }

    // Log security event
    await db.collection('security_log').insertOne({
      type: 'vulnerability_submitted',
      trackingId,
      researcherEmail,
      severity,
      component: affectedComponent,
      timestamp: new Date(),
      ipAddress: req.headers['x-forwarded-for'] || req.connection.remoteAddress
    });

    // Update statistics
    await updateBugBountyStats(db, severity);

    res.status(201).json({
      success: true,
      message: 'Vulnerability report submitted successfully',
      trackingId,
      status: 'submitted',
      estimatedReward: rewardEstimates[severity],
      timeline: `Critical issues: 24hr response | High: 48hr | Medium/Low: 1 week`
    });

  } catch (error) {
    console.error('Vulnerability submission error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Helper functions
async function sendNotificationEmail({ to, type, data }) {
  const nodemailer = require('nodemailer');
  
  const templates = {
    vulnerability_submitted: {
      subject: `Vulnerability Report Received - ${data.trackingId}`,
      html: `
        <h2>🛡️ Vulnerability Report Submitted</h2>
        <p>Thank you for your responsible disclosure!</p>
        
        <div style="background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 8px;">
          <p><strong>Tracking ID:</strong> ${data.trackingId}</p>
          <p><strong>Title:</strong> ${data.title}</p>
          <p><strong>Severity:</strong> ${data.severity.toUpperCase()}</p>
          <p><strong>Estimated Reward:</strong> $${data.rewardEstimate.min} - $${data.rewardEstimate.max}</p>
        </div>
        
        <h3>What happens next?</h3>
        <ul>
          <li>Our security team will review your submission within 48 hours</li>
          <li>You'll receive status updates via email</li>
          <li>Critical vulnerabilities are prioritized for immediate review</li>
          <li>Rewards are processed after vulnerability confirmation and fix deployment</li>
        </ul>
        
        <p>Questions? Reply to this email or contact security@enclave-messenger.com</p>
      `
    }
  };

  // Implementation would depend on your email service
}

async function sendSecurityTeamAlert({ type, data }) {
  // Send immediate alert to security team for new vulnerabilities
  // Could use email, Slack, Discord, PagerDuty, etc.
}

async function updateBugBountyStats(db, severity) {
  const today = new Date().toISOString().split('T')[0];
  
  await db.collection('bug_bounty_stats').updateOne(
    { date: today },
    { 
      $inc: { 
        [`submissions.${severity}`]: 1,
        'submissions.total': 1
      }
    },
    { upsert: true }
  );
}