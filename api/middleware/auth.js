// api/middleware/auth.js - Authentication and Security Middleware
import jwt from 'jsonwebtoken';
import { connectToDatabase } from '../config/database.js';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import DOMPurify from 'isomorphic-dompurify';

// Rate limiting for auth endpoints
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: { error: 'Too many authentication attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Input validation and sanitization
export function validateAndSanitizeInput(input, type = 'text') {
  if (!input) return null;
  
  // Convert to string and trim
  let sanitized = String(input).trim();
  
  switch (type) {
    case 'email':
      // Email validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(sanitized)) {
        throw new Error('Invalid email format');
      }
      // Prevent SQL injection patterns in email
      if (sanitized.includes("'") || sanitized.includes('"') || sanitized.includes(';') || sanitized.includes('--')) {
        throw new Error('Invalid email format');
      }
      break;
      
    case 'username':
      // Username validation - alphanumeric and underscores only
      const usernameRegex = /^[a-zA-Z0-9_]+$/;
      if (!usernameRegex.test(sanitized)) {
        throw new Error('Username can only contain letters, numbers, and underscores');
      }
      if (sanitized.length < 3 || sanitized.length > 50) {
        throw new Error('Username must be between 3 and 50 characters');
      }
      // Prevent common injection patterns
      const injectionPatterns = [
        "'", '"', ';', '--', '/*', '*/', 'DROP', 'DELETE', 'INSERT', 'UPDATE', 
        'SELECT', 'UNION', 'EXEC', 'EXECUTE', '<script>', '</script>'
      ];
      const upperInput = sanitized.toUpperCase();
      for (const pattern of injectionPatterns) {
        if (upperInput.includes(pattern.toUpperCase())) {
          throw new Error('Invalid characters in username');
        }
      }
      break;
      
    case 'password':
      // Password validation
      if (sanitized.length < 8) {
        throw new Error('Password must be at least 8 characters long');
      }
      if (sanitized.length > 128) {
        throw new Error('Password too long');
      }
      // Check for basic strength requirements
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
      if (!passwordRegex.test(sanitized)) {
        throw new Error('Password must contain uppercase, lowercase, number and special character');
      }
      break;
      
    case 'text':
    default:
      // General text sanitization
      sanitized = DOMPurify.sanitize(sanitized);
      
      // Remove potential SQL injection patterns
      const sqlPatterns = [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION)\b)/gi,
        /(;|--|\*\/|\/\*)/g,
        /('|('')|("|(\"\"))).*(\b(OR|AND)\b).*(=|LIKE)/gi,
        /\b(OR|AND)\b.*(\=|\>|\<|\!\=|\<\>|\<\=|\>\=)\s*[\d\w]/gi
      ];
      
      for (const pattern of sqlPatterns) {
        if (pattern.test(sanitized)) {
          throw new Error('Invalid input detected');
        }
      }
      break;
  }
  
  return sanitized;
}

// Secure input validation middleware
export function validateRequest(validations) {
  return (req, res, next) => {
    try {
      const errors = [];
      
      for (const [field, rules] of Object.entries(validations)) {
        const value = req.body[field];
        
        // Check required fields
        if (rules.required && (!value || value.trim() === '')) {
          errors.push(`${field} is required`);
          continue;
        }
        
        if (value) {
          try {
            // Validate and sanitize
            const sanitized = validateAndSanitizeInput(value, rules.type || 'text');
            req.body[field] = sanitized;
            
            // Additional length validation
            if (rules.minLength && sanitized.length < rules.minLength) {
              errors.push(`${field} must be at least ${rules.minLength} characters`);
            }
            if (rules.maxLength && sanitized.length > rules.maxLength) {
              errors.push(`${field} must be no more than ${rules.maxLength} characters`);
            }
            
          } catch (error) {
            errors.push(`${field}: ${error.message}`);
          }
        }
      }
      
      if (errors.length > 0) {
        return res.status(400).json({ error: 'Validation failed', details: errors });
      }
      
      next();
    } catch (error) {
      console.error('Validation middleware error:', error);
      res.status(500).json({ error: 'Internal validation error' });
    }
  };
}

// JWT token verification
export async function verifyToken(req, res) {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'No token provided' });
      return null;
    }
    
    const token = authHeader.substring(7);
    
    if (!token) {
      res.status(401).json({ error: 'No token provided' });
      return null;
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    
    // Verify user still exists and is active
    const db = await connectToDatabase();
    const user = await db.collection('moderators').findOne({ 
      _id: decoded.userId, 
      status: 'active' 
    });
    
    if (!user) {
      res.status(401).json({ error: 'Invalid token - user not found' });
      return null;
    }
    
    // Check if password was changed after token was issued
    if (user.passwordChangedAt && new Date(decoded.iat * 1000) < user.passwordChangedAt) {
      res.status(401).json({ error: 'Token invalidated - password was changed' });
      return null;
    }
    
    return decoded;
    
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      res.status(401).json({ error: 'Token expired' });
    } else if (error.name === 'JsonWebTokenError') {
      res.status(401).json({ error: 'Invalid token' });
    } else {
      console.error('Token verification error:', error);
      res.status(500).json({ error: 'Internal authentication error' });
    }
    return null;
  }
}

// Permission checking middleware
export function requirePermission(permission) {
  return async (req, res, next) => {
    try {
      const user = await verifyToken(req, res);
      if (!user) return; // verifyToken handles the response
      
      const db = await connectToDatabase();
      const userData = await db.collection('moderators').findOne({ _id: user.userId });
      
      if (!userData.permissions.includes(permission) && userData.role !== 'admin') {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }
      
      req.user = user;
      req.userData = userData;
      next();
    } catch (error) {
      console.error('Permission check error:', error);
      res.status(500).json({ error: 'Internal authorization error' });
    }
  };
}

// Security headers middleware
export function securityHeaders(req, res, next) {
  // Set security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
  
  next();
}

// IP-based rate limiting for sensitive operations
export const sensitiveOperationLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 requests per hour for sensitive operations
  message: { error: 'Too many sensitive operations, please try again later' },
  skip: (req) => {
    // Skip rate limiting for localhost in development
    return process.env.NODE_ENV === 'development' && 
           (req.ip === '127.0.0.1' || req.ip === '::1');
  }
});

// Audit logging for admin actions
export async function auditLog(action, userId, details = {}) {
  try {
    const db = await connectToDatabase();
    await db.collection('admin_log').insertOne({
      action,
      userId,
      details,
      timestamp: new Date(),
      ipAddress: details.ipAddress || null,
      userAgent: details.userAgent || null
    });
  } catch (error) {
    console.error('Audit logging error:', error);
  }
}