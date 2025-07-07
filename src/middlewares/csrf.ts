import express from 'express';
import Tokens = require('csrf');

const tokens = new Tokens();

// Middleware to validate CSRF
export const validateCSRF = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const secret = req.cookies.csrfSecret;
  const token = req.headers['x-csrf-token'] || req.body._csrf;
  
  if (!secret || !token || !tokens.verify(secret, token as string)) {
    res.status(403).json({ error: 'Invalid CSRF token' });
    return;
  }
  
  next();
};

// Function to generate CSRF token
export const generateCSRFToken = () => {
  const secret = tokens.secretSync();
  const token = tokens.create(secret);
  return { secret, token };
};
