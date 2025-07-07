import express, { Request, Response } from 'express';
import { getDatabase } from '../database';

const router = express.Router();

// VULNERABLE: Direct concatenation (DO NOT USE IN PRODUCTION)
router.get('/sql-vulnerable', (req: Request, res: Response) => {
  const executeQuery = async () => {
    try {
      const username = req.query.username as string;
      
      if (!username) {
        return res.json({ error: 'Username parameter required' });
      }

      const db = getDatabase();
      
      // ⚠️ VULNERABLE - Direct string concatenation
      const vulnerableQuery = `SELECT * FROM users WHERE username = '${username}'`;
      console.log('🚨 Vulnerable query:', vulnerableQuery);
      
      const result = await db.all(vulnerableQuery);
      
      res.json({
        message: 'Vulnerable query executed',
        query: vulnerableQuery,
        results: result,
        warning: '⚠️ This query is vulnerable to SQL Injection'
      });
    } catch (error: any) {
      res.status(500).json({ 
        error: 'Error in vulnerable query', 
        details: error.message 
      });
    }
  };
  executeQuery();
});

// SECURE: Prepared statements (USE IN PRODUCTION)
router.get('/sql-secure', (req: Request, res: Response) => {
  const executeQuery = async () => {
    try {
      const username = req.query.username as string;
      
      if (!username) {
        return res.json({ error: 'Username parameter required' });
      }

      const db = getDatabase();
      
      // ✅ SECURE - Prepared statements
      const secureQuery = 'SELECT * FROM users WHERE username = ?';
      console.log('✅ Secure query:', secureQuery);
      console.log('✅ Parameter:', username);
      
      const result = await db.all(secureQuery, [username]);
      
      res.json({
        message: 'Secure query executed',
        query: secureQuery,
        parameter: username,
        results: result,
        success: '✅ This query uses prepared statements'
      });
    } catch (error: any) {
      res.status(500).json({ 
        error: 'Error in secure query', 
        details: error.message 
      });
    }
  };
  executeQuery();
});

// List all users (for reference)
router.get('/users', (req: Request, res: Response) => {
  const executeQuery = async () => {
    try {
      const db = getDatabase();
      const users = await db.all('SELECT id, username, email, created_at FROM users');
      
      res.json({
        message: 'Users in database',
        users: users
      });
    } catch (error: any) {
      res.status(500).json({ 
        error: 'Error getting users', 
        details: error.message 
      });
    }
  };
  executeQuery();
});

export default router;
