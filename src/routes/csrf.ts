import express, { Request, Response } from 'express';
import { validateCSRF, generateCSRFToken } from '../middlewares';

const router = express.Router();

// Route to get CSRF token
router.get('/csrf-token', (req: Request, res: Response) => {
  const { secret, token } = generateCSRFToken();
  
  res.cookie('csrfSecret', secret, { 
    httpOnly: true, 
    secure: false, // change to true in production with HTTPS
    sameSite: 'strict' 
  });
  
  res.json({ csrfToken: token });
});

// CSRF protected route
router.post('/secure-action', validateCSRF, (req: Request, res: Response) => {
  res.json({ 
    success: true, 
    message: 'Action executed securely',
    data: req.body 
  });
});

export default router;
