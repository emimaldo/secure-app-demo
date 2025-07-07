import express, { Request, Response } from 'express';
import * as he from 'he';

const router = express.Router();

// Route to demonstrate XSS protection
router.get('/xss-test', (req: Request, res: Response) => {
  const userInput = req.query.input as string || 'No input';
  
  // We escape HTML to prevent XSS
  const safeInput = he.encode(userInput);
  
  // This HTML response is protected by helmet headers AND HTML escaping
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Test XSS Protection</title>
    </head>
    <body>
      <h1>User input (escaped):</h1>
      <div>${safeInput}</div>
      <h2>Raw input (vulnerable):</h2>
      <div>${userInput}</div>
      <p>Try with: ?input=&lt;script&gt;alert('XSS')&lt;/script&gt;</p>
    </body>
    </html>
  `);
});

export default router;
