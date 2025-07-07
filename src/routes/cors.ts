import express, { Request, Response } from 'express';
import { restrictedCors } from '../middlewares';

const router = express.Router();

// Route for data with restricted CORS
router.get('/data', restrictedCors, (req: Request, res: Response) => {
  res.json({ msg: '¡Secure data!' });
});

export default router;
