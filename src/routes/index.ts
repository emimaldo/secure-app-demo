import express from 'express';
import corsRoutes from './cors';
import csrfRoutes from './csrf';
import xssRoutes from './xss';
import sqlRoutes from './sql';
import cryptoRoutes from './crypto';

const router = express.Router();

// Group all routes
router.use('/', corsRoutes);
router.use('/', csrfRoutes);
router.use('/', xssRoutes);
router.use('/', sqlRoutes);
router.use('/', cryptoRoutes);

export { router as apiRoutes };
