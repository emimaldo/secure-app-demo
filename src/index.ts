import express from 'express';
import cookieParser from 'cookie-parser';
import { apiRoutes } from './routes';
import { xssProtection } from './middlewares';
import { initDatabase } from './database';

// Entry point
console.log('Hello from secure-app-demo!');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize database
initDatabase().catch(console.error);

// Global middlewares
app.use(xssProtection); // XSS protection and other security headers
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/', (req, res) => {
  res.send('¡Hello from secure-app-demo!');
});

// API Routes
app.use('/api', apiRoutes);

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
