import cors from 'cors';

// Restricted CORS configuration
export const restrictedCors = cors({
  origin: 'https://midominio.com',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
});
