import express, { Request, Response } from 'express';
import * as he from 'he';
import { restrictedCors, validateCSRF, generateCSRFToken } from '../middlewares';
import { getDatabase } from '../database';

const router = express.Router();

// Ruta para datos con CORS restringido
router.get('/data', restrictedCors, (req: Request, res: Response) => {
  res.json({ msg: '¡Datos seguros!' });
});

// Ruta para obtener token CSRF
router.get('/csrf-token', (req: Request, res: Response) => {
  const { secret, token } = generateCSRFToken();
  
  res.cookie('csrfSecret', secret, { 
    httpOnly: true, 
    secure: false, // cambiar a true en producción con HTTPS
    sameSite: 'strict' 
  });
  
  res.json({ csrfToken: token });
});

// Ruta protegida con CSRF
router.post('/secure-action', validateCSRF, (req: Request, res: Response) => {
  res.json({ 
    success: true, 
    message: 'Acción ejecutada de forma segura',
    data: req.body 
  });
});

// Ruta para demostrar protección XSS
router.get('/xss-test', (req: Request, res: Response) => {
  const userInput = req.query.input as string || 'Sin entrada';
  
  // Escapamos el HTML para prevenir XSS
  const safeInput = he.encode(userInput);
  
  // Esta respuesta HTML está protegida por los headers de helmet Y por escape de HTML
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Test XSS Protection</title>
    </head>
    <body>
      <h1>Entrada del usuario (escapada):</h1>
      <div>${safeInput}</div>
      <h2>Entrada sin escapar (vulnerable):</h2>
      <div>${userInput}</div>
      <p>Prueba con: ?input=&lt;script&gt;alert('XSS')&lt;/script&gt;</p>
    </body>
    </html>
  `);
});

// ===== RUTAS DE SQL INJECTION DEMO =====

// VULNERABLE: Concatenación directa (NO USAR EN PRODUCCIÓN)
router.get('/sql-vulnerable', (req: Request, res: Response) => {
  const executeQuery = async () => {
    try {
      const username = req.query.username as string;
      
      if (!username) {
        return res.json({ error: 'Se requiere parámetro username' });
      }

      const db = getDatabase();
      
      // ⚠️ VULNERABLE - Concatenación directa de strings
      const vulnerableQuery = `SELECT * FROM users WHERE username = '${username}'`;
      console.log('🚨 Query vulnerable:', vulnerableQuery);
      
      const result = await db.all(vulnerableQuery);
      
      res.json({
        message: 'Consulta vulnerable ejecutada',
        query: vulnerableQuery,
        results: result,
        warning: '⚠️ Esta consulta es vulnerable a SQL Injection'
      });
    } catch (error: any) {
      res.status(500).json({ 
        error: 'Error en consulta vulnerable', 
        details: error.message 
      });
    }
  };
  executeQuery();
});

// SEGURO: Consultas preparadas (USAR EN PRODUCCIÓN)
router.get('/sql-secure', (req: Request, res: Response) => {
  const executeQuery = async () => {
    try {
      const username = req.query.username as string;
      
      if (!username) {
        return res.json({ error: 'Se requiere parámetro username' });
      }

      const db = getDatabase();
      
      // ✅ SEGURO - Prepared statements
      const secureQuery = 'SELECT * FROM users WHERE username = ?';
      console.log('✅ Query segura:', secureQuery);
      console.log('✅ Parámetro:', username);
      
      const result = await db.all(secureQuery, [username]);
      
      res.json({
        message: 'Consulta segura ejecutada',
        query: secureQuery,
        parameter: username,
        results: result,
        success: '✅ Esta consulta usa prepared statements'
      });
    } catch (error: any) {
      res.status(500).json({ 
        error: 'Error en consulta segura', 
        details: error.message 
      });
    }
  };
  executeQuery();
});

// Listar todos los usuarios (para referencia)
router.get('/users', (req: Request, res: Response) => {
  const executeQuery = async () => {
    try {
      const db = getDatabase();
      const users = await db.all('SELECT id, username, email, created_at FROM users');
      
      res.json({
        message: 'Usuarios en la base de datos',
        users: users
      });
    } catch (error: any) {
      res.status(500).json({ 
        error: 'Error al obtener usuarios', 
        details: error.message 
      });
    }
  };
  executeQuery();
});

export default router;
