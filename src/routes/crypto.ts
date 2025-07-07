import express, { Request, Response } from 'express';
import { PasswordManager, AESCrypto, HashUtils, TokenManager } from '../crypto';
import { getDatabase } from '../database';

const router = express.Router();

// =============================================================================
// PASSWORD HASHING DEMO
// =============================================================================

// Hash a password with bcrypt (includes automatic salting)
router.post('/hash-password', (req: Request, res: Response) => {
  const executeHash = async () => {
    try {
      const { password } = req.body;
      
      if (!password) {
        return res.status(400).json({ error: 'Password is required' });
      }

      const hashedPassword = await PasswordManager.hashPassword(password);
      
      res.json({
        message: 'Password hashed successfully',
        hashed: hashedPassword,
        info: '🔒 bcrypt automatically includes salt and uses 12 rounds',
        note: 'Original password not returned for security reasons'
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  };
  executeHash();
});

// Verify a password against its hash
router.post('/verify-password', (req: Request, res: Response) => {
  const executeVerify = async () => {
    try {
      const { password, hash } = req.body;
      
      if (!password || !hash) {
        return res.status(400).json({ error: 'Password and hash are required' });
      }

      const isValid = await PasswordManager.verifyPassword(password, hash);
      
      res.json({
        message: 'Password verification completed',
        hash: hash,
        isValid: isValid,
        result: isValid ? '✅ Password matches!' : '❌ Invalid password',
        info: '🔒 Password not returned for security reasons'
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  };
  executeVerify();
});

// Authenticate user with real database and hashed passwords
router.post('/authenticate', (req: Request, res: Response) => {
  const executeAuth = async () => {
    try {
      const { username, password } = req.body;
      
      if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
      }

      const db = getDatabase();
      
      // Get user from database
      const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
      
      if (!user) {
        return res.status(401).json({
          message: 'Authentication failed',
          result: '❌ User not found',
          info: '🔒 Username/password not returned for security'
        });
      }

      // Verify password against stored hash
      const isValid = await PasswordManager.verifyPassword(password, user.password);
      
      if (!isValid) {
        return res.status(401).json({
          message: 'Authentication failed',
          result: '❌ Invalid password',
          info: '🔒 Username/password not returned for security'
        });
      }

      // Create a JWT-like token for successful login
      const tokenPayload = {
        userId: user.id,
        username: user.username,
        email: user.email,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
      };

      const token = TokenManager.createToken(tokenPayload);

      res.json({
        message: 'Authentication successful',
        result: '✅ Login successful!',
        user: {
          id: user.id,
          username: user.username,
          email: user.email
        },
        token: token,
        info: '🎫 JWT-like token generated for session'
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  };
  executeAuth();
});

// =============================================================================
// AES ENCRYPTION DEMO
// =============================================================================

// Encrypt data with AES
router.post('/encrypt', (req: Request, res: Response): void => {
  try {
    const { data } = req.body;
    
    if (!data) {
      res.status(400).json({ error: 'Data is required' });
      return;
    }

    const encrypted = AESCrypto.encrypt(data);
    
    res.json({
      message: 'Data encrypted successfully',
      encrypted: encrypted,
      info: '🔐 AES encryption with secret key'
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Decrypt data with AES
router.post('/decrypt', (req: Request, res: Response): void => {
  try {
    const { encryptedData } = req.body;
    
    if (!encryptedData) {
      res.status(400).json({ error: 'Encrypted data is required' });
      return;
    }

    const decrypted = AESCrypto.decrypt(encryptedData);
    
    res.json({
      message: 'Data decrypted successfully',
      decrypted: decrypted,
      info: '🔓 AES decryption successful'
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// HASHING DEMO (SHA-256)
// =============================================================================

// Generate different types of hashes
router.post('/hash', (req: Request, res: Response): void => {
  try {
    const { data } = req.body;
    
    if (!data) {
      res.status(400).json({ error: 'Data is required' });
      return;
    }

    const salt = HashUtils.generateSalt();
    const sha256Hash = HashUtils.sha256(data);
    const saltedHash = HashUtils.sha256WithSalt(data, salt);
    
    res.json({
      message: 'Hashing demonstration',
      sha256: sha256Hash,
      salt: salt,
      saltedHash: saltedHash,
      info: {
        sha256: 'Simple SHA-256 hash (deterministic)',
        salted: 'SHA-256 with random salt (more secure)',
        note: 'Same input = same SHA-256, but different salted hash each time'
      }
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// TOKEN DEMO (JWT-like)
// =============================================================================

// Create a signed token
router.post('/create-token', (req: Request, res: Response): void => {
  try {
    const { userId, email, role } = req.body;
    
    if (!userId || !email) {
      res.status(400).json({ error: 'userId and email are required' });
      return;
    }

    const payload = {
      userId,
      email,
      role: role || 'user',
      iat: Math.floor(Date.now() / 1000), // issued at
      exp: Math.floor(Date.now() / 1000) + (60 * 60) // expires in 1 hour
    };

    const token = TokenManager.createToken(payload);
    
    res.json({
      message: 'Token created successfully',
      payload: payload,
      token: token,
      info: '🎫 JWT-like token with HMAC signature'
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Verify and decode a token
router.post('/verify-token', (req: Request, res: Response): void => {
  try {
    const { token } = req.body;
    
    if (!token) {
      res.status(400).json({ error: 'Token is required' });
      return;
    }

    const payload = TokenManager.verifyToken(token);
    
    if (!payload) {
      res.status(401).json({
        message: 'Token verification failed',
        token: token,
        isValid: false,
        result: '❌ Invalid or tampered token'
      });
      return;
    }

    res.json({
      message: 'Token verified successfully',
      token: token,
      payload: payload,
      isValid: true,
      result: '✅ Token is valid and authentic'
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// CRYPTO DEMO OVERVIEW
// =============================================================================

// Get information about all crypto functions
router.get('/crypto-info', (req: Request, res: Response) => {
  res.json({
    message: 'Cryptography Demo Overview',
    features: {
      passwordHashing: {
        description: 'Secure password hashing with bcrypt',
        endpoints: ['/hash-password', '/verify-password', '/authenticate'],
        security: 'Uses salt + 12 rounds, resistant to rainbow tables'
      },
      aesEncryption: {
        description: 'Symmetric encryption with AES',
        endpoints: ['/encrypt', '/decrypt'],
        security: 'Same key for encrypt/decrypt, good for data storage'
      },
      hashing: {
        description: 'SHA-256 hashing with and without salt',
        endpoints: ['/hash'],
        security: 'One-way function, good for integrity verification'
      },
      tokens: {
        description: 'JWT-like token creation and verification',
        endpoints: ['/create-token', '/verify-token'],
        security: 'HMAC signature prevents tampering'
      }
    },
    testPayloads: {
      hashPassword: { password: 'mySecretPassword123' },
      authenticate: { username: 'admin', password: 'admin123' },
      encrypt: { data: 'sensitive information' },
      hash: { data: 'document content' },
      createToken: { userId: 1, email: 'user@example.com', role: 'admin' }
    }
  });
});

export default router;