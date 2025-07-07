import * as bcrypt from 'bcrypt';
import * as CryptoJS from 'crypto-js';
import * as crypto from 'crypto';

// =============================================================================
// PASSWORD HASHING WITH BCRYPT
// =============================================================================

export class PasswordManager {
  private static readonly SALT_ROUNDS = 12;

  /**
   * Hash a password using bcrypt (includes automatic salting)
   */
  static async hashPassword(password: string): Promise<string> {
    return await bcrypt.hash(password, this.SALT_ROUNDS);
  }

  /**
   * Verify a password against its hash
   */
  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    return await bcrypt.compare(password, hash);
  }
}

// =============================================================================
// AES SYMMETRIC ENCRYPTION
// =============================================================================

export class AESCrypto {
  private static readonly SECRET_KEY = 'my-super-secret-key-32-characters!';

  /**
   * Encrypt data using AES
   */
  static encrypt(data: string): string {
    return CryptoJS.AES.encrypt(data, this.SECRET_KEY).toString();
  }

  /**
   * Decrypt data using AES
   */
  static decrypt(encryptedData: string): string {
    const bytes = CryptoJS.AES.decrypt(encryptedData, this.SECRET_KEY);
    return bytes.toString(CryptoJS.enc.Utf8);
  }
}

// =============================================================================
// HASHING UTILITIES (SHA-256)
// =============================================================================

export class HashUtils {
  /**
   * Generate a random salt
   */
  static generateSalt(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Create SHA-256 hash
   */
  static sha256(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Create SHA-256 hash with salt
   */
  static sha256WithSalt(data: string, salt: string): string {
    return crypto.createHash('sha256').update(data + salt).digest('hex');
  }
}

// =============================================================================
// JWT-LIKE TOKEN MANAGEMENT
// =============================================================================

export class TokenManager {
  private static readonly SECRET_KEY = 'jwt-secret-key-super-secure-256-bits';

  /**
   * Create a signed token (JWT-like)
   */
  static createToken(payload: any): string {
    const header = { alg: 'HS256', typ: 'JWT' };
    
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    
    const signature = crypto
      .createHmac('sha256', this.SECRET_KEY)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest('base64url');
    
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  /**
   * Verify and decode a token
   */
  static verifyToken(token: string): any | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const [encodedHeader, encodedPayload, signature] = parts;
      
      // Verify signature
      const expectedSignature = crypto
        .createHmac('sha256', this.SECRET_KEY)
        .update(`${encodedHeader}.${encodedPayload}`)
        .digest('base64url');
      
      if (signature !== expectedSignature) return null;
      
      // Decode payload
      const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
      
      // Check expiration
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        return null; // Token expired
      }
      
      return payload;
    } catch (error) {
      return null;
    }
  }
}