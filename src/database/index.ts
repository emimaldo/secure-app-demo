import sqlite3 from 'sqlite3';
import { open, Database } from 'sqlite';
import path from 'path';
import * as bcrypt from 'bcrypt';

let db: Database | null = null;

export const initDatabase = async (): Promise<Database> => {
  if (db) return db;

  db = await open({
    filename: path.join(__dirname, '../../database.sqlite'),
    driver: sqlite3.Database
  });

  // Create users table for demo
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Check if users already exist
  const existingUsers = await db.get('SELECT COUNT(*) as count FROM users');
  
  if (existingUsers.count === 0) {
    // Hash real passwords for demo users
    const adminPassword = await bcrypt.hash('admin123', 12);
    const user1Password = await bcrypt.hash('user123', 12);
    const testPassword = await bcrypt.hash('test123', 12);

    // Insert test data with REAL hashed passwords
    await db.run(`
      INSERT INTO users (username, email, password) VALUES 
      (?, ?, ?),
      (?, ?, ?),
      (?, ?, ?)
    `, [
      'admin', 'admin@example.com', adminPassword,
      'user1', 'user1@example.com', user1Password,
      'test', 'test@example.com', testPassword
    ]);

    console.log('✅ Database initialized with REAL hashed passwords');
    console.log('📝 Demo credentials:');
    console.log('   - admin/admin123');
    console.log('   - user1/user123');
    console.log('   - test/test123');
  } else {
    console.log('✅ Database already initialized');
  }
  return db;
};

export const getDatabase = (): Database => {
  if (!db) {
    throw new Error('Database not initialized. Call initDatabase() first.');
  }
  return db;
};
