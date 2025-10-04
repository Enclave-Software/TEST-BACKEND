// api/config/database.js
import { MongoClient } from 'mongodb';

let cachedDb = null;

export async function connectToDatabase() {
  if (cachedDb) {
    return cachedDb;
  }

  const client = new MongoClient(process.env.MONGODB_URI);
  await client.connect();
  
  const db = client.db('enclave-community');
  cachedDb = db;
  
  return db;
}

export async function initializeCollections() {
  const db = await connectToDatabase();
  
  // Create collections with indexes
  await db.collection('discussions').createIndex({ category: 1, createdAt: -1 });
  await db.collection('discussions').createIndex({ status: 1 });
  await db.collection('discussions').createIndex({ authorEmail: 1 });
  
  await db.collection('vulnerabilities').createIndex({ severity: 1, createdAt: -1 });
  await db.collection('vulnerabilities').createIndex({ status: 1 });
  await db.collection('vulnerabilities').createIndex({ researcherEmail: 1 });
  
  await db.collection('moderators').createIndex({ email: 1 }, { unique: true });
  
  return db;
}