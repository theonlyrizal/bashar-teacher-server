const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const admin = require('firebase-admin');

// Firebase admin sdk
const decoded = Buffer.from(process.env.FIREBASE_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

//JWT Ver middleware
const verifyToken = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res.status(401).send({ message: 'Unauthorized access' });
  }
  const token = authorization.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: 'Unauthorized access' });
    }
    req.user = decoded;
    next();
  });
};

// Admin Middleware
const verifyAdmin = async (req, res, next) => {
  const email = req.user.email;
  if (req.user.role !== 'Admin') {
    return res.status(403).send({ message: 'Forbidden access' });
  }
  next();
};

// Tutor Middleware
const verifyTutor = async (req, res, next) => {
  if (req.user.role !== 'Tutor') {
    return res.status(403).send({ message: 'Forbidden access' });
  }
  next();
};

// Student Middleware
const verifyStudent = async (req, res, next) => {
  if (req.user.role !== 'Student') {
    return res.status(403).send({ message: 'Forbidden access' });
  }
  next();
};

// MONGO CLIENT STUFF
const user = process.env.MONGO_USER;
const pass = process.env.MONGO_PASS;
const uri = `mongodb+srv://${user}:${encodeURIComponent(
  pass
)}@cluster0.636pevp.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const database = client.db('basharTeacherDB');
    const usersCollection = database.collection('users');
    const tuitionsCollection = database.collection('tuitions');
    const applicationsCollection = database.collection('applications');
    const paymentsCollection = database.collection('payments');

    // ========================
    // AUTH APIs
    // ========================

    // user register-
    app.post('/api/auth/register', async (req, res) => {
      const user = req.body;
      // Check if user exists
      const query = { email: user.email };
      const existingUser = await usersCollection.findOne(query);
      if (existingUser) {
        return res.send({ message: 'User already exists', insertedId: null });
      }

      // Hash password
      if (user.password) {
        user.password = await bcrypt.hash(user.password, 10);
      }

      user.createdAt = new Date();
      // Default role if not provided
      if (!user.role) user.role = 'Student';

      // Allow Google Sign In reg without password
      const result = await usersCollection.insertOne(user);

      // Generate JWT
      const token = jwt.sign(
        { userId: result.insertedId, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.send({ result, token, user: { ...user, _id: result.insertedId, password: undefined } });
    });

    // Send a ping to confirm a successful connection
    // await client.db('admin').command({ ping: 1 });
    console.log('Pinged your deployment. You successfully connected to MongoDB!');
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);
