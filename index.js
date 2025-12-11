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

    // Login User
    app.post('/api/auth/login', async (req, res) => {
      const { email, password } = req.body;
      const user = await usersCollection.findOne({ email });
      if (!user) {
        return res.status(401).send({ message: 'Invalid credentials' });
      }

      // If user created via Google but trying to login with password (and has none)
      if (!user.password) {
        return res.status(401).send({ message: 'Please login with Google' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).send({ message: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { userId: user._id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.send({ token, user: { ...user, password: undefined } });
    });

    // Google Social Login (Sync/Register + JWT)
    app.post('/api/auth/google', async (req, res) => {
      const { token } = req.body; // Firebase ID Token
      if (!token) return res.status(400).send({ message: 'Token required' });

      try {
        // Verify Firebase Token
        const decoded = await admin.auth().verifyIdToken(token);
        const { email, name, picture, uid } = decoded;

        let user = await usersCollection.findOne({ email });

        if (!user) {
          // Register new user
          user = {
            name,
            email,
            role: 'Student', // Default
            photoURL: picture,
            firebaseUid: uid,
            createdAt: new Date(),
            isActive: true,
          };
          const result = await usersCollection.insertOne(user);
          user._id = result.insertedId;
        } else {
          // Update sync info
          if (!user.firebaseUid) {
            await usersCollection.updateOne(
              { _id: user._id },
              { $set: { firebaseUid: uid, photoURL: picture } }
            );
          }
        }

        // Generate our JWT
        const jwtToken = jwt.sign(
          { userId: user._id, email: user.email, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '7d' }
        );

        res.send({ token: jwtToken, user: { ...user, password: undefined } });
      } catch (error) {
        res.status(401).send({ message: 'Invalid token' });
      }
    });

    // Verify/Me
    app.get('/api/auth/me', verifyToken, async (req, res) => {
      const user = await usersCollection.findOne(
        { _id: new ObjectId(req.user.userId) },
        { projection: { password: 0 } }
      );
      res.send(user);
    });

    // ========================
    // USER APIs
    // ========================

    app.get('/api/users', verifyToken, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find({}, { projection: { password: 0 } }).toArray();
      res.send(result);
    });

    app.get('/api/users/tutors/latest', async (req, res) => {
      const result = await usersCollection
        .find({ role: 'Tutor' }, { projection: { password: 0 } })
        .sort({ createdAt: -1 })
        .limit(6)
        .toArray();
      res.send(result);
    });

    app.patch('/api/users/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: req.body,
      };
      const result = await usersCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });

    app.delete('/api/users/:id', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await usersCollection.deleteOne(query);
      res.send(result);
    });

    // ========================
    // TUITION APIs
    // ========================

    app.post('/api/tuitions', verifyToken, verifyStudent, async (req, res) => {
      const tuition = req.body;
      tuition.createdAt = new Date();
      tuition.studentId = new ObjectId(req.user.userId);
      tuition.status = 'Pending';

      // Ensure numbers
      if (tuition.budget) tuition.budget = parseFloat(tuition.budget);

      const result = await tuitionsCollection.insertOne(tuition);
      res.send(result);
    });

    // Send a ping to confirm a successful connection
    // await client.db('admin').command({ ping: 1 });
    console.log('Pinged your deployment. You successfully connected to MongoDB!');
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);
