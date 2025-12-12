const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
// Initialize Stripe with your Secret Key
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const admin = require('firebase-admin');

const app = express();
const port = process.env.PORT || 5000;

// --- IMPORTANT: STRIPE WEBHOOK ENDPOINT MUST COME BEFORE express.json() ---
// This is because Stripe sends the request body as raw text, which is required for signature verification.
// We apply a specific raw body parser only for the webhook route.
app.post(
  '/stripe-webhook',
  express.raw({ type: 'application/json' }), // Specific middleware for raw body
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
      // 1. Verify the event signature using the Webhook Secret
      // Make sure process.env.STRIPE_WEBHOOK_SECRET is set in your .env file
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET 
      );
    } catch (err) {
      console.error(`Webhook Signature Verification Failed: ${err.message}`);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    
    // 2. Handle the event
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      
      // Get the custom data (metadata) we passed during session creation
      const applicationId = session.metadata.applicationId;
      const studentId = session.metadata.studentId;

      console.log(`Webhook received for session: ${session.id}. App ID: ${applicationId}`);

      // Check if this payment was already processed (Idempotency)
      const paymentsCollection = client.db('basharTeacherDB').collection('payments');
      const applicationsCollection = client.db('basharTeacherDB').collection('applications');
      const transactionsCollection = client.db('basharTeacherDB').collection('transactions');

      const existingPayment = await paymentsCollection.findOne({ transactionId: session.id });
      if (existingPayment) {
        console.log('Payment already recorded (Idempotency handled).');
        return res.json({ received: true, message: 'Payment already recorded' });
      }

      try {
        // Retrieve application details
        const application = await applicationsCollection.findOne({
          _id: new ObjectId(applicationId),
        });
        
        if (!application) {
            console.error(`Application not found for ID: ${applicationId}`);
            return res.json({ received: true }); 
        }

        // A. Approve Application
        await applicationsCollection.updateOne(
          { _id: new ObjectId(applicationId) },
          { $set: { status: 'Approved' } }
        );

        // B. Reject Other Applications for the same tuition
        await applicationsCollection.updateMany(
            { 
              tuitionId: application.tuitionId, 
              _id: { $ne: new ObjectId(applicationId) } 
            },
            { $set: { status: 'Rejected' } }
        );

        // C. Update Tuition (Assign Tutor & Change Status)
        // Changing status to 'Assigned' removes it from the public job board (since GET /tuitions filters by 'Approved')
        await tuitionsCollection.updateOne(
            { _id: application.tuitionId },
            { 
                $set: { 
                    tutorId: application.tutorId,
                    status: 'Assigned' 
                } 
            }
        );

        // D. Create Transaction Record (with Revenue Split)
        const feePercentage = parseInt(process.env.PLATFORM_FEE_PERCENTAGE) || 0;
        const totalAmount = session.amount_total / 100;
        const siteRevenue = totalAmount * (feePercentage / 100);
        const tutorPayment = totalAmount - siteRevenue;

        const transaction = {
          paymentId: session.id, // Stripe Session ID
          stripeData: session,   // Full Stripe Session Data
          tutorId: application.tutorId,
          studentId: new ObjectId(studentId),
          applicationId: new ObjectId(applicationId),
          amount: totalAmount,
          siteRevenue: siteRevenue,
          tutorPayment: tutorPayment,
          timestamp: new Date(),
        };

        await transactionsCollection.insertOne(transaction);
        
        // Keep payments collection for backward compatibility if needed, or simply log it. 
        // For now, I'll just use the old format for 'payments' collection to avoid breaking existing 'my-payments' views 
        // until those are updated.
        const payment = {
          transactionId: session.id, 
          studentId: new ObjectId(studentId), 
          tutorId: application.tutorId, 
          tuitionId: application.tuitionId,
          amount: totalAmount, 
          date: new Date(),
          status: 'Completed',
        };

        const result = await paymentsCollection.insertOne(payment);
        console.log('Payment recorded successfully:', result.insertedId);

      } catch (dbError) {
        console.error('Database update error in webhook:', dbError);
        // Important: Return a 500 status code to Stripe so it retries the webhook
        return res.status(500).send('Internal Server Error'); 
      }
    } else {
        // Handle other relevant event types if needed
        console.log(`Unhandled event type ${event.type}`);
    }

    // 3. Return a 200 to acknowledge receipt of the event
    res.json({ received: true });
  }
);
// --- END OF WEBHOOK ENDPOINT ---

// Apply standard express.json() middleware for all other routes
app.use(express.json()); 

// Configure CORS and Firebase as before
app.use(cors({
  origin: [
    "https://bashar-teacher-client.vercel.app",
    "http://localhost:5173",
  ],
  credentials: true
}));

// Firebase admin sdk
const decoded = Buffer.from(process.env.FIREBASE_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// JWT Ver middleware (same as before)
const verifyToken = (req, res, next) => {
  // ... (Your JWT logic)
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

// Admin Middleware (same as before)
const verifyAdmin = async (req, res, next) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).send({ message: 'Forbidden access' });
  }
  next();
};

// Tutor Middleware (same as before)
const verifyTutor = async (req, res, next) => {
  if (req.user.role !== 'Tutor') {
    return res.status(403).send({ message: 'Forbidden access' });
  }
  next();
};

// Student Middleware (same as before)
const verifyStudent = async (req, res, next) => {
  if (req.user.role !== 'Student') {
    return res.status(403).send({ message: 'Forbidden access' });
  }
  next();
};

// MONGO CLIENT STUFF (same as before)
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
    // Connect the client to the server (optional starting in v4.7)
    // await client.connect();

    const database = client.db('basharTeacherDB');
    const usersCollection = database.collection('users');
    const tuitionsCollection = database.collection('tuitions');
    const applicationsCollection = database.collection('applications');
    const paymentsCollection = database.collection('payments');
    const transactionsCollection = database.collection('transactions');

    // ========================
    // AUTH, USER, TUITION, APPLICATION APIs (NO CHANGES)
    // ========================
    // ... (Your existing code for /auth, /users, /tuitions, /applications)

    // user register
    app.post('/auth/register', async (req, res) => {
      const user = req.body;
      const { adminToken } = req.body;

      const query = { email: user.email };
      const existingUser = await usersCollection.findOne(query);
      if (existingUser) {
        return res.send({ message: 'User already exists', insertedId: null });
      }
      
      // Determine Role based on Token
      if (adminToken && adminToken === process.env.ADMIN_TOKEN) {
        user.role = 'Admin';
      } else if (!user.role) {
        user.role = 'Student';
      }

      // Cleanup
      delete user.adminToken; // Don't save the token in DB

      if (user.password) {
        user.password = await bcrypt.hash(user.password, 10);
      }
      // Initialize role-specific fields
      if (user.role === 'Student') {
        user.school = '';
        user.class = '';
        user.address = '';
        user.bio = '';
      } else if (user.role === 'Tutor') {
        user.qualifications = []; // Array of strings or objects
        user.experience = '';
        user.skills = []; // Array of strings
        user.expectedSalary = 0;
        user.about = ''; // Bio for tutor
        user.location = '';
      }
      
      user.phone = user.phone || '';
      user.photoURL = user.photoURL || '';
      user.createdAt = new Date();
      user.isActive = true;
      
      const result = await usersCollection.insertOne(user);
      const token = jwt.sign(
        { userId: result.insertedId, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );
      res.send({ success: true, result, token, user: { ...user, _id: result.insertedId, password: undefined } });
    });

    // Login User
    app.post('/auth/login', async (req, res) => {
      const { email, password, adminToken } = req.body;

      // 1. Check for Admin via TOKEN (Super Admin Bypass)
      if (adminToken && adminToken === process.env.ADMIN_TOKEN) {
        const token = jwt.sign(
          { userId: 'admin-static-id', email: 'admin@bashar.com', role: 'Admin' },
          process.env.JWT_SECRET,
          { expiresIn: '7d' }
        );
        return res.send({
          success: true,
          token,
          user: {
            _id: 'admin-static-id',
            name: 'Super Admin',
            email: 'admin@bashar.com',
            role: 'Admin',
            photoURL: 'https://i.ibb.co/4pDNDk1/avatar.png',
          },
        });
      }

      // 2. Regular User Login
      const user = await usersCollection.findOne({ email });
      if (!user) {
        return res.status(401).send({ message: 'Invalid credentials' });
      }
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
      res.send({ success: true, token, user: { ...user, password: undefined } });
    });

    // Google Social Login (Sync/Register + JWT)
    app.post('/auth/google', async (req, res) => {
      const { token } = req.body; // Firebase ID Token
      if (!token) return res.status(400).send({ message: 'Token required' });
      try {
        const decoded = await admin.auth().verifyIdToken(token);
        const { email, name, picture, uid } = decoded;
        let user = await usersCollection.findOne({ email });
        if (!user) {
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
          if (!user.firebaseUid) {
            await usersCollection.updateOne(
              { _id: user._id },
              { $set: { firebaseUid: uid, photoURL: picture } }
            );
          }
        }
        const jwtToken = jwt.sign(
          { userId: user._id, email: user.email, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '7d' }
        );
        res.send({ success: true, token: jwtToken, user: { ...user, password: undefined } });
      } catch (error) {
        res.status(401).send({ message: 'Invalid token' });
      }
    });

    // Verify Token
    app.get('/auth/verify-token', verifyToken, async (req, res) => {
      const user = await usersCollection.findOne(
        { _id: new ObjectId(req.user.userId) },
        { projection: { password: 0 } }
      );
      res.send({ success: true, user });
    });

    // Verify/Me 
    app.get('/auth/me', verifyToken, async (req, res) => {
      const user = await usersCollection.findOne(
        { _id: new ObjectId(req.user.userId) },
        { projection: { password: 0 } }
      );
      res.send({ success: true, user });
    });

    // ========================
    // USER APIs
    // ========================

    app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find({}, { projection: { password: 0 } }).toArray();
      res.send(result);
    });

    app.get('/users/tutors/latest', async (req, res) => {
      const result = await usersCollection
        .find({ role: 'Tutor' }, { projection: { password: 0 } })
        .sort({ createdAt: -1 })
        .limit(6)
        .toArray();
      res.send(result);
    });

    // Get Single Tutor Public Profile
    app.get('/tutors/:id', async (req, res) => {
      const id = req.params.id;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: 'Invalid ID format' });
      }
      const query = { _id: new ObjectId(id), role: 'Tutor' };
      const user = await usersCollection.findOne(query, { projection: { password: 0 } });
      if (!user) {
         return res.status(404).send({ message: 'Tutor not found' });
      }
      res.send(user);
    });

    app.patch('/users/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: req.body,
      };
      const result = await usersCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });

    app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      
      try {
        // 1. Find user to get firebaseUid
        const user = await usersCollection.findOne(query);

        if (user && user.firebaseUid) {
          try {
            // 2. Delete from Firebase
            await admin.auth().deleteUser(user.firebaseUid);
            console.log(`Successfully deleted user from Firebase: ${user.firebaseUid}`);
          } catch (firebaseError) {
            console.error('Error deleting user from Firebase:', firebaseError);
            // Continue execution to delete from DB even if Firebase fails 
            // (e.g. user already deleted in Firebase manually)
          }
        }

        // 3. Delete from MongoDB
        const result = await usersCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).send({ message: 'Failed to delete user' });
      }
    });

    // ========================
    // TUITION APIs
    // ========================

    app.post('/tuitions', verifyToken, verifyStudent, async (req, res) => {
      const tuition = req.body;
      tuition.createdAt = new Date();
      tuition.studentId = new ObjectId(req.user.userId);
      tuition.status = 'Pending';
      if (tuition.budget) tuition.budget = parseFloat(tuition.budget);
      const result = await tuitionsCollection.insertOne(tuition);
      res.send(result);
    });

    app.get('/tuitions', async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 9;
      const skip = (page - 1) * limit;

      const { search, subject, location, class: classFilter, sort } = req.query;

      let query = { status: 'Approved' };

      if (search) {
        query.$or = [
          { subject: { $regex: search, $options: 'i' } },
          { location: { $regex: search, $options: 'i' } },
        ];
      }
      if (subject) query.subject = subject;
      if (location) query.location = location;
      if (classFilter) query.class = classFilter;

      let sortOptions = { createdAt: -1 };
      if (sort === 'budgetAsc') sortOptions = { budget: 1 };
      if (sort === 'budgetDesc') sortOptions = { budget: -1 };

      const total = await tuitionsCollection.countDocuments(query);
      const result = await tuitionsCollection
        .find(query)
        .sort(sortOptions)
        .skip(skip)
        .limit(limit)
        .toArray();

      res.send({
        tuitions: result,
        pagination: {
          total,
          page,
          pages: Math.ceil(total / limit),
        },
      });
    });


    app.get('/tuitions/latest', async (req, res) => {
      const result = await tuitionsCollection
        .find({ status: 'Approved' })
        .sort({ createdAt: -1 })
        .limit(6)
        .toArray();
      res.send(result);
    });

    // Get own tuitions
    app.get('/tuitions/my-tuitions', verifyToken, verifyStudent, async (req, res) => {
      const query = { studentId: new ObjectId(req.user.userId) };
      const result = await tuitionsCollection.find(query).sort({ createdAt: -1 }).toArray();
      res.send(result);
    });

    app.get('/tuitions/:id', async (req, res) => {
      const id = req.params.id;
      if (!ObjectId.isValid(id)) {
        return res.status(400).send({ message: 'Invalid ID format' });
      }
      const query = { _id: new ObjectId(id) };
      const result = await tuitionsCollection.findOne(query);
      res.send(result);
    });

    app.delete('/tuitions/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await tuitionsCollection.deleteOne(query);
      res.send(result);
    });

    // Admin: manage status
    app.patch('/tuitions/:id/status', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const { status } = req.body;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: { status: status },
      };
      const result = await tuitionsCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });

    // ========================
    // APPLICATION APIs
    // ========================

    app.post('/applications', verifyToken, verifyTutor, async (req, res) => {
      const application = req.body;
      application.tutorId = new ObjectId(req.user.userId);
      application.tuitionId = new ObjectId(application.tuitionId);
      application.createdAt = new Date();
      application.status = 'Pending';

      // Check existence
      const existing = await applicationsCollection.findOne({
        tutorId: application.tutorId,
        tuitionId: application.tuitionId,
      });
      if (existing) return res.send({ message: 'Already applied' });

      // Check if tuition is already assigned
      const tuition = await tuitionsCollection.findOne({ _id: application.tuitionId });
      if (tuition && tuition.status === 'Assigned') {
           return res.send({ message: 'This tuition has already been assigned to another tutor.' });
      }

      const result = await applicationsCollection.insertOne(application);
      res.send(result);
    });

    // Get apps for a specific tuition (for Student)
    app.get(
      '/applications/tuition/:tuitionId',
      verifyToken,
      verifyStudent,
      async (req, res) => {
        const tuitionId = req.params.tuitionId;
        const query = { tuitionId: new ObjectId(tuitionId) };
        const applications = await applicationsCollection.find(query).toArray();

        // Join tutor info manually
        const populated = await Promise.all(
          applications.map(async (app) => {
            const tutor = await usersCollection.findOne(
              { _id: app.tutorId },
              { projection: { password: 0 } }
            );
            return { ...app, tutor };
          })
        );

        res.send(populated);
      }
    );

    // Get tutor's applications
    app.get('/applications/my-applications', verifyToken, verifyTutor, async (req, res) => {
      const query = { tutorId: new ObjectId(req.user.userId) };
      const applications = await applicationsCollection.find(query).toArray();

      const populated = await Promise.all(
        applications.map(async (app) => {
          const tuition = await tuitionsCollection.findOne({ _id: app.tuitionId });
          return { ...app, tuition };
        })
      );

      res.send(populated);
    });

    // Approved applications (Tutor)
    app.get('/applications/approved', verifyToken, verifyTutor, async (req, res) => {
      const query = { tutorId: new ObjectId(req.user.userId), status: 'Approved' };
      const applications = await applicationsCollection.find(query).toArray();

      const populated = await Promise.all(
        applications.map(async (app) => {
          const tuition = await tuitionsCollection.findOne({ _id: app.tuitionId });
          const student = tuition
            ? await usersCollection.findOne({ _id: tuition.studentId })
            : null;
          return { ...app, tuition, student };
        })
      );

      res.send(populated);
    });

    app.patch('/applications/:id/reject', verifyToken, verifyStudent, async (req, res) => {
      const id = req.params.id;
      const result = await applicationsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status: 'Rejected' } }
      );
      res.send(result);
    });

    // ========================
    // PAYMENT APIs
    // ========================

    // Create Payment Intent/Session
    app.post(
      '/payments/create-checkout-session',
      verifyToken,
      verifyStudent,
      async (req, res) => {
        const { applicationId, salary } = req.body;

        const application = await applicationsCollection.findOne({
          _id: new ObjectId(applicationId),
        });
        if (!application) return res.status(404).send({ message: 'Application not found' });

        const tuition = await tuitionsCollection.findOne({ _id: application.tuitionId });
        if (!tuition) return res.status(404).send({ message: 'Tuition not found' });

        const amount = salary || application.expectedSalary;
        // Stripe uses the smallest currency unit (cents/pennies), so multiply by 100
        const amountCents = Math.round(amount * 100); 

        const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          customer_email: req.user.email,
          line_items: [
            {
              price_data: {
                currency: 'usd',
                product_data: {
                  name: `Tuition: ${tuition.subject}`,
                  description: `Class ${tuition.class}`,
                },
                unit_amount: amountCents,
              },
              quantity: 1,
            },
          ],
          mode: 'payment',
          // ⚠️ IMPORTANT CHANGE: Using metadata to pass critical IDs
          metadata: {
              applicationId: applicationId, 
              studentId: req.user.userId,
          },
          // Success URL only needs session ID for client-side display/lookup, 
          // the critical fulfillment is handled by the webhook.
          success_url: `${process.env.CLIENT_URL}/dashboard/payment/success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.CLIENT_URL}/dashboard/student/my-tuitions`,
        });

        res.send({ url: session.url });
      }
    );

    // Save Payment Info & Approve Tutor (SIMPLIFIED/SECURED)
    // This route is now only used for client-side verification/display, 
    // the fulfillment logic is safely in the webhook.
    app.post('/payments/success', verifyToken, async (req, res) => {
      const { sessionId } = req.body;

      try {
          // Verify with Stripe that the session exists and was paid
          const session = await stripe.checkout.sessions.retrieve(sessionId);
          
          if (session.payment_status !== 'paid') {
              return res.status(400).send({ message: 'Payment not completed' });
          }
          
          // Check the database to see if the webhook already recorded the payment (Idempotency)
          const existingPayment = await paymentsCollection.findOne({ transactionId: sessionId });
          
          if (existingPayment) {
              // Webhook succeeded, payment is safe. Just confirm to the client.
              return res.send({ 
                  message: 'Payment verified and recorded (via webhook)', 
                  payment: existingPayment 
              });
          }

          // This handles the case where webhook hasn't fired yet (e.g. localhost)
          // We must perform the SAME logic as the webhook here to ensure consistency
          const applicationId = session.metadata.applicationId;
          const studentId = session.metadata.studentId;

          const application = await applicationsCollection.findOne({
              _id: new ObjectId(applicationId),
          });

          if (application) {
              // A. Approve Application
              await applicationsCollection.updateOne(
                  { _id: new ObjectId(applicationId) },
                  { $set: { status: 'Approved' } }
              );

              // B. Reject Other Applications
              await applicationsCollection.updateMany(
                  { 
                      tuitionId: application.tuitionId, 
                      _id: { $ne: new ObjectId(applicationId) } 
                  },
                  { $set: { status: 'Rejected' } }
              );

              // C. Update Tuition
              await tuitionsCollection.updateOne(
                  { _id: application.tuitionId },
                  { 
                      $set: { 
                          tutorId: application.tutorId,
                          status: 'Assigned' 
                      } 
                  }
              );

              // D. Create Transaction Record (with Revenue Split)
              const feePercentage = parseInt(process.env.PLATFORM_FEE_PERCENTAGE) || 0;
              const totalAmount = session.amount_total / 100;
              const siteRevenue = totalAmount * (feePercentage / 100);
              const tutorPayment = totalAmount - siteRevenue;

              const transaction = {
                  paymentId: sessionId, // Stripe Session ID
                  stripeData: session,   // Full Stripe Session Data
                  tutorId: application.tutorId,
                  studentId: new ObjectId(studentId),
                  applicationId: new ObjectId(applicationId),
                  amount: totalAmount,
                  siteRevenue: siteRevenue,
                  tutorPayment: tutorPayment,
                  timestamp: new Date(),
              };

              await transactionsCollection.insertOne(transaction);
              
              // Keep payments collection for backward compatibility but using legacy fields
              const payment = {
                  transactionId: sessionId,
                  studentId: new ObjectId(studentId),
                  tutorId: application.tutorId,
                  tuitionId: application.tuitionId,
                  amount: totalAmount,
                  date: new Date(),
                  status: 'Completed',
              };
              await paymentsCollection.insertOne(payment);
              
              return res.send({ message: 'Payment verified and fulfilled directly.', payment });
          }
          return res.send({ message: 'Application not found for fulfillment.' });

      } catch (error) {
          console.error('Error retrieving Stripe session:', error);
          res.status(500).send({ message: 'Failed to verify payment details' });
      }
    });

    // Get Payments (Student)
    // Fetches from Transactions to show total amount paid
    app.get('/payments/my-payments', verifyToken, verifyStudent, async (req, res) => {
      const query = { studentId: new ObjectId(req.user.userId) };
      const transactions = await transactionsCollection.find(query).sort({ timestamp: -1 }).toArray();
      
      const populated = await Promise.all(
        transactions.map(async (t) => {
          const tuition = await tuitionsCollection.findOne({ _id: t.tuitionId });
          // Student sees the total amount they paid
          return { 
             _id: t._id,
             paymentId: t.paymentId,
             date: t.timestamp,
             amount: t.amount, // Total amount paid
             tuition
          };
        })
      );
      res.send(populated);
    });

    // Get Revenue (Tutor)
    // Fetches from Transactions to show their specific earnings
    app.get('/payments/my-revenue', verifyToken, verifyTutor, async (req, res) => {
      const query = { tutorId: new ObjectId(req.user.userId) };
      const transactions = await transactionsCollection.find(query).sort({ timestamp: -1 }).toArray();
      
      const sanitized = transactions.map(t => ({
          _id: t._id,
          paymentId: t.paymentId,
          date: t.timestamp,
          amount: t.tutorPayment, // Tutor sees ONLY their earnings
          // We can include other non-sensitive fields if needed
      }));

      res.send(sanitized);
    });

    // Admin Stats - Enhanced
    app.get('/admin/stats', verifyToken, verifyAdmin, async (req, res) => {
      const totalUsers = await usersCollection.countDocuments();
      const totalStudents = await usersCollection.countDocuments({ role: 'Student' });
      const totalTutors = await usersCollection.countDocuments({ role: 'Tutor' });
      
      const totalTuitions = await tuitionsCollection.countDocuments();
      const pendingTuitions = await tuitionsCollection.countDocuments({ status: 'Pending' });
      
      const totalTransactions = await transactionsCollection.countDocuments();
      
      // Calculate Financials: Total Volume (Gross) and Total Revenue (Site Earnings)
      const financialsResult = await transactionsCollection
        .aggregate([
          { 
            $group: { 
              _id: null, 
              totalVolume: { $sum: '$amount' },
              totalRevenue: { $sum: '$siteRevenue' } 
            } 
          }
        ])
        .toArray();
        
      const totalVolume = financialsResult[0]?.totalVolume || 0;
      const totalRevenue = financialsResult[0]?.totalRevenue || 0;

      res.send({ 
        totalUsers,
        totalStudents,
        totalTutors,
        totalTuitions,
        pendingTuitions,
        totalVolume,
        totalRevenue,
        totalTransactions 
      });
    });

    // Public: Latest Tuitions (Home Page)
    app.get('/tuitions/latest', async (req, res) => {
      const tuitions = await tuitionsCollection
          .find({ status: 'Approved' }) // Only show approved on home
          .sort({ createdAt: -1 })
          .limit(6)
          .toArray();
      res.send(tuitions);
    });

    // Public: Latest Tutors (Home Page)
    // Returns 6 Verified Tutors
    app.get('/users/tutors/latest', async (req, res) => {
      const tutors = await usersCollection
          .find({ role: 'Tutor', isVerified: true }) // Verified tutors only
          .sort({ _id: -1 }) // Newest first
          .limit(6)
          .project({ password: 0 }) // Don't send passwords
          .toArray();
      res.send(tutors);
    });

    // Admin: Get All Payments
    app.get('/admin/payments', verifyToken, verifyAdmin, async (req, res) => {
        const payments = await paymentsCollection.find().sort({ date: -1 }).limit(50).toArray();
         const populated = await Promise.all(
            payments.map(async (p) => {
              const student = await usersCollection.findOne({ _id: new ObjectId(p.studentId) });
              const tutor = await usersCollection.findOne({ _id: new ObjectId(p.tutorId) });
              return { ...p, studentId: student, tutorId: tutor };
            })
          );
        res.send(populated);
    });

    // Admin: Get All Tuitions (for management)
    app.get('/admin/tuitions', verifyToken, verifyAdmin, async (req, res) => {
      const tuitions = await tuitionsCollection.find().sort({ createdAt: -1 }).toArray();
       const populated = await Promise.all(
          tuitions.map(async (t) => {
             const student = await usersCollection.findOne({ _id: new ObjectId(t.studentId) });
             return { ...t, studentId: student };
          })
       );
      res.send(populated);
    });

    // ========================
    // STATS APIs (Student/Tutor)
    // ========================

    // Student Stats
    app.get('/student/stats', verifyToken, verifyStudent, async (req, res) => {
      const studentId = new ObjectId(req.user.userId);

      // 1. Total Tuitions Posted
      const totalTuitions = await tuitionsCollection.countDocuments({ studentId });
      
      // 2. Approved Tuitions (Ongoing/Assigned)
      const approvedTuitions = await tuitionsCollection.countDocuments({ 
          studentId, 
          status: { $in: ['Approved', 'Assigned'] } 
      });

      // 3. Total Applications Received
      const myTuitions = await tuitionsCollection.find({ studentId }, { projection: { _id: 1 } }).toArray();
      const tuitionIds = myTuitions.map(t => t._id);
      
      const totalApplications = await applicationsCollection.countDocuments({ 
        tuitionId: { $in: tuitionIds } 
      });

      // 4. Total Payments Made (using Transactions)
      const transactions = await transactionsCollection.find({ studentId }).toArray();
      const totalPayments = transactions.length;
      const totalSpent = transactions.reduce((sum, t) => sum + t.amount, 0);

      res.send({
        totalTuitions,
        approvedTuitions,
        totalApplications,
        totalPayments,
        totalSpent
      });
    });

    // Tutor Stats
    app.get('/tutor/stats', verifyToken, verifyTutor, async (req, res) => {
      const tutorId = new ObjectId(req.user.userId);

      // 1. Total Applications Made
      const totalApplications = await applicationsCollection.countDocuments({ tutorId });

      // 2. Approved Applications
      const approvedApplications = await applicationsCollection.countDocuments({ tutorId, status: 'Approved' });
      
      // 3. Pending Applications
      const pendingApplications = await applicationsCollection.countDocuments({ tutorId, status: 'Pending' });

      // 4. Total Revenue (Earnings from Transactions)
      const transactions = await transactionsCollection.find({ tutorId }).toArray();
      const totalRevenue = transactions.reduce((sum, t) => sum + (t.tutorPayment || 0), 0);

      res.send({
        totalApplications,
        approvedApplications,
        pendingApplications,
        totalRevenue
      });
    });

    // Send a ping to confirm a successful connection
    // await client.db('admin').command({ ping: 1 });
    console.log('Pinged your deployment. You successfully connected to MongoDB!');
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('Bashar Teacher Server is running...');
});

app.listen(port, () => {
  console.log(`Simple Server running on port ${port}`);
});