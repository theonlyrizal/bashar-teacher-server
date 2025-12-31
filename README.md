# Bashar Teacher - Backend API

[![Node.js](https://img.shields.io/badge/Node.js-20.x-339933)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-4.19.2-000000)](https://expressjs.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-6.3.0-47A248)](https://www.mongodb.com/)
[![JWT](https://img.shields.io/badge/JWT-9.0.2-000000)](https://jwt.io/)

This repository contains the backend API for the Bashar Teacher platform. It handles authentication, tuition management, application processing, and payment fulfillment.

## 🚀 Core Features

- **Robust Authentication:** Secure user registration and login using Bcrypt for password hashing and JSON Web Tokens (JWT) for session management.
- **Social Login Integration:** Seamlessly syncs with Firebase Authentication for Google social login.
- **Role-Based Authorization:** Custom middleware to verify and protect routes for Students, Tutors, and Admins.
- **Tuition Management:** Complete CRUD operations for tuition postings with search and filtering logic.
- **Application System:** Handles tutor applications, status updates (Pending, Approved, Rejected), and duplicate prevention.
- **Secure Payments (Stripe):** 
    - Integration with Stripe Checkout for secure tuition payments.
    - **Stripe Webhooks:** Reliable payment fulfillment using raw body verification to handle status updates and revenue distribution.
- **Admin Tools:** Extensive API for user and content management.

## 🛠️ Technologies Used

- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB (with Atlas)
- **Security:** Bcrypt.js, JSON Web Tokens (JWT)
- **Third-party Services:** 
    - Firebase Admin SDK (for user management & auth validation)
    - Stripe (for payment processing)
- **Environment Management:** Dotenv

## ⚙️ Local Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/bashar-teacher-server.git
   cd bashar-teacher-server
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure Environment Variables:**
   Create a `.env` file in the root directory and fill in the following values:
   ```env
   PORT=5000
   MONGO_USER=your_mongodb_user
   MONGO_PASS=your_mongodb_password
   JWT_SECRET=your_jwt_secret
   JWT_EXPIRE=7d
   ADMIN_TOKEN=your_static_admin_token
   CLIENT_URL=http://localhost:5173
   FIREBASE_SERVICE_KEY=your_base64_encoded_service_account_json
   STRIPE_SECRET_KEY=your_stripe_secret_key
   STRIPE_WEBHOOK_SECRET=your_stripe_webhook_signing_secret
   PLATFORM_FEE_PERCENTAGE=10
   ```

4. **Run the server:**
   - For development (with nodemon): `npm run dev`
   - For production: `npm start`

## 🔒 Security Notes

- Never commit the `.env` file to version control.
- Ensure `FIREBASE_SERVICE_KEY` is kept secure as it provides administrative access to your Firebase project.
- Stripe webhooks must use signature verification to ensure requests are legitimately from Stripe.
