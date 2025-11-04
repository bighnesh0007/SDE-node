# User Authentication API

A robust Node.js authentication system built with Express and MongoDB, featuring separate user and admin management.

## Features

- User Authentication
  - Registration
  - Login
  - Password Hashing
  - Input Validation
  - Email Verification
  
- Admin Management
  - Secure Admin Registration with Secret Key
  - Admin Login
  - Role-based Permissions
  - User Management Capabilities

- Security Features
  - Password Validation (uppercase, lowercase, numbers, special characters)
  - Email Format Validation
  - Input Sanitization
  - Secure Password Hashing with bcrypt

## Prerequisites

- Node.js
- MongoDB
- npm or yarn

## Installation

1. Clone the repository:
```bash
git clone https://github.com/bighnesh0007/SDE-node.git
cd SDE-node
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
   - Copy `.env.example` to `.env`
   - Update the values in `.env`:
     - `PORT`: Server port (default: 3000)
     - `MONGODB_URI`: MongoDB connection string
     - `ADMIN_SECRET_KEY`: Secret key for admin registration

## Usage

### Development
```bash
npm run dev
```

### Production
```bash
npm start
```

## API Endpoints

### User Routes
- POST `/user/register` - Register a new user
- POST `/user/login` - User login

### Admin Routes
- POST `/admin/register` - Register a new admin (requires secret key)
- POST `/admin/login` - Admin login

## Input Validation

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

### Name Requirements
- 2-50 characters
- Letters and spaces only

## Tech Stack

- Node.js
- Express.js (v5.1.0)
- MongoDB with Mongoose (v8.19.2)
- bcrypt (v6.0.0)

## Project Structure

```
src/
├── app.js              # Express app configuration
├── config/
│   └── database.js     # Database connection setup
├── controllers/
│   ├── adminController.js
│   └── userController.js
├── middlewares/
│   └── validation.js
├── models/
│   ├── Admin.js
│   └── User.js
├── routes/
│   ├── adminRoutes.js
│   └── userRoutes.js
└── utils/
    └── validators.js
```

## License

ISC
