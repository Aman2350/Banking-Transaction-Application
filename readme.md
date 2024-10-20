
# Banking Transactions Backend Application

## Overview

This backend application is built using Node.js and MySQL for a banking system. It provides user authentication, balance management, withdrawals, and fund transfer functionalities through RESTful API endpoints. The system ensures security by using JWT (JSON Web Tokens) for user authentication and session management.

## Features

### 1. User Authentication:

- **Register**: New users can register by providing a username, email, and password. The password is securely hashed using bcrypt before being stored in the database.
  
- **Login**: Registered users can log in with their email and password. On successful login, an access token (JWT) is generated and sent to the client. This token is required to access protected routes.

- **Token-based Authentication**: The API uses JWT to authenticate and authorize users. Only authenticated users can access or modify their account details and perform transactions.

### 2. Banking Operations:

- **Get Balance**: Users can view their current balance.
- **Withdrawal**: Users can withdraw a specified amount from their balance. The system checks for sufficient balance before proceeding.
- **Transfer Funds**: Users can transfer money between their account and another user’s account, ensuring the transaction is atomic (both accounts are updated together).

### 3. Transaction Logging:

Each transaction (withdrawal or transfer) is logged in a `transaction_history` table for record-keeping. Transaction logs include details like the transaction type (withdrawal/transfer), amount, and timestamps.

### 4. Database Integrity:

The application ensures data integrity using MySQL constraints such as foreign keys. For example, deleting a user will automatically delete their related records (like account and refresh token data). Triggers are also set up in MySQL for automated tasks like updating last login times or maintaining transaction records.

## API Endpoints

### 1. Authentication

- **POST** `/api/auth/register`: Registers a new user.
  
  **Request Body:**
  ```json
  {
    "username": "johndoe",
    "email": "johndoe@example.com",
    "password": "yourpassword"
  }
  ```

  **Response**: Confirmation message of successful registration.

- **POST** `/api/auth/login`: Logs in the user and provides an access token.
  
  **Request Body:**
  ```json
  {
    "email": "johndoe@example.com",
    "password": "yourpassword"
  }
  ```

  **Response:**
  ```json
  {
    "token": "JWT_ACCESS_TOKEN"
  }
  ```

### 2. Banking Transactions

- **GET** `/api/transactions/balance`: Retrieves the user's current balance.
  
  **Headers**: Requires a valid JWT token in the Authorization header:
  ```
  Authorization: Bearer <JWT_ACCESS_TOKEN>
  ```

  **Response:**
  ```json
  {
    "balance": 500.00
  }
  ```

- **POST** `/api/transactions/withdraw`: Allows the user to withdraw money from their account.
  
  **Request Body:**
  ```json
  {
    "amount": 100.00
  }
  ```

  **Headers**: Requires a valid JWT token.

  **Response:**
  ```json
  {
    "message": "Withdrawal successful"
  }
  ```

- **POST** `/api/transactions/transfer`: Allows the user to transfer funds to another user.
  
  **Request Body:**
  ```json
  {
    "amount": 200.00,
    "targetUserId": 2
  }
  ```

  **Headers**: Requires a valid JWT token.

  **Response:**
  ```json
  {
    "message": "Transfer successful"
  }
  ```

## Code Walkthrough

### 1. Models

#### User Model (`models/userModel.js`):

Contains methods to find a user by email and create a new user in the `users` table.

Example:
```javascript
const findUserByEmail = async (email) => {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    return rows[0];
};
```

#### Transaction Model (`models/transactionModel.js`):

Contains methods to manage account balances and log transactions.

Example:
```javascript
const updateBalance = async (userId, amount) => {
    await pool.query('UPDATE accounts SET balance = balance + ? WHERE user_id = ?', [amount, userId]);
};
```

### 2. Controllers

#### Auth Controller (`controllers/authController.js`):

Handles user registration, login, and token verification. Uses JWT to sign and verify tokens.

Example:
```javascript
const login = async (req, res) => {
    const { email, password } = req.body;
    const user = await findUserByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
};
```

#### Transactions Controller (`controllers/transactionsController.js`):

Handles balance retrieval, withdrawals, and transfers between accounts. Ensures that each transaction is logged in the `transaction_history` table.

Example:
```javascript
const transfer = async (req, res) => {
    const { amount, targetUserId } = req.body;
    const balance = await getBalance(req.user.id);
    if (balance < amount) return res.status(400).json({ message: 'Insufficient balance' });

    await updateBalance(req.user.id, -amount);
    await updateBalance(targetUserId, amount);
    await logTransaction(req.user.id, 'transfer', amount, targetUserId);
    res.json({ message: 'Transfer successful' });
};
```

### 3. Routes

#### Authentication Routes (`routes/authRoutes.js`):

Defines routes for user registration and login.

Example:
```javascript
router.post('/register', register);
router.post('/login', login);
```

#### Transaction Routes (`routes/transactionRoutes.js`):

Defines routes for checking balance, withdrawals, and transfers. These routes are protected by the `verifyToken` middleware.

Example:
```javascript
router.get('/balance', verifyToken, getBalanceHandler);
router.post('/withdraw', verifyToken, withdraw);
router.post('/transfer', verifyToken, transfer);
```

### 4. Middleware

#### Token Verification Middleware (`authController.js`):

Verifies the JWT token provided in the Authorization header of requests.

Example:
```javascript
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(403).json({ message: 'No token provided' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token is invalid' });
        req.user = user;
        next();
    });
};
```

## Database Design

- **`users` Table**: Stores user details.
  - `id`, `username`, `email`, `password`, `last_login`, `created_at`

- **`accounts` Table**: Stores the user's balance.
  - `user_id` (foreign key referencing `users.id`), `balance`

- **`transaction_history` Table**: Logs all transactions (withdrawals and transfers).
  - `id`, `user_id`, `transaction_type`, `amount`, `target_user_id`, `transaction_date`

- **`refresh_tokens` Table**: Manages session persistence with refresh tokens.
  - `id`, `user_id`, `token`, `expiry_date`

## Error Handling

The application uses status codes to indicate errors such as invalid credentials (401), insufficient balance (400), and unauthorized access (403). Custom error messages are sent in the response body to inform the user of the issue.

## Security Considerations

- **Password Hashing**: Passwords are hashed using bcrypt to ensure they are not stored in plaintext.
- **JWT Authentication**: Ensures that only authenticated users can access sensitive data. The JWT tokens are signed with a secret key, and their expiration is managed to reduce the risk of token misuse.
- **SQL Injection Protection**: Using parameterized queries (prepared statements) with MySQL to avoid SQL injection attacks.

---

This backend application provides a robust structure for user authentication and secure banking operations, adhering to industry-standard security practices.
```

