const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./db');
const cors = require('cors');
const cookieParser = require('cookie-parser');

dotenv.config();

const app = express();

// If you're behind nginx/proxy and using secure cookies, trust proxy
app.set('trust proxy', 1);

// Allowed origins
const whitelist = [
  'http://localhost:3000',        // dev
  'https://sensrs.com',           // frontend production
  'https://alice.sensrs.com'      // api subdomain (if needed)
];

const corsOptions = {
  origin: function (origin, callback) {
    // allow requests with no origin (mobile apps, curl, server-to-server)
    if (!origin) return callback(null, true);

    if (whitelist.indexOf(origin) !== -1) {
      return callback(null, true);
    } else {
      // reject other origins
      return callback(new Error('CORS: Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With']
};

// Enable CORS using the options
app.use(cors(corsOptions));
// Enable preflight for all routes
app.options('*', cors(corsOptions));

app.use(express.json());
app.use(cookieParser());

// Connect DB
connectDB();

// Routes
app.use('/api/auth', require('./routes/auth'));

app.get('/', (req, res) => res.send('SEnSRS backend running'));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
