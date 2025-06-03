require('dotenv').config();

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const passport = require('./config/passport');
const { pool, initDb } = require('./db');
const { performSecurityChecks } = require('./urlSecurity');
const authRoutes = require('./routes/auth');

// Import LEGITIMATE_DOMAINS from urlSecurity
const { LEGITIMATE_DOMAINS } = require('./urlSecurity');

const app = express();
const port = process.env.PORT || 8080;

// Google Safe Browsing API key
const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

if (!GOOGLE_SAFE_BROWSING_API_KEY) {
  console.error('Warning: GOOGLE_SAFE_BROWSING_API_KEY is not set in environment variables');
}

// CORS configuration
const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'Accept',
    'Origin',
    'X-Requested-With',
    'Cache-Control',
    'Pragma'
  ],
  exposedHeaders: ['Set-Cookie'],
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));

// Add preflight handler for all routes
app.options('*', cors(corsOptions));

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  store: new pgSession({
    pool,
    tableName: 'session'
  }),
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize Passport and restore authentication state from session
app.use(passport.initialize());
app.use(passport.session());

// Create session table
const initSessionTable = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS session (
        sid VARCHAR(255) PRIMARY KEY,
        sess JSON NOT NULL,
        expire TIMESTAMP NOT NULL
      )
    `);
    console.log('Session table initialized');
  } catch (error) {
    console.error('Error initializing session table:', error);
  }
};

// Initialize database and session table
initDb().then(initSessionTable).catch(console.error);

// Auth routes
app.use('/api/auth', authRoutes);

// Google OAuth routes
app.use('/auth', authRoutes);

// Test endpoint to verify server is running
app.get("/api/health", async (req, res) => {
  try {
    // Check database connection
    const dbStatus = await pool.query('SELECT NOW()');
    
    // Check if session table exists
    const sessionTableExists = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'session'
      );
    `);

    // Check if users table exists
    const usersTableExists = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'users'
      );
    `);

    // Set CORS headers explicitly for this endpoint
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Origin', process.env.FRONTEND_URL || 'http://localhost:3000');
    res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, Cache-Control, Pragma');

    res.json({ 
      status: "ok", 
      message: "Server is running",
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      apiKeyConfigured: !!GOOGLE_SAFE_BROWSING_API_KEY,
      database: {
        connected: !!dbStatus,
        sessionTable: sessionTableExists.rows[0].exists,
        usersTable: usersTableExists.rows[0].exists
      }
    });
  } catch (error) {
    console.error('Health check error:', error);
    res.status(500).json({
      status: "error",
      message: "Server health check failed",
      error: error.message
    });
  }
});

// Google Safe Browsing API check
async function checkUrlSafety(url) {
  if (!GOOGLE_SAFE_BROWSING_API_KEY) {
    throw new Error('Google Safe Browsing API key is not configured');
  }

  try {
    console.log('Checking URL safety for:', url);
    
    // Basic URL validation
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch (e) {
      throw new Error('Invalid URL format');
    }

    // Check if the domain is in our whitelist
    const domain = parsedUrl.hostname;
    if (LEGITIMATE_DOMAINS.some(legitDomain => domain === legitDomain)) {
      return {
        safe: true,
        threats: [],
        message: "This URL is from a trusted domain."
      };
    }

    // Ensure URL is properly formatted for the API
    const formattedUrl = parsedUrl.toString();

    console.log('Sending request to Google Safe Browsing API...');
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`,
      {
        client: {
          clientId: "netsafescan",
          clientVersion: "1.0.0"
        },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
            "THREAT_TYPE_UNSPECIFIED"
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: formattedUrl }]
        }
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        timeout: 10000 // 10 second timeout
      }
    );

    console.log('Received response from Google Safe Browsing API:', response.data);

    const isSafe = !response.data.matches;
    const threats = response.data.matches || [];
    
    // Add detailed threat information
    const threatDetails = threats.map(match => ({
      type: match.threatType,
      platform: match.platformType,
      severity: match.threatEntryType,
      timestamp: new Date().toISOString()
    }));

    return {
      safe: isSafe,
      threats: threatDetails,
      message: isSafe 
        ? "This URL appears to be safe according to Google Safe Browsing."
        : `Warning: This URL may be unsafe. Threats detected: ${threats.map(m => m.threatType).join(", ")}`
    };
  } catch (error) {
    console.error('Error checking URL safety:', error);
    
    // Handle specific error cases
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      console.error('API Error Response:', error.response.data);
      if (error.response.status === 400) {
        throw new Error('Invalid URL format or API request');
      } else if (error.response.status === 403) {
        throw new Error('API key is invalid or has exceeded quota');
      } else {
        throw new Error(`API Error: ${error.response.status} - ${error.response.statusText}`);
      }
    } else if (error.request) {
      // The request was made but no response was received
      console.error('No response received:', error.request);
      throw new Error('No response received from Google Safe Browsing API');
    } else if (error.code === 'ECONNABORTED') {
      // Request timeout
      throw new Error('Request to Google Safe Browsing API timed out');
    } else {
      // Something happened in setting up the request that triggered an Error
      console.error('Request setup error:', error.message);
      throw new Error(`Failed to check URL safety: ${error.message}`);
    }
  }
}

// Analytics endpoints
app.get("/api/analytics", async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM scan_analytics ORDER BY id DESC LIMIT 1');
    const analytics = result.rows[0] || {
      total_scans: 0,
      safe_scans: 0,
      unsafe_scans: 0,
      last_updated: new Date()
    };
    
    // Transform the data to match the client's expected structure
    const transformedAnalytics = {
      urlsScanned: analytics.total_scans || 0,
      accuracyRate: analytics.total_scans > 0 
        ? (analytics.safe_scans / analytics.total_scans * 100)
        : 99.9,
      protectedUsers: analytics.total_scans || 0,
      lastUpdated: analytics.last_updated || new Date().toISOString()
    };
    
    res.json(transformedAnalytics);
  } catch (error) {
    console.error('Error fetching analytics:', error);
    res.status(500).json({
      error: "Failed to fetch analytics",
      message: error.message
    });
  }
});

// Get scan statistics endpoint
app.get("/api/analytics/stats", async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM scan_analytics ORDER BY id DESC LIMIT 1');
    const analytics = result.rows[0] || {
      total_scans: 0,
      safe_scans: 0,
      unsafe_scans: 0
    };

    // Get recent scans
    const recentScans = await pool.query(
      'SELECT url, is_safe, scan_date FROM url_scans ORDER BY scan_date DESC LIMIT 10'
    );

    // Get top threats
    const topThreats = await pool.query(`
      SELECT jsonb_array_elements(threats) as threat, COUNT(*) as count
      FROM url_scans
      WHERE threats IS NOT NULL
      GROUP BY threat
      ORDER BY count DESC
      LIMIT 5
    `);

    res.json({
      totalScans: analytics.total_scans,
      safeScans: analytics.safe_scans,
      unsafeScans: analytics.unsafe_scans,
      safetyRate: analytics.total_scans > 0 
        ? (analytics.safe_scans / analytics.total_scans * 100).toFixed(1)
        : 0,
      topThreats: topThreats.rows,
      recentScans: recentScans.rows
    });
  } catch (error) {
    console.error('Error fetching scan statistics:', error);
    res.status(500).json({ error: "Failed to fetch scan statistics" });
  }
});

// URL scanning endpoint
app.post("/api/scan", async (req, res) => {
  const client = await pool.connect();
  try {
    const { url } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;
    console.log('Received scan request for URL:', url, 'from IP:', ipAddress);
    
    if (!url) {
      console.log('No URL provided in request');
      return res.status(400).json({ 
        error: "URL is required",
        message: "Please provide a URL to scan"
      });
    }

    await client.query('BEGIN');

    // First check with Google Safe Browsing API
    console.log('Checking URL with Google Safe Browsing API...');
    const googleSafety = await checkUrlSafety(url);
    
    // Then perform our additional security checks
    console.log('Performing additional security checks...');
    const securityChecks = await performSecurityChecks(url);

    // Combine results
    const isSafe = securityChecks.safe && googleSafety.safe;
    const allThreats = [...(securityChecks.threats || []), ...(googleSafety.threats || [])];
    
    // Format threats for database storage
    const formattedThreats = allThreats.map(threat => ({
      type: typeof threat === 'string' ? threat : threat.type,
      timestamp: new Date().toISOString()
    }));

    // Store scan results in database with IP address
    await client.query(
      'INSERT INTO url_scans (url, is_safe, threats, scan_details, ip_address) VALUES ($1, $2, $3, $4, $5)',
      [url, isSafe, JSON.stringify(formattedThreats), JSON.stringify({ securityChecks, googleSafety }), ipAddress]
    );

    // Get updated statistics including unique users count
    const statsResult = await client.query(`
      WITH scan_counts AS (
        SELECT 
          COUNT(*) as total_scans,
          COUNT(CASE WHEN is_safe THEN 1 END) as safe_scans,
          COUNT(CASE WHEN NOT is_safe THEN 1 END) as unsafe_scans,
          COUNT(DISTINCT ip_address) as unique_users
        FROM url_scans
      )
      UPDATE threat_stats
      SET 
        total_scans = scan_counts.total_scans,
        safe_scans = scan_counts.safe_scans,
        unsafe_scans = scan_counts.unsafe_scans,
        detection_rate = CASE 
          WHEN scan_counts.total_scans > 0 
          THEN ROUND((scan_counts.unsafe_scans::float / scan_counts.total_scans::float * 100)::numeric, 2)
          ELSE 0
        END,
        last_updated = CURRENT_TIMESTAMP
      FROM scan_counts
      WHERE threat_stats.id = (SELECT id FROM threat_stats ORDER BY id DESC LIMIT 1)
      RETURNING threat_stats.*, scan_counts.unique_users
    `);

    // Get threat distribution
    const threatDistribution = await client.query(`
      SELECT 
        jsonb_array_elements(threats)->>'type' as threat_type,
        COUNT(*) as count
      FROM url_scans
      WHERE threats IS NOT NULL
      GROUP BY threat_type
      ORDER BY count DESC
    `);

    await client.query('COMMIT');

    // Prepare response with updated statistics
    const response = {
      safe: isSafe,
      threats: allThreats,
      message: allThreats.length > 0 
        ? `Warning: This URL may be unsafe. Threats detected: ${allThreats.map(t => typeof t === 'string' ? t : t.type).join(", ")}`
        : "This URL appears to be safe.",
      details: {
        securityChecks,
        googleSafety
      },
      statistics: {
        totalScans: statsResult.rows[0].total_scans,
        safeScans: statsResult.rows[0].safe_scans,
        unsafeScans: statsResult.rows[0].unsafe_scans,
        detectionRate: statsResult.rows[0].detection_rate,
        threatDistribution: threatDistribution.rows,
        protectedUsers: statsResult.rows[0].unique_users,
        lastUpdated: statsResult.rows[0].last_updated
      }
    };

    console.log('Scan completed successfully:', response);
    res.json(response);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Scan error:', error);
    res.status(500).json({ 
      error: "Failed to scan URL",
      message: error.message || "An unexpected error occurred while scanning the URL"
    });
  } finally {
    client.release();
  }
});

// Real-time statistics endpoint
app.get("/api/statistics", async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Get latest statistics with unique users count
    const statsResult = await client.query(`
      WITH scan_counts AS (
        SELECT 
          COUNT(*) as total_scans,
          COUNT(CASE WHEN is_safe THEN 1 END) as safe_scans,
          COUNT(CASE WHEN NOT is_safe THEN 1 END) as unsafe_scans,
          COUNT(DISTINCT ip_address) as unique_users
        FROM url_scans
      )
      UPDATE threat_stats
      SET 
        total_scans = scan_counts.total_scans,
        safe_scans = scan_counts.safe_scans,
        unsafe_scans = scan_counts.unsafe_scans,
        detection_rate = CASE 
          WHEN scan_counts.total_scans > 0 
          THEN ROUND((scan_counts.unsafe_scans::float / scan_counts.total_scans::float * 100)::numeric, 2)
          ELSE 0
        END,
        last_updated = CURRENT_TIMESTAMP
      FROM scan_counts
      WHERE threat_stats.id = (SELECT id FROM threat_stats ORDER BY id DESC LIMIT 1)
      RETURNING threat_stats.*, scan_counts.unique_users
    `);

    // Get threat distribution
    const threatDistribution = await client.query(`
      SELECT 
        jsonb_array_elements(threats)->>'type' as threat_type,
        COUNT(*) as count
      FROM url_scans
      WHERE threats IS NOT NULL
      GROUP BY threat_type
      ORDER BY count DESC
    `);

    // Get recent scans
    const recentScans = await client.query(`
      SELECT url, is_safe, scan_date, threats
      FROM url_scans
      ORDER BY scan_date DESC
      LIMIT 10
    `);

    await client.query('COMMIT');

    const response = {
      statistics: {
        totalScans: statsResult.rows[0].total_scans,
        safeScans: statsResult.rows[0].safe_scans,
        unsafeScans: statsResult.rows[0].unsafe_scans,
        detectionRate: statsResult.rows[0].detection_rate,
        threatDistribution: threatDistribution.rows,
        protectedUsers: statsResult.rows[0].unique_users,
        recentScans: recentScans.rows,
        lastUpdated: statsResult.rows[0].last_updated
      }
    };

    res.json(response);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error fetching statistics:', error);
    res.status(500).json({
      error: "Failed to fetch statistics",
      message: error.message
    });
  } finally {
    client.release();
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    status: "error",
    message: "Internal server error",
    error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Frontend URL: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
});