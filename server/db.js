const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'netsafescan',
  password: process.env.DB_PASSWORD || 'postgres',
  port: process.env.DB_PORT || 5432,
});

// Create tables if they don't exist
const initDb = async () => {
  try {
    // Create users table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255),
        full_name VARCHAR(255),
        google_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create session table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS session (
        sid VARCHAR(255) PRIMARY KEY,
        sess JSON NOT NULL,
        expire TIMESTAMP NOT NULL
      )
    `);

    // Create url_scans table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS url_scans (
        id SERIAL PRIMARY KEY,
        url TEXT NOT NULL,
        is_safe BOOLEAN NOT NULL,
        threats JSONB,
        scan_details JSONB,
        ip_address VARCHAR(45),
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create threat_stats table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS threat_stats (
        id SERIAL PRIMARY KEY,
        total_scans INTEGER DEFAULT 0,
        safe_scans INTEGER DEFAULT 0,
        unsafe_scans INTEGER DEFAULT 0,
        detection_rate DECIMAL(5,2) DEFAULT 0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add detection_rate column if it doesn't exist
    await pool.query(`
      DO $$ 
      BEGIN
        IF NOT EXISTS (
          SELECT 1 
          FROM information_schema.columns 
          WHERE table_name = 'threat_stats' 
          AND column_name = 'detection_rate'
        ) THEN
          ALTER TABLE threat_stats ADD COLUMN detection_rate DECIMAL(5,2) DEFAULT 0;
        END IF;
      END $$;
    `);

    // Add safe_scans column if it doesn't exist
    await pool.query(`
      DO $$ 
      BEGIN
        IF NOT EXISTS (
          SELECT 1 
          FROM information_schema.columns 
          WHERE table_name = 'threat_stats' 
          AND column_name = 'safe_scans'
        ) THEN
          ALTER TABLE threat_stats ADD COLUMN safe_scans INTEGER DEFAULT 0;
        END IF;
      END $$;
    `);

    // Add unsafe_scans column if it doesn't exist
    await pool.query(`
      DO $$ 
      BEGIN
        IF NOT EXISTS (
          SELECT 1 
          FROM information_schema.columns 
          WHERE table_name = 'threat_stats' 
          AND column_name = 'unsafe_scans'
        ) THEN
          ALTER TABLE threat_stats ADD COLUMN unsafe_scans INTEGER DEFAULT 0;
        END IF;
      END $$;
    `);

    // Insert initial threat_stats record if none exists
    await pool.query(`
      INSERT INTO threat_stats (total_scans, safe_scans, unsafe_scans, detection_rate)
      SELECT 0, 0, 0, 0
      WHERE NOT EXISTS (SELECT 1 FROM threat_stats)
    `);

    // Create index for faster statistics queries
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_url_scans_scan_date ON url_scans(scan_date);
      CREATE INDEX IF NOT EXISTS idx_url_scans_ip_address ON url_scans(ip_address);
    `);

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
    throw error;
  }
};

module.exports = {
  pool,
  initDb
}; 